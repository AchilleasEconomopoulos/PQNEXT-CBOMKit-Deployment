package policies

# NOTE: this is the experimental working copy. The OPA container serves
# /home/achilleas/cbomkit/opa/quantum_safe.rego from a bind mount and reloads it
# on restart, so evaluating this file requires uploading it first:
#
#   curl -X PUT --data-binary @quantum_safe.rego -H 'Content-Type: text/plain' \
#     http://localhost:8181/v1/policies/policies/quantum_safe.rego
#
# A container restart silently reverts to the other copy.

# Quantum-safety policy for CycloneDX CBOM cryptographic assets.
#
# Algorithms are evaluated using the same ordered checks as
# BasicQuantumSafeComplianceService. Other asset types inherit the worst result
# of every algorithm reachable through CycloneDX cryptographic relationships or
# the generic dependency graph.

asymmetric_primitives := {"signature", "key-agree", "keyagree", "kem", "pke"}
unknown_primitives := {"unknown", "other"}

not_applicable_material_types := {
	"secret-key",
	"shared-secret",
	"digest",
	"tag",
	"salt",
	"nonce",
	"initialization-vector",
	"seed",
	"additional-data",
	"password",
}

whitelist_names := {
	"ml-kem", "mlkem", "ml-dsa", "slh-dsa", "pqxdh", "bike", "mceliece",
	"frodokem", "hqc", "kyber", "ntru", "crystals", "falcon", "mayo",
	"sphincs", "xmss", "lms",
}

whitelist_oids := {
	"1.3.6.1.4.1.2.267.12.4.4", "1.3.6.1.4.1.2.267.12.6.5",
	"1.3.6.1.4.1.2.267.12.8.7", "1.3.9999.6.4.16", "1.3.9999.6.7.16",
	"1.3.9999.6.4.13", "1.3.9999.6.7.13", "1.3.9999.6.5.12",
	"1.3.9999.6.8.12", "1.3.9999.6.5.10", "1.3.9999.6.8.10",
	"1.3.9999.6.6.12", "1.3.9999.6.9.12", "1.3.9999.6.6.10",
	"1.3.9999.6.9.10", "1.3.6.1.4.1.22554.5.6.1",
	"1.3.6.1.4.1.22554.5.6.2", "1.3.6.1.4.1.22554.5.6.3",
}

# Lower rank means a worse compliance result.
result_rank := {
	"quantum-vulnerable": 1,
	"unknown": 2,
	"quantum-safe": 3,
	"na": 4,
}

rank_result := {
	1: "quantum-vulnerable",
	2: "unknown",
	3: "quantum-safe",
	4: "na",
}

is_algorithm(component) if {
	component.cryptoProperties.assetType == "algorithm"
}

is_related_crypto_material(component) if {
	component.cryptoProperties.assetType == "related-crypto-material"
}

is_certificate(component) if {
	component.cryptoProperties.assetType == "certificate"
}

is_asymmetric(primitive) if {
	primitive in asymmetric_primitives
}

is_unknown_primitive(primitive) if {
	primitive in unknown_primitives
}

is_asymmetric_or_unknown(primitive) if {
	is_asymmetric(primitive)
}

is_asymmetric_or_unknown(primitive) if {
	is_unknown_primitive(primitive)
}

has_algorithm_properties(component) if {
	component.cryptoProperties.algorithmProperties
}

has_positive_nist_level(component) if {
	component.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel > 0
}

has_primitive(component) if {
	component.cryptoProperties.algorithmProperties.primitive
}

has_whitelisted_oid(component) if {
	component.cryptoProperties.oid in whitelist_oids
}

matching_name(component) := name_match if {
	name := lower(component.name)
	some name_match in whitelist_names
	contains(name, name_match)
}

has_matching_name(component) if {
	matching_name(component)
}

# Provenance recorded by the CBOMkit-theia OpenSSL configuration plugin. A
# configuration file is a control plane: one openssl.cnf constrains every TLS
# connection the processes loading it can make, so a finding is only actionable
# if it names the directive that has to change.
#
# These readers are total and set-valued. A CBOM without theia properties yields
# empty sets, so every rule below stays inert and such a CBOM is assessed exactly
# as before. Both properties are repeatable: an asset reachable from two
# directives keeps both rather than causing a conflict.
openssl_property_values(component, key) := {value |
	some property in object.get(component, "properties", [])
	property.name == key
	value := property.value
}

openssl_directives(component) := openssl_property_values(component, "theia:openssl:directive")

openssl_tokens(component) := openssl_property_values(component, "theia:openssl:token")

has_openssl_directive(component) if {
	count(openssl_directives(component)) > 0
}

is_openssl_config(component) if {
	count(openssl_property_values(component, "theia:openssl:config")) > 0
}

# Prefer the raw configuration token over the component name: it is the text the
# user has to find and edit.
openssl_display(component) := component.name if {
	count(openssl_tokens(component)) == 0
}

openssl_display(component) := concat("/", sort([token |
	some token in openssl_tokens(component)
])) if {
	count(openssl_tokens(component)) > 0
}

component_by_ref(ref) := component if {
	some component in object.get(input, "components", [])
	component["bom-ref"] == ref
}

component_exists(ref) if {
	component_by_ref(ref)
}

# References defined by related cryptographic material.
related_material_algorithm_refs(component) := {ref |
	ref := component.cryptoProperties.relatedCryptoMaterialProperties.algorithmRef
}

related_material_secured_by_refs(component) := {ref |
	ref := component.cryptoProperties.relatedCryptoMaterialProperties.securedBy.algorithmRef
}

related_material_asset_refs(component) := {ref |
	some related in component.cryptoProperties.relatedCryptoMaterialProperties.relatedCryptographicAssets
	ref := related.ref
}

# References defined by certificates. CycloneDX 1.6 names the signing algorithm
# and the certified public key in dedicated fields; 1.7 generalises both into
# relatedCryptographicAssets. Both encodings are accepted so certificates
# resolve to their algorithms regardless of the emitting tool's schema version.
certificate_signature_algorithm_refs(component) := {ref |
	ref := component.cryptoProperties.certificateProperties.signatureAlgorithmRef
}

certificate_public_key_refs(component) := {ref |
	ref := component.cryptoProperties.certificateProperties.subjectPublicKeyRef
}

certificate_asset_refs(component) := {ref |
	some related in component.cryptoProperties.certificateProperties.relatedCryptographicAssets
	ref := related.ref
}

certificate_typed_asset_refs(component, asset_type) := {ref |
	some related in component.cryptoProperties.certificateProperties.relatedCryptographicAssets
	related.type == asset_type
	ref := related.ref
}

# The two sides a certificate is judged on: the algorithm that signed it and the
# public key it certifies. A certificate is only as safe as the weaker of them.
certificate_signature_refs(component) := union({
	certificate_signature_algorithm_refs(component),
	certificate_typed_asset_refs(component, "algorithm"),
})

certificate_subject_key_refs(component) := union({
	certificate_public_key_refs(component),
	certificate_typed_asset_refs(component, "publicKey"),
})

# References defined by protocol cipher suites. The guide uses string refs, but
# object refs are accepted as a compatibility fallback.
protocol_string_algorithm_refs(component) := {ref |
	some cipher_suite in component.cryptoProperties.protocolProperties.cipherSuites
	some algorithm_ref in cipher_suite.algorithms
	is_string(algorithm_ref)
	ref := algorithm_ref
}

protocol_object_algorithm_refs(component) := {ref |
	some cipher_suite in component.cryptoProperties.protocolProperties.cipherSuites
	some algorithm_ref in cipher_suite.algorithms
	ref := algorithm_ref.ref
}

# Generic CycloneDX dependency relationships.
dependency_refs(component) := {ref |
	some dependency in object.get(input, "dependencies", [])
	dependency.ref == component["bom-ref"]
	some ref in object.get(dependency, "dependsOn", [])
}

component_references(component) := union({
	related_material_algorithm_refs(component),
	related_material_secured_by_refs(component),
	related_material_asset_refs(component),
	certificate_signature_algorithm_refs(component),
	certificate_public_key_refs(component),
	certificate_asset_refs(component),
	protocol_string_algorithm_refs(component),
	protocol_object_algorithm_refs(component),
	dependency_refs(component),
})

has_references(component) if {
	count(component_references(component)) > 0
}

# graph.reachable handles duplicate edges and cycles. Include referenced IDs
# that are not components as empty graph nodes so dangling refs remain in the
# reachable set and contribute an unknown result.
component_ids := {ref |
	some component in object.get(input, "components", [])
	ref := component["bom-ref"]
}

referenced_ids := {ref |
	some component in object.get(input, "components", [])
	some ref in component_references(component)
}

all_graph_ids := component_ids | referenced_ids

graph_references(ref) := references if {
	component := component_by_ref(ref)
	references := component_references(component)
}

graph_references(ref) := set() if {
	not component_exists(ref)
}

asset_graph := {ref: graph_references(ref) |
	some ref in all_graph_ids
}

reachable_refs(component) := reachable if {
	start := {component["bom-ref"]}
	reachable_with_self := graph.reachable(asset_graph, start)
	reachable := reachable_with_self - start
}

reachable_algorithm_refs(component) := {ref |
	some ref in reachable_refs(component)
	referenced_component := component_by_ref(ref)
	is_algorithm(referenced_component)
}

dangling_refs(component) := {ref |
	some ref in reachable_refs(component)
	not component_exists(ref)
}

sorted_reachable_refs(component) := sort([ref | some ref in reachable_refs(component)])

# Direct algorithm evaluation mirrors BasicQuantumSafeComplianceService.
algorithm_assessment(component) := {
	"result": "unknown",
	"rule": "missing_algorithm_properties",
	"property": "cryptoProperties.algorithmProperties",
	"value": "",
} if {
	not has_algorithm_properties(component)
}

algorithm_assessment(component) := {
	"result": "quantum-safe",
	"rule": "positive_nist_quantum_security_level",
	"property": "cryptoProperties.algorithmProperties.nistQuantumSecurityLevel",
	"value": sprintf("%v", [component.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel]),
} if {
	has_positive_nist_level(component)
}

algorithm_assessment(component) := {
	"result": "unknown",
	"rule": "missing_primitive",
	"property": "cryptoProperties.algorithmProperties.primitive",
	"value": "",
} if {
	has_algorithm_properties(component)
	not has_positive_nist_level(component)
	not has_primitive(component)
}

algorithm_assessment(component) := {
	"result": "quantum-safe",
	"rule": "whitelisted_oid",
	"property": "cryptoProperties.oid",
	"value": sprintf("%v", [component.cryptoProperties.oid]),
} if {
	not has_positive_nist_level(component)
	primitive := component.cryptoProperties.algorithmProperties.primitive
	is_asymmetric_or_unknown(primitive)
	has_whitelisted_oid(component)
}

algorithm_assessment(component) := {
	"result": "quantum-safe",
	"rule": "whitelisted_name",
	"property": "name",
	"value": sprintf("%v", [component.name]),
} if {
	not has_positive_nist_level(component)
	primitive := component.cryptoProperties.algorithmProperties.primitive
	is_asymmetric_or_unknown(primitive)
	not has_whitelisted_oid(component)
	has_matching_name(component)
}

algorithm_assessment(component) := {
	"result": "quantum-vulnerable",
	"rule": "asymmetric_not_whitelisted",
	"property": "cryptoProperties.algorithmProperties.primitive",
	"value": sprintf("%v", [component.cryptoProperties.algorithmProperties.primitive]),
} if {
	not has_positive_nist_level(component)
	primitive := component.cryptoProperties.algorithmProperties.primitive
	is_asymmetric(primitive)
	not has_whitelisted_oid(component)
	not has_matching_name(component)
}

algorithm_assessment(component) := {
	"result": "unknown",
	"rule": "unknown_primitive",
	"property": "cryptoProperties.algorithmProperties.primitive",
	"value": sprintf("%v", [component.cryptoProperties.algorithmProperties.primitive]),
} if {
	not has_positive_nist_level(component)
	primitive := component.cryptoProperties.algorithmProperties.primitive
	is_unknown_primitive(primitive)
	not has_whitelisted_oid(component)
	not has_matching_name(component)
}

algorithm_assessment(component) := {
	"result": "na",
	"rule": "non_asymmetric_primitive",
	"property": "cryptoProperties.algorithmProperties.primitive",
	"value": sprintf("%v", [component.cryptoProperties.algorithmProperties.primitive]),
} if {
	not has_positive_nist_level(component)
	primitive := component.cryptoProperties.algorithmProperties.primitive
	not is_asymmetric(primitive)
	not is_unknown_primitive(primitive)
}

# Candidate results for a component and every transitively referenced
# algorithm. Direct algorithm results are included so hybrid/composite
# algorithms inherit the worst result of their constituents.
direct_candidate_results(component) := {result |
	is_algorithm(component)
	result := algorithm_assessment(component).result
}

reachable_candidate_results(component) := {result |
	some ref in reachable_algorithm_refs(component)
	referenced_component := component_by_ref(ref)
	result := algorithm_assessment(referenced_component).result
}

dangling_candidate_results(component) := {"unknown" |
	count(dangling_refs(component)) > 0
}

unresolved_candidate_results(component) := {"unknown" |
	has_references(component)
	not is_algorithm(component)
	count(reachable_algorithm_refs(component)) == 0
}

candidate_results(component) := union({
	direct_candidate_results(component),
	reachable_candidate_results(component),
	dangling_candidate_results(component),
	unresolved_candidate_results(component),
})

worst_result(results) := result if {
	ranks := [result_rank[candidate] | some candidate in results]
	worst_rank := min(ranks)
	result := rank_result[worst_rank]
}

# Per-side evaluation for certificates. Unlike reachable_refs the starting
# references are kept, because a certificate's signatureAlgorithmRef points
# directly at the algorithm being judged.
refs_algorithm_results(refs) := {result |
	some ref in graph.reachable(asset_graph, refs)
	referenced_component := component_by_ref(ref)
	is_algorithm(referenced_component)
	result := algorithm_assessment(referenced_component).result
}

refs_dangling_results(refs) := {"unknown" |
	some ref in graph.reachable(asset_graph, refs)
	not component_exists(ref)
}

refs_unresolved_results(refs) := {"unknown" |
	count(refs) > 0
	count(refs_algorithm_results(refs)) == 0
}

refs_results(refs) := union({
	refs_algorithm_results(refs),
	refs_dangling_results(refs),
	refs_unresolved_results(refs),
})

# Human-readable per-side outcome used to attribute a certificate finding.
side_summary(refs) := "not specified" if {
	count(refs) == 0
}

side_summary(refs) := worst_result(refs_results(refs)) if {
	count(refs) > 0
}

# Unlinked material that is intrinsically non-asymmetric is outside the scope
# of this quantum-safety policy. Ambiguous material remains unknown.
is_not_applicable_material(component) if {
	is_related_crypto_material(component)
	component.cryptoProperties.relatedCryptoMaterialProperties.type in not_applicable_material_types
}

unlinked_result(component) := "na" if {
	is_not_applicable_material(component)
}

unlinked_result(component) := "unknown" if {
	not is_algorithm(component)
	not is_not_applicable_material(component)
}

unlinked_rule("unknown") := "unlinked_asset_unknown"

unlinked_rule("na") := "unlinked_asset_not_applicable"

# The directives responsible for a component's result: every configuration-derived
# algorithm it reaches whose own result is the one being reported. A protocol or
# configuration file is judged worst-of, so these are the entries a user would
# have to change to improve the verdict.
offending_entries(component) := entries if {
	results := candidate_results(component)
	count(results) > 0
	worst := worst_result(results)
	entries := {[directive, openssl_display(referenced)] |
		some ref in reachable_algorithm_refs(component)
		referenced := component_by_ref(ref)
		algorithm_assessment(referenced).result == worst
		some directive in openssl_directives(referenced)
	}
}

# Kept total so count() below never goes undefined and silently drops a finding.
offending_entries(component) := set() if {
	count(candidate_results(component)) == 0
}

offending_directives(component) := sort({directive |
	some entry in offending_entries(component)
	directive := entry[0]
})

offending_names(component, wanted) := sort({name |
	some entry in offending_entries(component)
	entry[0] == wanted
	name := entry[1]
})

offending_summary(component) := concat("; ", [summary |
	some directive in offending_directives(component)
	summary := sprintf("%s permits %s", [
		directive,
		concat(", ", offending_names(component, directive)),
	])
])

has_openssl_context(component) if {
	is_openssl_config(component)
}

has_openssl_context(component) if {
	count(offending_entries(component)) > 0
}

openssl_summary_text(component) := "no quantum-vulnerable directives" if {
	count(offending_entries(component)) == 0
}

openssl_summary_text(component) := offending_summary(component) if {
	count(offending_entries(component)) > 0
}

# Presentation only: the result itself always comes from final_assessment, so
# worst-of propagation and certificate side-attribution are unchanged. These
# three clauses are mutually exclusive.
presentation(component, assessment) := {
	"rule": "openssl_directive_quantum_safety",
	"property": "theia:openssl:directive",
	"value": sprintf("%s permits %s (%s)", [
		concat(", ", sort([directive | some directive in openssl_directives(component)])),
		openssl_display(component),
		assessment.result,
	]),
} if {
	has_openssl_directive(component)
}

presentation(component, assessment) := {
	"rule": "openssl_config_quantum_safety",
	"property": "theia:openssl:config",
	"value": sprintf("%s: %s", [assessment.result, openssl_summary_text(component)]),
} if {
	not has_openssl_directive(component)
	has_openssl_context(component)
}

presentation(component, assessment) := {
	"rule": assessment.rule,
	"property": assessment.property,
	"value": assessment.value,
} if {
	not has_openssl_directive(component)
	not has_openssl_context(component)
}

final_assessment(component) := algorithm_assessment(component) if {
	is_algorithm(component)
	not has_references(component)
}

# Certificates are reported with their own rule so a finding names the side that
# caused it: re-signing by the CA and re-keying the subject are different fixes.
final_assessment(component) := {
	"result": result,
	"rule": "certificate_quantum_safety",
	"property": "cryptoProperties.certificateProperties",
	"value": sprintf(
		"%s (signature algorithm: %s, subject public key: %s)",
		[
			result,
			side_summary(certificate_signature_refs(component)),
			side_summary(certificate_subject_key_refs(component)),
		],
	),
} if {
	is_certificate(component)
	has_references(component)
	results := candidate_results(component)
	count(results) > 0
	result := worst_result(results)
}

final_assessment(component) := {
	"result": result,
	"rule": "linked_asset_quantum_safety",
	"property": "cryptographic asset references",
	"value": sprintf("%s across %d referenced asset(s)", [result, count(reachable_refs(component))]),
} if {
	not is_certificate(component)
	has_references(component)
	results := candidate_results(component)
	count(results) > 0
	result := worst_result(results)
}

final_assessment(component) := {
	"result": result,
	"rule": rule,
	"property": "cryptoProperties.assetType",
	"value": sprintf("%v", [asset_type]),
} if {
	not is_algorithm(component)
	not has_references(component)
	result := unlinked_result(component)
	rule := unlinked_rule(result)
	crypto_properties := object.get(component, "cryptoProperties", {})
	asset_type := object.get(crypto_properties, "assetType", "unknown")
}

quantum_safe.findings contains finding if {
	some component in object.get(input, "components", [])
	assessment := final_assessment(component)
	view := presentation(component, assessment)
	references := sorted_reachable_refs(component)
	finding := {
		"bom-ref": component["bom-ref"],
		"result": assessment.result,
		"rule": view.rule,
		"property": view.property,
		"value": view.value,
		"referenceList": references,
	}
}
