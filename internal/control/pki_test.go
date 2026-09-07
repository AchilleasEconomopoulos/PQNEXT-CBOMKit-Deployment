package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type certificateFixture struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func makeCertificate(t *testing.T, name string, isCA bool, parent *certificateFixture, usages []x509.ExtKeyUsage, dns []string, ips []net.IP, notBefore, notAfter time.Time) certificateFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           usages,
		DNSNames:              dns,
		IPAddresses:           ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	issuer := template
	issuerKey := key
	if parent != nil {
		issuer = parent.cert
		issuerKey = parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFixture{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func fixtureMaterial(t *testing.T, leafOptions ...func(*x509.Certificate)) pkiMaterial {
	t.Helper()
	now := time.Now()
	serverCA := makeCertificate(t, "server-ca", true, nil, nil, nil, nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	clientCA := makeCertificate(t, "client-ca", true, nil, nil, nil, nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	leaf := makeCertificate(t, "server", false, &serverCA, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"server.example"}, []net.IP{net.ParseIP("127.0.0.1")}, now.Add(-time.Hour), now.Add(time.Hour))
	if len(leafOptions) > 0 {
		template := *leaf.cert
		for _, option := range leafOptions {
			option(&template)
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, serverCA.cert, &leaf.key.PublicKey, serverCA.key)
		if err != nil {
			t.Fatal(err)
		}
		leaf.cert, err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		leaf.pem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.key)
	if err != nil {
		t.Fatal(err)
	}
	return pkiMaterial{
		ServerCertificate: append(append([]byte{}, leaf.pem...), serverCA.pem...),
		ServerKey:         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		ClientCA:          clientCA.pem,
	}
}

func TestValidatePKIAcceptsSeparateServerAndClientCAs(t *testing.T) {
	material := fixtureMaterial(t)
	if err := validatePKI(material, "127.0.0.1", "server.example", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePKIRejectsInvalidInputs(t *testing.T) {
	valid := fixtureMaterial(t)
	tests := []struct {
		name   string
		change func(pkiMaterial) pkiMaterial
		match  string
	}{
		{"missing chain", func(m pkiMaterial) pkiMaterial {
			_, rest := pem.Decode(m.ServerCertificate)
			m.ServerCertificate = m.ServerCertificate[:len(m.ServerCertificate)-len(rest)]
			return m
		}, "missing its issuer"},
		{"wrong SAN", func(m pkiMaterial) pkiMaterial { return m }, "does not cover DNS"},
		{"malformed PEM", func(m pkiMaterial) pkiMaterial { m.ServerCertificate = []byte("not pem"); return m }, "non-PEM"},
		{"mismatched key", func(m pkiMaterial) pkiMaterial { m.ServerKey = fixtureMaterial(t).ServerKey; return m }, "do not match"},
		{"non CA client trust", func(m pkiMaterial) pkiMaterial {
			block, _ := pem.Decode(m.ServerCertificate)
			m.ClientCA = pem.EncodeToMemory(block)
			return m
		}, "not authorized"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dns := "server.example"
			if test.name == "wrong SAN" {
				dns = "wrong.example"
			}
			err := validatePKI(test.change(valid), "127.0.0.1", dns, time.Now())
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("error = %v, want substring %q", err, test.match)
			}
		})
	}
}

func TestValidatePKIRejectsExpiryAndWrongEKU(t *testing.T) {
	expired := fixtureMaterial(t, func(cert *x509.Certificate) {
		cert.NotBefore = time.Now().Add(-2 * time.Hour)
		cert.NotAfter = time.Now().Add(-time.Hour)
	})
	if err := validatePKI(expired, "127.0.0.1", "server.example", time.Now()); err == nil || !strings.Contains(err.Error(), "not valid") {
		t.Fatalf("expired certificate error = %v", err)
	}
	clientOnly := fixtureMaterial(t, func(cert *x509.Certificate) {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	if err := validatePKI(clientOnly, "127.0.0.1", "server.example", time.Now()); err == nil || !strings.Contains(err.Error(), "serverAuth") {
		t.Fatalf("wrong EKU error = %v", err)
	}
}

func TestParsePrivateKeyRejectsEncryptedKey(t *testing.T) {
	material := fixtureMaterial(t)
	block, _ := pem.Decode(material.ServerKey)
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", block.Bytes, []byte("secret"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePrivateKey(pem.EncodeToMemory(encrypted)); err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Fatalf("error = %v", err)
	}
}

func TestPKIArchiveRoundTripAndAtomicInstall(t *testing.T) {
	material := fixtureMaterial(t)
	archive, err := makePKIArchive(material)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := readPKIArchive(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.ServerKey, material.ServerKey) {
		t.Fatal("private key changed during archive round trip")
	}
	target := t.TempDir()
	if err := installPKI(target, "external", decoded); err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink(filepath.Join(target, "current"))
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(filepath.Join(target, current, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("server key mode = %o", keyInfo.Mode().Perm())
	}
	var bad bytes.Buffer
	badWriter := tar.NewWriter(&bad)
	_ = badWriter.WriteHeader(&tar.Header{Name: "../server.key", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	_, _ = badWriter.Write([]byte("x"))
	_ = badWriter.Close()
	if _, err := readPKIArchive(&bad); err == nil {
		t.Fatal("archive with an unexpected path was accepted")
	}
	stillCurrent, _ := os.Readlink(filepath.Join(target, "current"))
	if stillCurrent != current {
		t.Fatal("active PKI changed after invalid input")
	}
}

func makeRecoveryArchive(t *testing.T) []byte {
	t.Helper()
	now := time.Now()
	root := makeCertificate(t, "root", true, nil, nil, nil, nil, now.Add(-time.Hour), now.Add(24*time.Hour))
	keyDER, err := x509.MarshalECPrivateKey(root.key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("recovery password"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	fingerprintBytes := sha256.Sum256(root.cert.Raw)
	manifest, _ := json.Marshal(recoveryManifest{Version: 1, Fingerprint: hex.EncodeToString(fingerprintBytes[:]), CAName: "test", CreatedAt: now.UTC().Format(time.RFC3339)})
	files := map[string][]byte{
		"root_ca.crt":   root.pem,
		"root_ca_key":   pem.EncodeToMemory(encrypted),
		"manifest.json": append(manifest, '\n'),
	}
	var sums strings.Builder
	for _, name := range []string{"root_ca.crt", "root_ca_key", "manifest.json"} {
		digest := sha256.Sum256(files[name])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	files["SHA256SUMS"] = []byte(sums.String())
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"root_ca.crt", "root_ca_key", "manifest.json", "SHA256SUMS"} {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestValidateAndSaveRecoveryArchive(t *testing.T) {
	archive := makeRecoveryArchive(t)
	manifest, err := validateRecoveryArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	path, err := saveRecoveryArchive(t.TempDir(), manifest.Fingerprint, archive)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery archive mode = %o", info.Mode().Perm())
	}
}

func TestValidateRootCertificate(t *testing.T) {
	now := time.Now()
	root := makeCertificate(t, "managed-root", true, nil, nil, nil, nil, now.Add(-time.Hour), now.Add(time.Hour))
	digest := sha256.Sum256(root.cert.Raw)
	fingerprint := hex.EncodeToString(digest[:])
	if err := validateRootCertificate(root.pem, fingerprint, now); err != nil {
		t.Fatal(err)
	}
	if err := validateRootCertificate(root.pem, strings.Repeat("0", 64), now); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("fingerprint mismatch error = %v", err)
	}
	leaf := makeCertificate(t, "not-a-ca", false, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, nil, now.Add(-time.Hour), now.Add(time.Hour))
	leafDigest := sha256.Sum256(leaf.cert.Raw)
	if err := validateRootCertificate(leaf.pem, hex.EncodeToString(leafDigest[:]), now); err == nil || !strings.Contains(err.Error(), "self-signed certificate authority") {
		t.Fatalf("non-CA error = %v", err)
	}
}

func TestRecoveryArchiveRejectsTampering(t *testing.T) {
	archive := makeRecoveryArchive(t)
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := tr.Next()
		if err != nil {
			break
		}
		files[header.Name], _ = ioReadAll(tr)
	}
	files["manifest.json"] = append(files["manifest.json"], ' ')
	var output bytes.Buffer
	outGzip := gzip.NewWriter(&output)
	tw := tar.NewWriter(outGzip)
	for _, name := range []string{"root_ca.crt", "root_ca_key", "manifest.json", "SHA256SUMS"} {
		data := files[name]
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = outGzip.Close()
	if _, err := validateRecoveryArchive(output.Bytes()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered recovery error = %v", err)
	}
}

func ioReadAll(r *tar.Reader) ([]byte, error) {
	var output bytes.Buffer
	_, err := output.ReadFrom(r)
	return output.Bytes(), err
}
