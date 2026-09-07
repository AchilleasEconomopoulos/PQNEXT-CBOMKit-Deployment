package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maxPKIFileSize = 4 << 20
	maxPKIArchive  = 16 << 20
)

type pkiMaterial struct {
	ServerCertificate []byte
	ServerKey         []byte
	ClientCA          []byte
}

type recoveryManifest struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
	CAName      string `json:"caName"`
	CreatedAt   string `json:"createdAt"`
}

func validateRootCertificate(data []byte, expectedFingerprint string, now time.Time) error {
	certs, err := parseCertificateBundle(data, "root CA certificate")
	if err != nil {
		return err
	}
	if len(certs) != 1 {
		return errors.New("root CA export must contain exactly one certificate")
	}
	root := certs[0]
	if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.CheckSignatureFrom(root) != nil {
		return errors.New("exported certificate is not a self-signed certificate authority")
	}
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return fmt.Errorf("root CA certificate is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	digest := sha256.Sum256(root.Raw)
	actual := hex.EncodeToString(digest[:])
	if !strings.EqualFold(strings.TrimSpace(expectedFingerprint), actual) {
		return fmt.Errorf("root CA fingerprint mismatch: expected %s, got %s", expectedFingerprint, actual)
	}
	return nil
}

func readRegularFile(path, description string) ([]byte, error) {
	data, _, err := readRegularFileInfo(path, description)
	return data, err
}

func readRegularFileInfo(path, description string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s metadata: %w", description, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s must be a regular file", description)
	}
	if info.Size() == 0 || info.Size() > maxPKIFileSize {
		return nil, nil, fmt.Errorf("%s must be between 1 byte and %d bytes", description, maxPKIFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", description, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s metadata: %w", description, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, nil, fmt.Errorf("%s changed while it was being opened", description)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPKIFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", description, err)
	}
	if len(data) == 0 || len(data) > maxPKIFileSize {
		return nil, nil, fmt.Errorf("%s must be between 1 byte and %d bytes", description, maxPKIFileSize)
	}
	return data, openedInfo, nil
}

func loadPKIMaterial(certPath, keyPath, caPath string) (pkiMaterial, error) {
	cert, err := readRegularFile(certPath, "server certificate")
	if err != nil {
		return pkiMaterial{}, err
	}
	key, err := readRegularFile(keyPath, "server private key")
	if err != nil {
		return pkiMaterial{}, err
	}
	ca, err := readRegularFile(caPath, "client CA bundle")
	if err != nil {
		return pkiMaterial{}, err
	}
	return pkiMaterial{ServerCertificate: cert, ServerKey: key, ClientCA: ca}, nil
}

func parseCertificateBundle(data []byte, description string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("%s contains non-PEM data", description)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s contains unexpected PEM block %q", description, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", description, err)
		}
		certs = append(certs, cert)
		rest = remaining
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s contains no certificates", description)
	}
	return certs, nil
}

func parsePrivateKey(data []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("server private key must contain exactly one PEM block")
	}
	if x509.IsEncryptedPEMBlock(block) || strings.Contains(block.Type, "ENCRYPTED") {
		return nil, errors.New("server private key must be unencrypted")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private-key PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing server private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private-key type %T", key)
	}
	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private-key type %T", key)
	}
}

func validatePKI(material pkiMaterial, serverIP, serverDNS string, now time.Time) error {
	serverChain, err := parseCertificateBundle(material.ServerCertificate, "server certificate chain")
	if err != nil {
		return err
	}
	leaf := serverChain[0]
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("server certificate is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	serverUsage := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			serverUsage = true
			break
		}
	}
	if !serverUsage {
		return errors.New("server certificate does not permit serverAuth")
	}
	if ip := net.ParseIP(serverIP); ip == nil {
		return fmt.Errorf("invalid server IP %q", serverIP)
	}
	if err := leaf.VerifyHostname(serverIP); err != nil {
		return fmt.Errorf("server certificate does not cover IP %q: %w", serverIP, err)
	}
	if serverDNS != "" {
		if err := leaf.VerifyHostname(serverDNS); err != nil {
			return fmt.Errorf("server certificate does not cover DNS name %q: %w", serverDNS, err)
		}
	}
	if len(serverChain) < 2 {
		if !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			return errors.New("server certificate chain is missing its issuer certificate")
		}
	}
	for i := 0; i+1 < len(serverChain); i++ {
		issuer := serverChain[i+1]
		if now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
			return fmt.Errorf("server chain certificate %d is not currently valid", i+1)
		}
		if !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("server chain certificate %d is not a signing CA", i+1)
		}
		if err := serverChain[i].CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("server chain certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(serverChain[len(serverChain)-1])
	intermediates := x509.NewCertPool()
	for _, cert := range serverChain[1 : len(serverChain)-1] {
		intermediates.AddCert(cert)
	}
	identity := serverIP
	if serverDNS != "" {
		identity = serverDNS
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       identity,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("server certificate chain validation failed: %w", err)
	}
	signer, err := parsePrivateKey(material.ServerKey)
	if err != nil {
		return err
	}
	leafPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("encoding server certificate public key: %w", err)
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("encoding server private-key public key: %w", err)
	}
	if !bytes.Equal(leafPublic, keyPublic) {
		return errors.New("server certificate and private key do not match")
	}
	clientCAs, err := parseCertificateBundle(material.ClientCA, "client CA bundle")
	if err != nil {
		return err
	}
	for i, cert := range clientCAs {
		if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("client CA certificate %d is not authorized to sign certificates", i)
		}
	}
	return nil
}

func makePKIArchive(material pkiMaterial) ([]byte, error) {
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	files := []struct {
		name string
		mode int64
		data []byte
	}{
		{"server.crt", 0o644, material.ServerCertificate},
		{"server.key", 0o600, material.ServerKey},
		{"ca.crt", 0o644, material.ClientCA},
	}
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: file.mode, Size: int64(len(file.data)), Typeflag: tar.TypeReg}
		if err := w.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("creating PKI archive: %w", err)
		}
		if _, err := w.Write(file.data); err != nil {
			return nil, fmt.Errorf("creating PKI archive: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing PKI archive: %w", err)
	}
	return output.Bytes(), nil
}

func readPKIArchive(r io.Reader) (pkiMaterial, error) {
	archive, err := io.ReadAll(io.LimitReader(r, maxPKIArchive+1))
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("reading PKI archive: %w", err)
	}
	if len(archive) > maxPKIArchive {
		return pkiMaterial{}, errors.New("PKI archive is too large")
	}
	buffer := bytes.NewReader(archive)
	tr := tar.NewReader(buffer)
	files := make(map[string][]byte, 3)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return pkiMaterial{}, fmt.Errorf("reading PKI archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || (header.Name != "server.crt" && header.Name != "server.key" && header.Name != "ca.crt") {
			return pkiMaterial{}, fmt.Errorf("unexpected PKI archive entry %q", header.Name)
		}
		if _, exists := files[header.Name]; exists {
			return pkiMaterial{}, fmt.Errorf("duplicate PKI archive entry %q", header.Name)
		}
		if header.Size <= 0 || header.Size > maxPKIFileSize {
			return pkiMaterial{}, fmt.Errorf("invalid size for PKI archive entry %q", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxPKIFileSize+1))
		if err != nil {
			return pkiMaterial{}, fmt.Errorf("reading PKI archive entry %q: %w", header.Name, err)
		}
		if len(data) > maxPKIFileSize {
			return pkiMaterial{}, fmt.Errorf("PKI archive entry %q is too large", header.Name)
		}
		files[header.Name] = data
	}
	trailing, err := io.ReadAll(buffer)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("reading PKI archive trailer: %w", err)
	}
	if len(bytes.Trim(trailing, "\x00")) != 0 {
		return pkiMaterial{}, errors.New("PKI archive contains trailing data")
	}
	for _, name := range []string{"server.crt", "server.key", "ca.crt"} {
		if len(files[name]) == 0 {
			return pkiMaterial{}, fmt.Errorf("PKI archive is missing %q", name)
		}
	}
	return pkiMaterial{files["server.crt"], files["server.key"], files["ca.crt"]}, nil
}

func installPKI(targetDir, source string, material pkiMaterial) error {
	versions := filepath.Join(targetDir, "versions")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		return fmt.Errorf("creating PKI versions directory: %w", err)
	}
	versionDir, err := os.MkdirTemp(versions, ".staging-")
	if err != nil {
		return fmt.Errorf("creating PKI staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(versionDir)
		}
	}()
	if err := writeFileSync(filepath.Join(versionDir, "server.crt"), material.ServerCertificate, 0o644); err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(versionDir, "server.key"), material.ServerKey, 0o600); err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(versionDir, "ca.crt"), material.ClientCA, 0o644); err != nil {
		return err
	}
	metadata, err := json.MarshalIndent(map[string]any{
		"version":     1,
		"source":      source,
		"installedAt": time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding PKI metadata: %w", err)
	}
	if err := writeFileSync(filepath.Join(versionDir, "metadata.json"), append(metadata, '\n'), 0o644); err != nil {
		return err
	}
	if err := syncDir(versionDir); err != nil {
		return err
	}
	finalName := "version-" + filepath.Base(versionDir)[len(".staging-"):]
	finalDir := filepath.Join(versions, finalName)
	if err := os.Rename(versionDir, finalDir); err != nil {
		return fmt.Errorf("committing PKI version: %w", err)
	}
	versionDir = finalDir
	linkTarget := filepath.Join("versions", finalName)
	oldTarget, _ := os.Readlink(filepath.Join(targetDir, "current"))
	tmpLink := filepath.Join(targetDir, ".current-new")
	_ = os.Remove(tmpLink)
	if err := os.Symlink(linkTarget, tmpLink); err != nil {
		return fmt.Errorf("creating PKI current link: %w", err)
	}
	if err := replaceFile(tmpLink, filepath.Join(targetDir, "current")); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("activating PKI version: %w", err)
	}
	committed = true
	if err := syncDir(targetDir); err != nil {
		return err
	}
	if filepath.Dir(oldTarget) == "versions" && oldTarget != linkTarget {
		_ = os.RemoveAll(filepath.Join(targetDir, oldTarget))
	}
	return nil
}

func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("syncing directory: %w", err)
	}
	return nil
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("syncing %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", filepath.Base(path), err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", filepath.Base(path), err)
	}
	return nil
}

func validateRecoveryArchive(data []byte) (recoveryManifest, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return recoveryManifest{}, fmt.Errorf("opening recovery archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxPKIArchive+1))
	files := map[string][]byte{}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return recoveryManifest{}, fmt.Errorf("reading recovery archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || (header.Name != "root_ca.crt" && header.Name != "root_ca_key" && header.Name != "manifest.json" && header.Name != "SHA256SUMS") {
			return recoveryManifest{}, fmt.Errorf("unexpected recovery archive entry %q", header.Name)
		}
		if _, exists := files[header.Name]; exists {
			return recoveryManifest{}, fmt.Errorf("duplicate recovery archive entry %q", header.Name)
		}
		if header.Size <= 0 || header.Size > maxPKIFileSize {
			return recoveryManifest{}, fmt.Errorf("invalid recovery archive entry %q", header.Name)
		}
		entry, err := io.ReadAll(io.LimitReader(tr, maxPKIFileSize+1))
		if err != nil {
			return recoveryManifest{}, err
		}
		files[header.Name] = entry
	}
	for _, name := range []string{"root_ca.crt", "root_ca_key", "manifest.json", "SHA256SUMS"} {
		if len(files[name]) == 0 {
			return recoveryManifest{}, fmt.Errorf("recovery archive is missing %q", name)
		}
	}
	block, rest := pem.Decode(files["root_ca_key"])
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || (!strings.Contains(block.Type, "ENCRYPTED") && !x509.IsEncryptedPEMBlock(block)) {
		return recoveryManifest{}, errors.New("recovery root key is not an encrypted PEM private key")
	}
	certs, err := parseCertificateBundle(files["root_ca.crt"], "recovery root certificate")
	if err != nil || len(certs) != 1 {
		return recoveryManifest{}, errors.New("recovery archive must contain exactly one root certificate")
	}
	if !certs[0].IsCA || certs[0].KeyUsage&x509.KeyUsageCertSign == 0 || certs[0].CheckSignatureFrom(certs[0]) != nil {
		return recoveryManifest{}, errors.New("recovery root certificate is not a self-signed certificate authority")
	}
	checksums := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(files["SHA256SUMS"])), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return recoveryManifest{}, errors.New("recovery checksum file is malformed")
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != "root_ca.crt" && name != "root_ca_key" && name != "manifest.json" {
			return recoveryManifest{}, fmt.Errorf("recovery checksum references unexpected file %q", name)
		}
		if _, exists := checksums[name]; exists {
			return recoveryManifest{}, fmt.Errorf("duplicate recovery checksum for %q", name)
		}
		checksums[name] = strings.ToLower(fields[0])
	}
	for _, name := range []string{"root_ca.crt", "root_ca_key", "manifest.json"} {
		digest := sha256.Sum256(files[name])
		if checksums[name] != hex.EncodeToString(digest[:]) {
			return recoveryManifest{}, fmt.Errorf("recovery checksum does not match %q", name)
		}
	}
	var manifest recoveryManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		return recoveryManifest{}, fmt.Errorf("parsing recovery manifest: %w", err)
	}
	fingerprintBytes := sha256.Sum256(certs[0].Raw)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])
	if manifest.Version != 1 || manifest.Fingerprint != fingerprint {
		return recoveryManifest{}, errors.New("recovery manifest does not match its root certificate")
	}
	if strings.TrimSpace(manifest.CAName) == "" {
		return recoveryManifest{}, errors.New("recovery manifest has no CA name")
	}
	if _, err := time.Parse(time.RFC3339, manifest.CreatedAt); err != nil {
		return recoveryManifest{}, errors.New("recovery manifest has an invalid creation time")
	}
	return manifest, nil
}

func defaultRecoveryDir(goos string, env map[string]string, home string) string {
	switch goos {
	case "windows":
		if value := env["LOCALAPPDATA"]; value != "" {
			return filepath.Join(value, "pqnext-cbomkit", "recovery")
		}
		return filepath.Join(home, "AppData", "Local", "pqnext-cbomkit", "recovery")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "pqnext-cbomkit", "recovery")
	default:
		if value := env["XDG_DATA_HOME"]; value != "" {
			return filepath.Join(value, "pqnext-cbomkit", "recovery")
		}
	}
	return filepath.Join(home, ".local", "share", "pqnext-cbomkit", "recovery")
}

func currentDefaultRecoveryDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	env := map[string]string{
		"LOCALAPPDATA":  os.Getenv("LOCALAPPDATA"),
		"XDG_DATA_HOME": os.Getenv("XDG_DATA_HOME"),
	}
	return defaultRecoveryDir(runtime.GOOS, env, home), nil
}
