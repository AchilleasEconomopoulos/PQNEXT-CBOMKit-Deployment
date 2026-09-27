package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeStackVersion(t *testing.T) {
	for _, version := range []string{"1.2.3", "v1.2.3", "stack-v1.2.3"} {
		if tag, err := normalizeStackVersion(version); err != nil || tag != "stack-v1.2.3" {
			t.Fatalf("normalize(%q) = %q, %v", version, tag, err)
		}
	}
	if tag, err := normalizeStackVersion("1.2.3-rc.1"); err != nil || tag != "stack-v1.2.3-rc.1" {
		t.Fatalf("prerelease = %q, %v", tag, err)
	}
	for _, version := range []string{"", "latest", "1.2", "cli-v1.2.3", "../1.2.3", "1.2.3/extra", "1.2.3?token=x"} {
		if _, err := normalizeStackVersion(version); err == nil {
			t.Fatalf("accepted invalid version %q", version)
		}
	}
}

func stackArchive(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, header := range headers {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func fixtureStackArchive(t *testing.T) []byte {
	t.Helper()
	var headers []*tar.Header
	for _, name := range []string{
		"docker-compose.yml", "nginx.conf", ".env.example", ".dockerignore", "go.mod", "go.sum",
		"step-ca/Dockerfile", "step-ca/bin/pqnext-cbomkit-pki", "step-ca/templates/server.tpl", "step-ca/templates/client.tpl",
		"opa/quantum_safe.rego", "cmd/pqnext-cbomkitctl/main.go", "internal/control/app.go",
	} {
		mode := int64(0o644)
		if name == "step-ca/bin/pqnext-cbomkit-pki" {
			mode = 0o755
		}
		headers = append(headers, &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: 1})
	}
	return stackArchive(t, headers)
}

func serveStack(t *testing.T, archive []byte, checksum string) (*httptest.Server, *int) {
	t.Helper()
	requests := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests = *requests + 1
		if r.Header.Get("Authorization") != "" {
			t.Error("public download sent authorization")
		}
		switch r.URL.Path {
		case "/stack-v1.2.3/SHA256SUMS":
			fmt.Fprintf(w, "%s  pqnext-cbomkit-stack-v1.2.3.tar.gz\n", checksum)
		case "/stack-v1.2.3/pqnext-cbomkit-stack-v1.2.3.tar.gz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func TestDownloadStackVerifiesAndReusesBundle(t *testing.T) {
	home := setTestStateHome(t)
	archive := fixtureStackArchive(t)
	server, requests := serveStack(t, archive, fmt.Sprintf("%x", sha256.Sum256(archive)))
	a := &app{releaseBaseURL: server.URL, httpClient: server.Client(), stdout: io.Discard}
	dir, err := a.downloadStack(context.Background(), "stack-v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if dir != filepath.Join(home, ".pqnext", "cbomkit", "stacks", "stack-v1.2.3") || *requests != 2 {
		t.Fatalf("dir=%q requests=%d", dir, *requests)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "step-ca", "bin", "pqnext-cbomkit-pki"))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("script mode: info=%v err=%v", info, err)
		}
	}
	if _, err := a.downloadStack(context.Background(), "stack-v1.2.3"); err != nil || *requests != 2 {
		t.Fatalf("cache reuse: err=%v requests=%d", err, *requests)
	}
}

func TestDownloadStackFailureLeavesNoDeployment(t *testing.T) {
	for _, test := range []struct {
		name    string
		archive []byte
		badHash bool
	}{
		{"checksum mismatch", fixtureStackArchive(t), true},
		{"incomplete bundle", stackArchive(t, []*tar.Header{{Name: composeFile, Typeflag: tar.TypeReg, Size: 1}}), false},
		{"unsafe archive", stackArchive(t, []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg, Size: 1}}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := setTestStateHome(t)
			checksum := fmt.Sprintf("%x", sha256.Sum256(test.archive))
			if test.badHash {
				checksum = strings.Repeat("0", 64)
			}
			server, _ := serveStack(t, test.archive, checksum)
			a := &app{releaseBaseURL: server.URL, httpClient: server.Client(), stdout: io.Discard}
			if _, err := a.downloadStack(context.Background(), "stack-v1.2.3"); err == nil {
				t.Fatal("invalid download succeeded")
			}
			parent := filepath.Join(home, ".pqnext", "cbomkit", "stacks")
			entries, err := os.ReadDir(parent)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed download left files: %v", entries)
			}
		})
	}
}

func TestDownloadReleaseAssetHTTPFailuresAndLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "too much data")
	}))
	defer server.Close()
	a := &app{httpClient: server.Client()}
	for _, test := range []struct{ path, want string }{{"/missing", "HTTP 404"}, {"/large", "size limit"}} {
		if _, err := a.downloadReleaseAsset(context.Background(), server.URL+test.path, 4); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("download %s: %v", test.path, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.downloadReleaseAsset(ctx, server.URL, 4); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled download: %v", err)
	}
}

func TestExtractStackRejectsUnsafeEntries(t *testing.T) {
	for _, header := range []*tar.Header{
		{Name: "../outside", Typeflag: tar.TypeReg, Size: 1},
		{Name: "/absolute", Typeflag: tar.TypeReg, Size: 1},
		{Name: `C:\outside`, Typeflag: tar.TypeReg, Size: 1},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"},
		{Name: "link", Typeflag: tar.TypeLink, Linkname: "../outside"},
		{Name: "device", Typeflag: tar.TypeChar},
		{Name: ".env", Typeflag: tar.TypeReg, Size: 1},
	} {
		t.Run(header.Name, func(t *testing.T) {
			if err := extractStack(stackArchive(t, []*tar.Header{header}), t.TempDir()); err == nil {
				t.Fatal("unsafe archive extracted")
			}
		})
	}
	archive := fixtureStackArchive(t)
	archive[len(archive)-1] ^= 0xff
	if err := extractStack(archive, t.TempDir()); err == nil {
		t.Fatal("corrupt gzip footer accepted")
	}
}

func TestExtractGitDeploymentArchive(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is needed to check the release workflow archive format")
	}
	if _, err := os.Stat(filepath.Join("..", "..", ".git")); errors.Is(err, os.ErrNotExist) {
		t.Skip("release workflow archive check needs a Git checkout")
	}
	command := exec.Command("git", "archive", "--format=tar", "HEAD",
		"docker-compose.yml", "nginx.conf", "opa", "step-ca", ".env.example", ".dockerignore",
		"go.mod", "go.sum", "cmd", "internal", "README.md")
	command.Dir = filepath.Join("..", "..")
	data, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := extractStack(archive.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	if err := validateStackDirectory(dir); err != nil {
		t.Fatal(err)
	}
}

func TestCopyDeploymentEnvironmentPreservesSettings(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(t.TempDir(), "settings.env")
	if err := os.WriteFile(source, []byte("POSTGRESQL_AUTH_PASSWORD=example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := copyDeploymentEnvironment(source, dir); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(source, []byte("different settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyDeploymentEnvironment(source, dir); err == nil {
		t.Fatal("existing configuration overwritten")
	}
	data, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil || string(data) != "POSTGRESQL_AUTH_PASSWORD=example\n" {
		t.Fatalf("configuration=%q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, ".env"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("configuration permissions: info=%v err=%v", info, err)
		}
	}
}

type releaseInstallRunner struct{ recordingRunner }

func (r *releaseInstallRunner) Run(ctx context.Context, dir string, env map[string]string, input io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	if err := r.recordingRunner.Run(ctx, dir, env, input, stdout, stderr, name, args...); err != nil {
		return err
	}
	if len(args) > 1 && args[0] == "volume" && args[1] == "inspect" {
		return errors.New("volume does not exist")
	}
	return nil
}

func TestInstallDownloadedReleaseAndResolveLaterCommands(t *testing.T) {
	setTestStateHome(t)
	t.Chdir(t.TempDir())
	archive := fixtureStackArchive(t)
	server, requests := serveStack(t, archive, fmt.Sprintf("%x", sha256.Sum256(archive)))
	runner := &releaseInstallRunner{}
	a := &app{runner: runner, releaseBaseURL: server.URL, httpClient: server.Client(), stdin: bytes.NewReader(nil), stdout: io.Discard, stderr: io.Discard}
	material := fixtureMaterial(t)
	inputs := t.TempDir()
	for name, data := range map[string][]byte{
		"server.crt": material.ServerCertificate, "server.key": material.ServerKey,
		"ca.crt": material.ClientCA, "settings.env": []byte("POSTGRESQL_AUTH_PASSWORD=example\n"),
	} {
		if err := os.WriteFile(filepath.Join(inputs, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--stack-version", "1.2.3", "--env-file", filepath.Join(inputs, "settings.env"),
		"--pki", "external", "--server-ip", "127.0.0.1", "--server-dns", "server.example",
		"--server-cert", filepath.Join(inputs, "server.crt"), "--server-key", filepath.Join(inputs, "server.key"), "--client-ca", filepath.Join(inputs, "ca.crt")}
	if err := a.install(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	state, err := loadState()
	if err != nil || state == nil || state.ProjectDir != a.projectDir || state.StackVersion != "stack-v1.2.3" {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	if dir, err := resolveProject(); err != nil || dir != a.projectDir {
		t.Fatalf("resolveProject=%q err=%v", dir, err)
	}
	later := &app{runner: runner, stdout: io.Discard, stderr: io.Discard}
	// Retry from another directory without downloading or resupplying .env.
	if err := later.install(context.Background(), args[4:]); err != nil || *requests != 2 {
		t.Fatalf("retry: err=%v requests=%d", err, *requests)
	}
	if err := later.status(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call.dir != state.ProjectDir {
			t.Fatalf("command used %q instead of %q", call.dir, state.ProjectDir)
		}
	}
	if err := (&app{}).prepareInstallProject(context.Background(), installOptions{stackVersion: "1.2.4"}, state); err == nil || !strings.Contains(err.Error(), "different stack release") {
		t.Fatal("stack version change accepted")
	}
}

func TestInstallDownloadedReleaseWithoutConfigurationFile(t *testing.T) {
	setTestStateHome(t)
	archive := fixtureStackArchive(t)
	server, _ := serveStack(t, archive, fmt.Sprintf("%x", sha256.Sum256(archive)))
	a := &app{releaseBaseURL: server.URL, httpClient: server.Client(), stdout: io.Discard, stderr: io.Discard}
	if err := a.prepareInstallProject(context.Background(), installOptions{stackVersion: "1.2.3"}, nil); err != nil {
		t.Fatalf("optional configuration rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(a.projectDir, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected .env file: %v", err)
	}
	state := &deploymentState{ProjectDir: a.projectDir, StackVersion: "stack-v1.2.3"}
	if err := a.prepareInstallProject(context.Background(), installOptions{}, state); err != nil {
		t.Fatalf("retry without configuration rejected: %v", err)
	}
}

func TestInstallProjectDirAndVersionAreMutuallyExclusive(t *testing.T) {
	setTestStateHome(t)
	a := &app{projectDir: t.TempDir(), stdout: io.Discard, stderr: io.Discard}
	err := a.install(context.Background(), []string{"--stack-version", "1.2.3", "--server-ip", "127.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("combined flags: %v", err)
	}
}

func TestStackChecksumRejectsMissingInvalidAndDuplicateEntries(t *testing.T) {
	const asset = "deployment.tar.gz"
	valid := strings.Repeat("a", 64) + "  " + asset + "\n"
	for _, data := range []string{"", strings.Repeat("a", 64) + "  other.tar.gz", "bad  " + asset, valid + valid} {
		if _, err := stackChecksum([]byte(data), asset); err == nil {
			t.Fatalf("invalid checksum accepted: %q", data)
		}
	}
}

func TestInstallVersionValidationDoesNotRequireCheckout(t *testing.T) {
	setTestStateHome(t)
	t.Chdir(t.TempDir())
	var stderr bytes.Buffer
	code := Main([]string{"install", "--stack-version", "../bad", "--server-ip", "127.0.0.1"}, bytes.NewReader(nil), io.Discard, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "--stack-version must") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if code := Main([]string{"--help"}, bytes.NewReader(nil), io.Discard, io.Discard); code != 0 {
		t.Fatalf("help outside checkout: code=%d", code)
	}
}
