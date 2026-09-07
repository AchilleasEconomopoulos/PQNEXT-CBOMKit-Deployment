package control

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type runnerCall struct {
	dir   string
	env   map[string]string
	name  string
	args  []string
	input []byte
}

type recordingRunner struct {
	calls []runnerCall
}

func (r *recordingRunner) Run(_ context.Context, dir string, env map[string]string, input io.Reader, _, _ io.Writer, name string, args ...string) error {
	var inputBytes []byte
	if input != nil {
		inputBytes, _ = io.ReadAll(input)
	}
	r.calls = append(r.calls, runnerCall{dir: dir, env: env, name: name, args: append([]string{}, args...), input: inputBytes})
	return nil
}

func TestSecretIsOnlySentOnStandardInput(t *testing.T) {
	const secret = "this-must-never-be-an-argument"
	runner := &recordingRunner{}
	a := &app{projectDir: "/deployment", runner: runner, stdout: io.Discard, stderr: io.Discard}
	if err := a.composeInput(context.Background(), "192.0.2.4", "", strings.NewReader(secret), "--profile", "pki-tools", "run", "ca-init"); err != nil {
		t.Fatal(err)
	}
	call := runner.calls[0]
	if string(call.input) != secret {
		t.Fatal("secret was not passed intact on stdin")
	}
	for _, arg := range call.args {
		if strings.Contains(arg, secret) {
			t.Fatal("secret appeared in process arguments")
		}
	}
	for _, value := range call.env {
		if strings.Contains(value, secret) {
			t.Fatal("secret appeared in process environment")
		}
	}
}

func TestBootstrapVolumeNamesAreUniqueAndConstrained(t *testing.T) {
	first, err := newBootstrapVolumeName()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newBootstrapVolumeName()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !bootstrapVolumePattern.MatchString(first) || !bootstrapVolumePattern.MatchString(second) {
		t.Fatalf("invalid bootstrap volume names %q and %q", first, second)
	}
}

func TestRootPasswordFileMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("long-enough-passphrase"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &app{stdin: bytes.NewReader(nil)}
	if _, err := a.readRootPassword(path); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("insecure password file error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	password, err := a.readRootPassword(path)
	if err != nil {
		t.Fatal(err)
	}
	zeroBytes(password)
}

func TestComposeInvocationUsesArgumentArrayAndExplicitProject(t *testing.T) {
	runner := &recordingRunner{}
	a := &app{projectDir: "/deployment", runner: runner, stdout: io.Discard, stderr: io.Discard}
	if err := a.compose(context.Background(), "192.0.2.4", "host.example", nil, "up", "-d"); err != nil {
		t.Fatal(err)
	}
	want := []string{"compose", "--project-name", "pqnext-cbomkit", "--file", "docker-compose.yml", "up", "-d"}
	if len(runner.calls) != 1 || runner.calls[0].name != "docker" || !reflect.DeepEqual(runner.calls[0].args, want) {
		t.Fatalf("call = %#v, want args %#v", runner.calls, want)
	}
	if runner.calls[0].env["SERVER_IP"] != "192.0.2.4" || runner.calls[0].env["SERVER_DNS_NAME"] != "host.example" {
		t.Fatalf("environment = %#v", runner.calls[0].env)
	}
}

func TestInstallOptionValidation(t *testing.T) {
	validManaged := installOptions{mode: "managed", serverIP: "192.0.2.2"}
	if err := validateInstallOptions(validManaged); err != nil {
		t.Fatal(err)
	}
	validExternal := installOptions{mode: "external", serverIP: "192.0.2.2", serverCert: "cert", serverKey: "key", clientCA: "ca"}
	if err := validateInstallOptions(validExternal); err != nil {
		t.Fatal(err)
	}
	for _, options := range []installOptions{
		{mode: "wrong", serverIP: "192.0.2.2"},
		{mode: "managed", serverIP: "not-an-ip"},
		{mode: "external", serverIP: "192.0.2.2", serverCert: "cert"},
		{mode: "managed", serverIP: "192.0.2.2", serverKey: "key"},
	} {
		if err := validateInstallOptions(options); err == nil {
			t.Fatalf("options %#v unexpectedly accepted", options)
		}
	}
}

func TestDefaultRecoveryDirectories(t *testing.T) {
	tests := []struct {
		goos string
		env  map[string]string
		home string
		want []string
	}{
		{"linux", map[string]string{"XDG_DATA_HOME": "/data"}, "/home/user", []string{"data", "pqnext-cbomkit", "recovery"}},
		{"linux", nil, "/home/user", []string{".local", "share", "pqnext-cbomkit", "recovery"}},
		{"darwin", nil, "/Users/user", []string{"Library", "Application Support", "pqnext-cbomkit", "recovery"}},
		{"windows", map[string]string{"LOCALAPPDATA": `C:\\Users\\user\\AppData\\Local`}, `C:\\Users\\user`, []string{"AppData", "Local", "pqnext-cbomkit", "recovery"}},
	}
	for _, test := range tests {
		got := defaultRecoveryDir(test.goos, test.env, test.home)
		for _, part := range test.want {
			if !strings.Contains(got, part) {
				t.Fatalf("defaultRecoveryDir(%q) = %q, missing %q", test.goos, got, part)
			}
		}
	}
}

func TestStateRejectsPKIModeChange(t *testing.T) {
	dir := t.TempDir()
	state := deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10"}
	if err := saveState(dir, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PKIMode != "managed" {
		t.Fatalf("mode = %q", loaded.PKIMode)
	}
	info, err := osStat(statePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info != 0o600 {
		t.Fatalf("state mode = %o", info)
	}
}

func osStat(path string) (uint32, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	return uint32(info.Mode().Perm()), nil
}

func TestInternalCommandDoesNotRequireComposeFile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"internal-validate-pki", "--dir", t.TempDir(), "--server-ip", "127.0.0.1"}, bytes.NewReader(nil), &stdout, &stderr)
	if code == 0 || strings.Contains(stderr.String(), "cannot locate docker-compose.yml") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}
