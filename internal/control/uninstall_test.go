package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type uninstallRunner struct {
	calls          []runnerCall
	volumes        map[string]bool
	bootstrap      map[string]bool
	failDown       bool
	failVolumeName string
}

func (r *uninstallRunner) Run(_ context.Context, dir string, env map[string]string, _ io.Reader, output, _ io.Writer, name string, args ...string) error {
	r.calls = append(r.calls, runnerCall{dir: dir, env: env, name: name, args: append([]string{}, args...)})
	if name != "docker" {
		return errors.New("unexpected command")
	}
	if len(args) > 0 && args[0] == "compose" {
		if r.failDown && containsArg(args, "down") {
			return errors.New("compose down failed")
		}
		return nil
	}
	if len(args) < 2 || args[0] != "volume" {
		return errors.New("unexpected Docker arguments")
	}
	switch args[1] {
	case "ls":
		var names []string
		filterBootstrap := containsArg(args, "label=com.pqnext.cbomkit.bootstrap=true")
		for volume := range r.volumes {
			if !filterBootstrap || r.bootstrap[volume] {
				names = append(names, volume)
			}
		}
		sort.Strings(names)
		if len(names) != 0 {
			_, _ = io.WriteString(output, strings.Join(names, "\n")+"\n")
		}
	case "rm":
		if len(args) != 3 || args[2] == r.failVolumeName {
			return errors.New("volume removal failed")
		}
		delete(r.volumes, args[2])
	default:
		return errors.New("unexpected volume operation")
	}
	return nil
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func newUninstallApp(t *testing.T, runner *uninstallRunner) *app {
	t.Helper()
	return &app{projectDir: t.TempDir(), runner: runner, stdin: bytes.NewReader(nil), stdout: io.Discard, stderr: io.Discard}
}

func TestUninstallManagedRemovesDeploymentAndRecordedRecovery(t *testing.T) {
	setTestStateHome(t)
	archive := makeRecoveryArchive(t)
	manifest, err := validateRecoveryArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "recovery.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap := "pqnext-cbomkit-ca-root-bootstrap-0123456789abcdef"
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", RootFingerprint: manifest.Fingerprint, RecoveryArchive: archivePath, BootstrapVolume: bootstrap}); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallRunner{volumes: map[string]bool{bootstrap: true, "pqnext-cbomkit-app-data": true, "pqnext-cbomkit-postgres-data": true, "pqnext-cbomkit-ca-data": true, "pqnext-cbomkit-nginx-pki": true, "unrelated-data": true}, bootstrap: map[string]bool{bootstrap: true}}
	a := newUninstallApp(t, runner)
	if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.volumes, map[string]bool{"unrelated-data": true}) {
		t.Fatalf("remaining volumes = %#v", runner.volumes)
	}
	path, err := statePath()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, archivePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file %s was not removed: %v", path, err)
		}
	}
	var down runnerCall
	for _, call := range runner.calls {
		if containsArg(call.args, "down") {
			down = call
			break
		}
	}
	if !reflect.DeepEqual(down.args, []string{"compose", "--project-name", composeProject, "--file", composeFile, "--profile", "managed-pki", "--profile", "pki-tools", "down", "--volumes", "--remove-orphans"}) || down.env["SERVER_IP"] != "192.0.2.10" {
		t.Fatalf("unexpected Compose teardown: %#v", down)
	}
}

func TestUninstallExternalAndPartialInstall(t *testing.T) {
	for _, test := range []struct {
		name  string
		state *deploymentState
	}{
		{"external", &deploymentState{PKIMode: "external", ServerIP: "192.0.2.20"}},
		{"partial without state", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			setTestStateHome(t)
			if test.state != nil {
				if err := saveState(*test.state); err != nil {
					t.Fatal(err)
				}
			}
			bootstrap := "pqnext-cbomkit-ca-root-bootstrap-0123456789abcdef"
			runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-app-data": true, "pqnext-cbomkit-nginx-pki": true, bootstrap: true}, bootstrap: map[string]bool{bootstrap: true}}
			a := newUninstallApp(t, runner)
			if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
				t.Fatal(err)
			}
			if len(runner.volumes) != 0 {
				t.Fatalf("volumes left behind: %#v", runner.volumes)
			}
			wantIP := "127.0.0.1"
			if test.state != nil {
				wantIP = test.state.ServerIP
			}
			if runner.calls[1].env["SERVER_IP"] != wantIP {
				t.Fatalf("Compose server IP = %q, want %q", runner.calls[1].env["SERVER_IP"], wantIP)
			}
			if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
				t.Fatalf("repeated uninstall: %v", err)
			}
		})
	}
}

func TestUninstallEmptyStackAndMissingArchive(t *testing.T) {
	for _, test := range []struct {
		name  string
		state bool
	}{
		{"empty stack", false},
		{"missing archive", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setTestStateHome(t)
			if test.state {
				if err := saveState(deploymentState{PKIMode: "managed", RecoveryArchive: filepath.Join(t.TempDir(), "missing.tar.gz"), RootFingerprint: strings.Repeat("a", 64)}); err != nil {
					t.Fatal(err)
				}
			}
			runner := &uninstallRunner{volumes: map[string]bool{}}
			a := newUninstallApp(t, runner)
			if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
				t.Fatal(err)
			}
			if len(runner.volumes) != 0 {
				t.Fatalf("remaining volumes: %#v", runner.volumes)
			}
			if runner.calls[1].env["SERVER_IP"] != "127.0.0.1" {
				t.Fatalf("Compose server IP = %q", runner.calls[1].env["SERVER_IP"])
			}
			stateFile, err := statePath()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(stateFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("state remains after uninstall: %v", err)
			}
		})
	}
}

func TestUninstallRequiresBootstrapOwnershipLabel(t *testing.T) {
	setTestStateHome(t)
	bootstrap := "pqnext-cbomkit-ca-root-bootstrap-0123456789abcdef"
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", BootstrapVolume: bootstrap}); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallRunner{volumes: map[string]bool{bootstrap: true}}
	a := newUninstallApp(t, runner)
	if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
		t.Fatal(err)
	}
	if !runner.volumes[bootstrap] {
		t.Fatal("bootstrap volume without ownership label was removed")
	}
}

func TestUninstallRequiresConfirmationBeforeDocker(t *testing.T) {
	setTestStateHome(t)
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-ca-data": true}}
	a := newUninstallApp(t, runner)
	if err := a.uninstall(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("missing confirmation error = %v", err)
	}
	if len(runner.calls) != 0 || !runner.volumes["pqnext-cbomkit-ca-data"] {
		t.Fatal("uninstall touched Docker before confirmation")
	}
	var prompt bytes.Buffer
	if err := readUninstallConfirmation(strings.NewReader("uninstall\n"), &prompt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prompt.String(), "database") {
		t.Fatalf("prompt = %q", prompt.String())
	}
	if err := readUninstallConfirmation(strings.NewReader("no\n"), io.Discard); err == nil {
		t.Fatal("wrong confirmation was accepted")
	}
}

func TestUninstallCleansKnownVolumesWithUnreadableState(t *testing.T) {
	setTestStateHome(t)
	stateFile, err := statePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap := "pqnext-cbomkit-ca-root-bootstrap-0123456789abcdef"
	unlabeled := "pqnext-cbomkit-ca-root-bootstrap-fedcba9876543210"
	runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-ca-data": true, bootstrap: true, unlabeled: true}, bootstrap: map[string]bool{bootstrap: true}}
	var stderr bytes.Buffer
	a := newUninstallApp(t, runner)
	a.stderr = &stderr
	if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.volumes, map[string]bool{unlabeled: true}) {
		t.Fatalf("remaining volumes = %#v", runner.volumes)
	}
	if _, err := os.Stat(stateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreadable state was not removed: %v", err)
	}
	if !strings.Contains(stderr.String(), "untracked host files") {
		t.Fatalf("missing partial-cleanup warning: %q", stderr.String())
	}
}

func TestUninstallRejectsMismatchedRecoveryBeforeDocker(t *testing.T) {
	setTestStateHome(t)
	archive := makeRecoveryArchive(t)
	archivePath := filepath.Join(t.TempDir(), "recovery.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", RootFingerprint: strings.Repeat("a", 64), RecoveryArchive: archivePath}); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-ca-data": true}}
	a := newUninstallApp(t, runner)
	if err := a.uninstall(context.Background(), []string{"--yes"}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched archive error = %v", err)
	}
	if len(runner.calls) != 0 || !runner.volumes["pqnext-cbomkit-ca-data"] {
		t.Fatal("Docker was touched despite invalid archive")
	}
}

func TestUninstallRejectsNonRegularRecoveryBeforeDocker(t *testing.T) {
	setTestStateHome(t)
	archivePath := t.TempDir()
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", RootFingerprint: strings.Repeat("a", 64), RecoveryArchive: archivePath}); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-ca-data": true}}
	a := newUninstallApp(t, runner)
	if err := a.uninstall(context.Background(), []string{"--yes"}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("non-regular archive error = %v", err)
	}
	if len(runner.calls) != 0 || !runner.volumes["pqnext-cbomkit-ca-data"] {
		t.Fatal("Docker was touched despite non-regular archive")
	}
}

func TestUninstallDockerFailurePreservesStateAndArchive(t *testing.T) {
	for _, fail := range []string{"down", "volume"} {
		t.Run(fail, func(t *testing.T) {
			setTestStateHome(t)
			archive := makeRecoveryArchive(t)
			manifest, err := validateRecoveryArchive(archive)
			if err != nil {
				t.Fatal(err)
			}
			archivePath := filepath.Join(t.TempDir(), "recovery.tar.gz")
			if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", RootFingerprint: manifest.Fingerprint, RecoveryArchive: archivePath}); err != nil {
				t.Fatal(err)
			}
			runner := &uninstallRunner{volumes: map[string]bool{"pqnext-cbomkit-ca-data": true}, failDown: fail == "down"}
			if fail == "volume" {
				runner.failVolumeName = "pqnext-cbomkit-ca-data"
			}
			a := newUninstallApp(t, runner)
			if err := a.uninstall(context.Background(), []string{"--yes"}); err == nil {
				t.Fatal("Docker failure was ignored")
			}
			path, err := statePath()
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{path, archivePath} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("file %s lost after Docker failure: %v", path, err)
				}
			}
		})
	}
}

func TestSaveRecoveryArchiveReturnsAbsolutePath(t *testing.T) {
	archive := makeRecoveryArchive(t)
	manifest, err := validateRecoveryArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	relative, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Fatal(err)
	}
	path, err := saveRecoveryArchive(relative, manifest.Fingerprint, archive)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("recovery path is relative: %q", path)
	}
	relativeArchive, err := filepath.Rel(wd, path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, info, err := inspectRecoveryForUninstall(relativeArchive, manifest.Fingerprint)
	if err != nil || info == nil || resolved != path {
		t.Fatalf("relative archive resolved to %q, info=%v, err=%v", resolved, info, err)
	}
	setTestStateHome(t)
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10", RootFingerprint: manifest.Fingerprint, RecoveryArchive: relativeArchive}); err != nil {
		t.Fatal(err)
	}
	a := newUninstallApp(t, &uninstallRunner{volumes: map[string]bool{}})
	if err := a.uninstall(context.Background(), []string{"--yes"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("relative recovery archive remains: %v", err)
	}
}
