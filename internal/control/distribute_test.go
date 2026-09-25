package control

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadCAHostsValidatesAllEntriesBeforeCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	contents := "# scanners\n\nalice@192.0.2.21\nscanner@client.example.com\nalice@192.0.2.21\nscanner@[2001:db8::1]\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, err := readCAHosts(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice@192.0.2.21", "scanner@client.example.com", "scanner@[2001:db8::1]"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	for _, bad := range []string{"-oProxyCommand=evil@host", "user@host:other", "user@host/path", "user@host another", "user@@host", "user@", "user@-host"} {
		if err := os.WriteFile(path, []byte("valid@192.0.2.1\n"+bad+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCAHosts(path); err == nil || !strings.Contains(err.Error(), "line 2") {
			t.Fatalf("host %q was not rejected: %v", bad, err)
		}
	}
}

type failingSCPRunner struct {
	recordingRunner
}

func (r *failingSCPRunner) Run(ctx context.Context, dir string, env map[string]string, input io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	if err := r.recordingRunner.Run(ctx, dir, env, input, stdout, stderr, name, args...); err != nil {
		return err
	}
	if name == "scp" && strings.HasPrefix(args[len(args)-1], "bad@") {
		return errors.New("SSH failed")
	}
	return nil
}

func TestCopyCACertificateContinuesAndReportsFailures(t *testing.T) {
	runner := &failingSCPRunner{}
	var stdout, stderr bytes.Buffer
	a := &app{projectDir: t.TempDir(), runner: runner, stdout: &stdout, stderr: &stderr}
	err := a.copyCACertificate(context.Background(), []string{"bad@192.0.2.1", "good@192.0.2.2"}, []byte("public certificate"), "fingerprint")
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("distribution error = %v", err)
	}
	if len(runner.calls) != 4 || runner.calls[0].name != "ssh" || runner.calls[1].name != "scp" || runner.calls[2].name != "ssh" || runner.calls[3].name != "scp" {
		t.Fatalf("distribution calls = %#v", runner.calls)
	}
	if got := runner.calls[0].args[1]; got != "mkdir -p -m 700 .config/pqnext" {
		t.Fatalf("remote directory command = %q", got)
	}
	if got := runner.calls[3].args[1]; got != "good@192.0.2.2:.config/pqnext/ca.crt" {
		t.Fatalf("destination = %q", got)
	}
	if _, err := os.Stat(runner.calls[1].args[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary CA certificate was not removed: %v", err)
	}
	if !strings.Contains(stdout.String(), "good@192.0.2.2:~/.config/pqnext/ca.crt") || !strings.Contains(stderr.String(), "bad@192.0.2.1") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
