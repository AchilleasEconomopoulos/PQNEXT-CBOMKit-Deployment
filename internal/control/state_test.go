package control

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStateLivesInUserHome(t *testing.T) {
	home := setTestStateHome(t)
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, ".pqnext-cbomkit-state.json"), []byte("old project state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, err := loadState(); err != nil || state != nil {
		t.Fatalf("project-local state was read: state=%#v err=%v", state, err)
	}
	if err := saveState(deploymentState{PKIMode: "managed", ServerIP: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	path, err := statePath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".pqnext", "cbomkit", "state.json"); path != want {
		t.Fatalf("state path = %q, want %q", path, want)
	}
	state, err := loadState()
	if err != nil || state == nil || state.ServerIP != "192.0.2.10" {
		t.Fatalf("home state = %#v, err=%v", state, err)
	}
	if runtime.GOOS != "windows" {
		for _, dir := range []string{filepath.Join(home, ".pqnext"), filepath.Join(home, ".pqnext", "cbomkit")} {
			info, err := os.Stat(dir)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("state directory %s: info=%v err=%v", dir, info, err)
			}
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("state file: info=%v err=%v", info, err)
		}
	}
}
