package control

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"
)

var uninstallVolumes = append([]string{
	"pqnext-cbomkit-app-data",
	"pqnext-cbomkit-postgres-data",
}, managedVolumes...)

func (a *app) uninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var yes bool
	fs.BoolVar(&yes, "yes", false, "skip interactive confirmation for unattended use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected uninstall arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := a.confirmUninstall(yes); err != nil {
		return err
	}

	stateFile, err := statePath()
	if err != nil {
		return err
	}
	stateInfo, err := os.Lstat(stateFile)
	stateStatErr := err
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(a.stderr, "Cannot inspect deployment state: %v; untracked host files will be left in place.\n", err)
	}
	if err == nil && !stateInfo.Mode().IsRegular() {
		return fmt.Errorf("deployment state %s must be a regular file", stateFile)
	}
	var state *deploymentState
	if err == nil {
		state, err = loadState()
		if err != nil {
			fmt.Fprintf(a.stderr, "Cannot read deployment state: %v; untracked host files will be left in place.\n", err)
		}
	}

	var recoveryPath string
	var recoveryInfo os.FileInfo
	if state != nil && state.RecoveryArchive != "" {
		if state.RootFingerprint == "" {
			fmt.Fprintf(a.stderr, "Recovery archive %s cannot be verified without a root fingerprint; leaving it in place.\n", state.RecoveryArchive)
		} else {
			recoveryPath, recoveryInfo, err = inspectRecoveryForUninstall(state.RecoveryArchive, state.RootFingerprint)
			if err != nil {
				return err
			}
		}
	}
	if err := a.checkDocker(ctx); err != nil {
		return err
	}
	serverIP, serverDNS := "127.0.0.1", ""
	if state != nil {
		if state.ServerIP != "" {
			serverIP = state.ServerIP
		}
		serverDNS = state.ServerDNS
		a.bootstrapVolume = state.BootstrapVolume
	}
	if err := a.compose(ctx, serverIP, serverDNS, nil,
		"--profile", "managed-pki", "--profile", "pki-tools", "down", "--volumes", "--remove-orphans"); err != nil {
		return fmt.Errorf("stopping and removing deployment: %w", err)
	}
	if err := a.removeUninstallVolumes(ctx, state); err != nil {
		return err
	}
	if recoveryInfo != nil {
		_, current, err := inspectRecoveryForUninstall(recoveryPath, state.RootFingerprint)
		if err != nil {
			return err
		}
		if current != nil && !os.SameFile(recoveryInfo, current) {
			return fmt.Errorf("recovery archive %s changed during uninstall", recoveryPath)
		}
		if current != nil {
			if err := os.Remove(recoveryPath); err != nil {
				return fmt.Errorf("removing recovery archive: %w", err)
			}
		}
	}
	if stateInfo != nil {
		current, err := os.Lstat(stateFile)
		if err == nil && (!current.Mode().IsRegular() || !os.SameFile(stateInfo, current)) {
			return errors.New("deployment state changed during uninstall")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking deployment state before removal: %w", err)
		}
		if err == nil {
			if err := os.Remove(stateFile); err != nil {
				return fmt.Errorf("removing deployment state: %w", err)
			}
		}
	}
	removeEmptyStateDir(filepath.Dir(stateFile))
	if state == nil {
		fmt.Fprintln(a.stderr, "No readable deployment state was found; custom recovery archives and other untracked host files require manual cleanup.")
	}
	if stateStatErr != nil && !errors.Is(stateStatErr, os.ErrNotExist) {
		return fmt.Errorf("Docker resources were removed, but deployment state %s could not be inspected and may remain: %w", stateFile, stateStatErr)
	}
	fmt.Fprintln(a.stdout, "PQNEXT-CBOMKit deployment uninstalled.")
	return nil
}

func (a *app) confirmUninstall(yes bool) error {
	if yes {
		return nil
	}
	input, ok := a.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return errors.New("interactive confirmation requires a terminal; pass --yes for unattended use")
	}
	return readUninstallConfirmation(input, a.stderr)
}

func readUninstallConfirmation(input io.Reader, prompt io.Writer) error {
	fmt.Fprint(prompt, "This will delete the deployment, database, PKI, and recorded recovery archive. Type uninstall to continue: ")
	var answer []byte
	var one [1]byte
	for len(answer) < 64 {
		n, err := input.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				if string(bytes.TrimSpace(answer)) == "uninstall" {
					return nil
				}
				return errors.New("uninstall cancelled")
			}
			answer = append(answer, one[0])
		}
		if err != nil {
			return fmt.Errorf("reading uninstall confirmation: %w", err)
		}
		if n == 0 {
			return errors.New("reading uninstall confirmation: no input")
		}
	}
	return errors.New("uninstall confirmation is too long")
}

func inspectRecoveryForUninstall(path, fingerprint string) (string, os.FileInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolving recovery archive: %w", err)
	}
	info, err := os.Lstat(absPath)
	if errors.Is(err, os.ErrNotExist) {
		return absPath, nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("checking recovery archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxPKIArchive {
		return "", nil, fmt.Errorf("recovery archive %s must be a regular file of at most %d bytes", absPath, maxPKIArchive)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return "", nil, fmt.Errorf("opening recovery archive: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return "", nil, fmt.Errorf("recovery archive %s changed while opening it", absPath)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPKIArchive+1))
	if err != nil {
		return "", nil, fmt.Errorf("reading recovery archive: %w", err)
	}
	if len(data) > maxPKIArchive {
		return "", nil, errors.New("recovery archive is too large")
	}
	manifest, err := validateRecoveryArchive(data)
	if err != nil {
		return "", nil, fmt.Errorf("validating recovery archive before uninstall: %w", err)
	}
	if !strings.EqualFold(manifest.Fingerprint, fingerprint) {
		return "", nil, fmt.Errorf("recovery archive %s does not match deployment state fingerprint", absPath)
	}
	return absPath, info, nil
}

func (a *app) removeUninstallVolumes(ctx context.Context, state *deploymentState) error {
	available, err := a.listDockerVolumes(ctx)
	if err != nil {
		return err
	}
	bootstrap, err := a.listDockerVolumes(ctx, "label=com.pqnext.cbomkit.bootstrap=true")
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(available))
	for _, name := range available {
		known[name] = true
	}
	selected := append([]string{}, uninstallVolumes...)
	ownedBootstrap := make(map[string]bool, len(bootstrap))
	for _, name := range bootstrap {
		if bootstrapVolumePattern.MatchString(name) {
			selected = append(selected, name)
			ownedBootstrap[name] = true
		}
	}
	if state != nil && state.BootstrapVolume != "" && known[state.BootstrapVolume] && !ownedBootstrap[state.BootstrapVolume] {
		fmt.Fprintf(a.stderr, "Bootstrap volume %s lacks the ownership label; leaving it in place for manual review.\n", state.BootstrapVolume)
	}
	seen := make(map[string]bool)
	for _, name := range selected {
		if !known[name] || seen[name] {
			continue
		}
		seen[name] = true
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "docker", "volume", "rm", name); err != nil {
			return fmt.Errorf("removing deployment volume %s: %w", name, err)
		}
	}
	return nil
}

func (a *app) listDockerVolumes(ctx context.Context, filter ...string) ([]string, error) {
	args := []string{"volume", "ls", "--format", "{{.Name}}"}
	for _, value := range filter {
		args = append(args, "--filter", value)
	}
	var output bytes.Buffer
	if err := a.runner.Run(ctx, a.projectDir, nil, nil, &output, a.stderr, "docker", args...); err != nil {
		return nil, fmt.Errorf("listing Docker volumes: %w", err)
	}
	var names []string
	for _, line := range strings.Split(output.String(), "\n") {
		if name := strings.TrimSpace(line); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func removeEmptyStateDir(dir string) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) == 0 {
		_ = os.Remove(dir)
	}
}
