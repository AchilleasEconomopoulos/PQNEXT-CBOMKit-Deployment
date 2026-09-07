package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	composeProject = "pqnext-cbomkit"
	composeFile    = "docker-compose.yml"
)

var managedVolumes = []string{
	"pqnext-cbomkit-ca-data",
	"pqnext-cbomkit-ca-password",
	"pqnext-cbomkit-ca-admin-password",
	"pqnext-cbomkit-ca-client-password",
	"pqnext-cbomkit-ca-server-password",
	"pqnext-cbomkit-ca-public",
	"pqnext-cbomkit-nginx-pki",
}

type app struct {
	projectDir      string
	runner          commandRunner
	stdin           io.Reader
	stdout          io.Writer
	stderr          io.Writer
	bootstrapVolume string
}

// Main is the command-line entry point. It returns a process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	projectDir, remaining, err := parseGlobalArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	internalCommand := len(remaining) > 0 && strings.HasPrefix(remaining[0], "internal-")
	if projectDir == "" && internalCommand {
		projectDir = "."
	}
	if projectDir == "" {
		projectDir, err = locateProject()
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}
	projectDir, err = filepath.Abs(projectDir)
	if err != nil {
		fmt.Fprintln(stderr, "error: resolving project directory:", err)
		return 1
	}

	a := &app{projectDir: projectDir, runner: execRunner{}, stdin: stdin, stdout: stdout, stderr: stderr}
	if err := a.run(context.Background(), remaining); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func parseGlobalArgs(args []string) (string, []string, error) {
	var projectDir string
	for len(args) > 0 {
		switch args[0] {
		case "--project-dir":
			if len(args) < 2 || args[1] == "" {
				return "", nil, errors.New("--project-dir requires a path")
			}
			projectDir, args = args[1], args[2:]
		case "--help", "-h":
			return projectDir, []string{"help"}, nil
		default:
			return projectDir, args, nil
		}
	}
	return projectDir, args, nil
}

func locateProject() (string, error) {
	if wd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(wd, composeFile)); err == nil {
			return wd, nil
		}
	}
	executable, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(executable)
		if _, err := os.Stat(filepath.Join(dir, composeFile)); err == nil {
			return dir, nil
		}
	}
	return "", errors.New("cannot locate docker-compose.yml; run from the deployment directory or pass --project-dir")
}

func (a *app) run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" {
		printUsage(a.stdout)
		return nil
	}
	switch args[0] {
	case "install":
		return a.install(ctx, args[1:])
	case "up":
		return a.up(ctx, args[1:])
	case "down":
		return a.down(ctx, args[1:])
	case "status":
		return a.status(ctx, args[1:])
	case "pki":
		if len(args) < 2 {
			return errors.New("usage: pqnext-cbomkitctl pki import ... | pki export-ca --output PATH")
		}
		switch args[1] {
		case "import":
			return a.importExternal(ctx, args[2:])
		case "export-ca":
			return a.exportCA(ctx, args[2:])
		default:
			return fmt.Errorf("unknown pki command %q", args[1])
		}
	case "client-token":
		return a.clientToken(ctx, args[1:])
	case "internal-import-pki":
		return internalImportPKI(args[1:], a.stdin)
	case "internal-install-pki":
		return internalInstallPKI(args[1:])
	case "internal-validate-pki":
		return internalValidatePKI(args[1:])
	case "internal-validate-recovery":
		return internalValidateRecovery(args[1:], a.stdin, a.stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  pqnext-cbomkitctl [--project-dir PATH] install --pki managed --server-ip ADDRESS [options]
  pqnext-cbomkitctl [--project-dir PATH] install --pki external --server-ip ADDRESS --server-cert PATH --server-key PATH --client-ca PATH
  pqnext-cbomkitctl [--project-dir PATH] up|down|status
  pqnext-cbomkitctl [--project-dir PATH] pki import --server-cert PATH --server-key PATH --client-ca PATH
  pqnext-cbomkitctl [--project-dir PATH] pki export-ca --output PATH
  pqnext-cbomkitctl [--project-dir PATH] client-token --name NAME [--output PATH]`)
}

type installOptions struct {
	mode             string
	serverIP         string
	serverDNS        string
	recoveryDir      string
	rootPasswordFile string
	serverCert       string
	serverKey        string
	clientCA         string
}

func (a *app) install(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var options installOptions
	fs.StringVar(&options.mode, "pki", "managed", "PKI mode: managed or external")
	fs.StringVar(&options.serverIP, "server-ip", "", "server IP address")
	fs.StringVar(&options.serverDNS, "server-dns", "", "optional server DNS name")
	fs.StringVar(&options.recoveryDir, "recovery-dir", "", "managed root recovery directory")
	fs.StringVar(&options.rootPasswordFile, "root-password-file", "", "file containing managed root recovery passphrase")
	fs.StringVar(&options.serverCert, "server-cert", "", "external server certificate chain")
	fs.StringVar(&options.serverKey, "server-key", "", "external unencrypted server private key")
	fs.StringVar(&options.clientCA, "client-ca", "", "external client CA trust bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected install arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateInstallOptions(options); err != nil {
		return err
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state != nil && state.PKIMode != options.mode {
		return fmt.Errorf("deployment is already configured for %s PKI; migration to %s is not supported", state.PKIMode, options.mode)
	}
	if state != nil && (state.ServerIP != options.serverIP || state.ServerDNS != options.serverDNS) {
		return errors.New("server identity differs from the recorded deployment state; certificate identity migration is not implemented")
	}
	newState := state == nil
	if state == nil {
		if err := refuseLegacyPKI(a.projectDir); err != nil {
			return err
		}
		state = &deploymentState{Version: stateVersion, PKIMode: options.mode, ServerIP: options.serverIP, ServerDNS: options.serverDNS}
		if options.mode == "managed" {
			state.BootstrapVolume, err = newBootstrapVolumeName()
			if err != nil {
				return err
			}
		}
	}
	a.bootstrapVolume = state.BootstrapVolume
	if err := a.checkDocker(ctx); err != nil {
		return err
	}
	if options.mode == "external" {
		material, err := loadPKIMaterial(options.serverCert, options.serverKey, options.clientCA)
		if err != nil {
			return err
		}
		if err := validatePKI(material, options.serverIP, options.serverDNS, time.Now()); err != nil {
			return fmt.Errorf("external PKI validation failed: %w", err)
		}
		if newState {
			if err := a.refuseExistingDeploymentVolumes(ctx, []string{"pqnext-cbomkit-nginx-pki"}); err != nil {
				return err
			}
			if err := saveState(a.projectDir, *state); err != nil {
				return err
			}
		}
		if err := a.ensureVolumes(ctx, []string{"pqnext-cbomkit-nginx-pki"}); err != nil {
			return err
		}
		if err := a.buildTools(ctx, options.serverIP, options.serverDNS); err != nil {
			return err
		}
		if err := a.runImporter(ctx, material, options.serverIP, options.serverDNS); err != nil {
			return err
		}
		if err := a.compose(ctx, options.serverIP, options.serverDNS, nil, "up", "-d", "--wait"); err != nil {
			return err
		}
		if err := a.reloadNginxIfRunning(ctx, options.serverIP, options.serverDNS); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "PQNEXT-CBOMKit is running with externally managed PKI.")
		return nil
	}

	if newState {
		if err := a.refuseExistingDeploymentVolumes(ctx, managedVolumes); err != nil {
			return err
		}
		if err := saveState(a.projectDir, *state); err != nil {
			return err
		}
	}
	if err := a.ensureVolumes(ctx, managedVolumes); err != nil {
		return err
	}
	if err := a.buildTools(ctx, options.serverIP, options.serverDNS); err != nil {
		return err
	}
	if state.RootFingerprint == "" {
		password, err := a.readRootPassword(options.rootPasswordFile)
		if err != nil {
			return err
		}
		defer zeroBytes(password)
		if options.recoveryDir == "" {
			options.recoveryDir, err = currentDefaultRecoveryDir()
			if err != nil {
				return err
			}
		}
		if err := a.ensureBootstrapVolume(ctx); err != nil {
			return err
		}
		if err := a.composeInput(ctx, options.serverIP, options.serverDNS, bytes.NewReader(password), "--profile", "pki-tools", "run", "--rm", "-T", "ca-init"); err != nil {
			return fmt.Errorf("initializing managed CA: %w", err)
		}
		recovery, err := a.exportRecovery(ctx, options.serverIP, options.serverDNS)
		if err != nil {
			return err
		}
		manifest, err := validateRecoveryArchive(recovery)
		if err != nil {
			return fmt.Errorf("validating exported root recovery archive: %w", err)
		}
		archivePath, err := saveRecoveryArchive(options.recoveryDir, manifest.Fingerprint, recovery)
		if err != nil {
			return err
		}
		state.RootFingerprint = manifest.Fingerprint
		state.RecoveryArchive = archivePath
		if err := saveState(a.projectDir, *state); err != nil {
			return err
		}
	}
	if err := a.compose(ctx, options.serverIP, options.serverDNS, nil, "--profile", "pki-tools", "run", "--rm", "-T", "ca-finalize"); err != nil {
		return fmt.Errorf("finalizing managed CA: %w", err)
	}
	if err := a.removeBootstrapVolume(ctx); err != nil {
		return err
	}
	if err := a.compose(ctx, options.serverIP, options.serverDNS, nil, "--profile", "managed-pki", "up", "-d", "--wait", "step-ca"); err != nil {
		return fmt.Errorf("starting managed CA: %w", err)
	}
	for _, job := range []string{"ca-configure", "nginx-cert-init"} {
		if err := a.compose(ctx, options.serverIP, options.serverDNS, nil, "--profile", "pki-tools", "run", "--rm", "-T", job); err != nil {
			return fmt.Errorf("running %s: %w", job, err)
		}
	}
	if err := a.compose(ctx, options.serverIP, options.serverDNS, nil, "--profile", "managed-pki", "up", "-d", "--wait"); err != nil {
		return err
	}
	if err := a.reloadNginxIfRunning(ctx, options.serverIP, options.serverDNS); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "PQNEXT-CBOMKit is running with managed PKI.\nRoot fingerprint: %s\nRecovery archive: %s\n", state.RootFingerprint, state.RecoveryArchive)
	return nil
}

func (a *app) refuseExistingDeploymentVolumes(ctx context.Context, names []string) error {
	for _, name := range names {
		var discard bytes.Buffer
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, &discard, &discard, "docker", "volume", "inspect", name); err == nil {
			return fmt.Errorf("Docker volume %s already exists but no deployment state was found; automatic adoption is refused", name)
		}
	}
	return nil
}

func validateInstallOptions(options installOptions) error {
	if options.mode != "managed" && options.mode != "external" {
		return errors.New("--pki must be managed or external")
	}
	if net.ParseIP(options.serverIP) == nil {
		return errors.New("--server-ip must be a valid IP address")
	}
	if strings.ContainsAny(options.serverDNS, "\x00/\\") {
		return errors.New("--server-dns is invalid")
	}
	if options.mode == "managed" {
		if options.serverCert != "" || options.serverKey != "" || options.clientCA != "" {
			return errors.New("external certificate flags cannot be used with managed PKI")
		}
		return nil
	}
	if options.serverCert == "" || options.serverKey == "" || options.clientCA == "" {
		return errors.New("external PKI requires --server-cert, --server-key, and --client-ca")
	}
	if options.recoveryDir != "" || options.rootPasswordFile != "" {
		return errors.New("managed recovery flags cannot be used with external PKI")
	}
	return nil
}

func refuseLegacyPKI(projectDir string) error {
	for _, name := range []string{"server.crt", "server.key", "ca.crt"} {
		path := filepath.Join(projectDir, "pki", name)
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return fmt.Errorf("legacy bind-mounted PKI file %s exists; fresh-install migration is intentionally refused", path)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking legacy PKI: %w", err)
		}
	}
	return nil
}

func (a *app) checkDocker(ctx context.Context) error {
	var output bytes.Buffer
	if err := a.runner.Run(ctx, a.projectDir, nil, nil, &output, a.stderr, "docker", "compose", "version"); err != nil {
		return errors.New("Docker Compose v2 is required")
	}
	return nil
}

func (a *app) ensureVolumes(ctx context.Context, names []string) error {
	for _, name := range names {
		var discard bytes.Buffer
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, &discard, &discard, "docker", "volume", "inspect", name); err == nil {
			continue
		}
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "docker", "volume", "create", "--label", "com.pqnext.cbomkit.managed=true", name); err != nil {
			return fmt.Errorf("creating Docker volume %s: %w", name, err)
		}
	}
	return nil
}

func (a *app) ensureBootstrapVolume(ctx context.Context) error {
	name := a.bootstrapVolume
	if !bootstrapVolumePattern.MatchString(name) {
		return errors.New("managed installation has no valid bootstrap volume name")
	}
	var discard bytes.Buffer
	if err := a.runner.Run(ctx, a.projectDir, nil, nil, &discard, &discard, "docker", "volume", "inspect", name); err == nil {
		return nil
	}
	return a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "docker", "volume", "create",
		"--label", "com.pqnext.cbomkit.managed=true", "--label", "com.pqnext.cbomkit.bootstrap=true", name)
}

func (a *app) removeBootstrapVolume(ctx context.Context) error {
	name := a.bootstrapVolume
	if !bootstrapVolumePattern.MatchString(name) {
		return errors.New("managed installation has no valid bootstrap volume name")
	}
	var discard bytes.Buffer
	if err := a.runner.Run(ctx, a.projectDir, nil, nil, &discard, &discard, "docker", "volume", "inspect", name); err != nil {
		return nil
	}
	if err := a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "docker", "volume", "rm", name); err != nil {
		return fmt.Errorf("removing exported root bootstrap volume: %w", err)
	}
	return nil
}

var bootstrapVolumePattern = regexp.MustCompile(`^pqnext-cbomkit-ca-root-bootstrap-[0-9a-f]{16}$`)

func newBootstrapVolumeName() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generating bootstrap volume name: %w", err)
	}
	return "pqnext-cbomkit-ca-root-bootstrap-" + hex.EncodeToString(random), nil
}

func (a *app) composeEnvironment(serverIP, serverDNS string) map[string]string {
	bootstrap := a.bootstrapVolume
	if bootstrap == "" {
		bootstrap = "pqnext-cbomkit-ca-root-bootstrap-unused"
	}
	return map[string]string{
		"SERVER_IP":                       serverIP,
		"SERVER_DNS_NAME":                 serverDNS,
		"PQNEXT_CBOMKIT_BOOTSTRAP_VOLUME": bootstrap,
	}
}

func (a *app) compose(ctx context.Context, serverIP, serverDNS string, stdout io.Writer, args ...string) error {
	if stdout == nil {
		stdout = a.stdout
	}
	base := []string{"compose", "--project-name", composeProject, "--file", composeFile}
	base = append(base, args...)
	return a.runner.Run(ctx, a.projectDir, a.composeEnvironment(serverIP, serverDNS), nil, stdout, a.stderr, "docker", base...)
}

func (a *app) composeInput(ctx context.Context, serverIP, serverDNS string, stdin io.Reader, args ...string) error {
	base := []string{"compose", "--project-name", composeProject, "--file", composeFile}
	base = append(base, args...)
	return a.runner.Run(ctx, a.projectDir, a.composeEnvironment(serverIP, serverDNS), stdin, a.stdout, a.stderr, "docker", base...)
}

func (a *app) buildTools(ctx context.Context, serverIP, serverDNS string) error {
	return a.compose(ctx, serverIP, serverDNS, nil, "--profile", "pki-tools", "build", "pki-import")
}

func (a *app) runImporter(ctx context.Context, material pkiMaterial, serverIP, serverDNS string) error {
	archive, err := makePKIArchive(material)
	if err != nil {
		return err
	}
	return a.composeInput(ctx, serverIP, serverDNS, bytes.NewReader(archive), "--profile", "pki-tools", "run", "--rm", "-T", "pki-import")
}

func (a *app) exportRecovery(ctx context.Context, serverIP, serverDNS string) ([]byte, error) {
	var output bytes.Buffer
	if err := a.compose(ctx, serverIP, serverDNS, &output, "--profile", "pki-tools", "run", "--rm", "-T", "root-export"); err != nil {
		return nil, fmt.Errorf("exporting root recovery archive: %w", err)
	}
	if output.Len() > maxPKIArchive {
		return nil, errors.New("exported recovery archive is too large")
	}
	return output.Bytes(), nil
}

func (a *app) readRootPassword(path string) ([]byte, error) {
	if path != "" {
		password, info, err := readRegularFileInfo(path, "root password file")
		if err != nil {
			return nil, err
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			zeroBytes(password)
			return nil, errors.New("root password file must not be accessible by group or other users")
		}
		if len(bytes.TrimSpace(password)) < 12 {
			return nil, errors.New("root recovery passphrase must contain at least 12 non-whitespace bytes")
		}
		return password, nil
	}
	input, ok := a.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return nil, errors.New("non-interactive managed installation requires --root-password-file")
	}
	fmt.Fprint(a.stderr, "Root recovery passphrase: ")
	first, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(a.stderr)
	if err != nil {
		return nil, fmt.Errorf("reading root recovery passphrase: %w", err)
	}
	fmt.Fprint(a.stderr, "Confirm root recovery passphrase: ")
	second, err := term.ReadPassword(int(input.Fd()))
	fmt.Fprintln(a.stderr)
	if err != nil {
		zeroBytes(first)
		return nil, fmt.Errorf("reading root recovery passphrase confirmation: %w", err)
	}
	defer zeroBytes(second)
	if !bytes.Equal(first, second) {
		zeroBytes(first)
		return nil, errors.New("root recovery passphrases do not match")
	}
	if len(bytes.TrimSpace(first)) < 12 {
		zeroBytes(first)
		return nil, errors.New("root recovery passphrase must contain at least 12 non-whitespace bytes")
	}
	return first, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func saveRecoveryArchive(dir, fingerprint string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating recovery directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return "", fmt.Errorf("securing recovery directory: %w", err)
	}
	path := filepath.Join(dir, "pqnext-cbomkit-root-recovery-"+fingerprint+".tar.gz")
	if existing, err := os.ReadFile(path); err == nil {
		if bytes.Equal(existing, data) {
			return path, nil
		}
		return "", fmt.Errorf("recovery archive %s already exists with different contents", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking recovery archive: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pqnext-cbomkit-recovery-*")
	if err != nil {
		return "", fmt.Errorf("creating temporary recovery archive: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return "", fmt.Errorf("securing temporary recovery archive: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("writing recovery archive: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("syncing recovery archive: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("closing recovery archive: %w", err)
	}
	if err := replaceFile(tmpName, path); err != nil {
		return "", fmt.Errorf("finalizing recovery archive: %w", err)
	}
	return path, nil
}

func (a *app) importExternal(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pki import", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var cert, key, ca string
	fs.StringVar(&cert, "server-cert", "", "server certificate chain")
	fs.StringVar(&key, "server-key", "", "unencrypted server private key")
	fs.StringVar(&ca, "client-ca", "", "client CA trust bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || cert == "" || key == "" || ca == "" {
		return errors.New("pki import requires --server-cert, --server-key, and --client-ca")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil || state.PKIMode != "external" {
		return errors.New("pki import is available only for an installed external-PKI deployment")
	}
	material, err := loadPKIMaterial(cert, key, ca)
	if err != nil {
		return err
	}
	if err := validatePKI(material, state.ServerIP, state.ServerDNS, time.Now()); err != nil {
		return fmt.Errorf("external PKI validation failed: %w", err)
	}
	if err := a.checkDocker(ctx); err != nil {
		return err
	}
	if err := a.buildTools(ctx, state.ServerIP, state.ServerDNS); err != nil {
		return err
	}
	if err := a.runImporter(ctx, material, state.ServerIP, state.ServerDNS); err != nil {
		return err
	}
	if err := a.reloadNginxIfRunning(ctx, state.ServerIP, state.ServerDNS); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "External PKI material was validated and activated atomically.")
	return nil
}

func (a *app) reloadNginxIfRunning(ctx context.Context, serverIP, serverDNS string) error {
	var running bytes.Buffer
	if err := a.compose(ctx, serverIP, serverDNS, &running, "ps", "--status", "running", "--services", "nginx"); err != nil {
		return nil
	}
	if strings.TrimSpace(running.String()) != "nginx" {
		return nil
	}
	if err := a.compose(ctx, serverIP, serverDNS, nil, "exec", "-T", "nginx", "nginx", "-s", "reload"); err != nil {
		return fmt.Errorf("certificates were installed but NGINX reload failed: %w", err)
	}
	return nil
}

func (a *app) up(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("up accepts no arguments")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil {
		return errors.New("deployment is not installed")
	}
	profile := []string{}
	if state.PKIMode == "managed" {
		profile = []string{"--profile", "managed-pki"}
	}
	profile = append(profile, "up", "-d", "--wait")
	return a.compose(ctx, state.ServerIP, state.ServerDNS, nil, profile...)
}

func (a *app) down(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("down accepts no arguments")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil {
		return errors.New("deployment is not installed")
	}
	profile := []string{}
	if state.PKIMode == "managed" {
		profile = []string{"--profile", "managed-pki"}
	}
	profile = append(profile, "down")
	return a.compose(ctx, state.ServerIP, state.ServerDNS, nil, profile...)
}

func (a *app) status(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("status accepts no arguments")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil {
		return errors.New("deployment is not installed")
	}
	return a.compose(ctx, state.ServerIP, state.ServerDNS, nil, "ps")
}

var safeClientName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func (a *app) clientToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client-token", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var name, outputPath string
	fs.StringVar(&name, "name", "", "client identity")
	fs.StringVar(&outputPath, "output", "", "token output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !safeClientName.MatchString(name) {
		return errors.New("--name must be 1-128 letters, digits, dots, underscores, or hyphens and start with a letter or digit")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil || state.PKIMode != "managed" {
		return errors.New("client-token is available only for an installed managed-PKI deployment")
	}
	a.bootstrapVolume = state.BootstrapVolume
	var token bytes.Buffer
	if err := a.compose(ctx, state.ServerIP, state.ServerDNS, &token, "--profile", "pki-tools", "run", "--rm", "-T", "client-token", "client-token", name); err != nil {
		return err
	}
	value := strings.TrimSpace(token.String())
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("step-ca returned an invalid enrollment token")
	}
	if outputPath == "" {
		outputPath = name + ".token"
	}
	if err := atomicWritePrivate(outputPath, []byte(value+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Created short-lived enrollment token: %s\n", outputPath)
	return nil
}

func (a *app) exportCA(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pki export-ca", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var outputPath string
	fs.StringVar(&outputPath, "output", "", "root CA certificate output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(outputPath) == "" {
		return errors.New("pki export-ca requires --output PATH")
	}
	state, err := loadState(a.projectDir)
	if err != nil {
		return err
	}
	if state == nil || state.PKIMode != "managed" {
		return errors.New("pki export-ca is available only for an installed managed-PKI deployment")
	}
	if state.RootFingerprint == "" {
		return errors.New("managed-PKI deployment state has no root fingerprint")
	}
	a.bootstrapVolume = state.BootstrapVolume
	var certificate bytes.Buffer
	if err := a.compose(ctx, state.ServerIP, state.ServerDNS, &certificate, "--profile", "pki-tools", "run", "--rm", "-T", "ca-export"); err != nil {
		return fmt.Errorf("exporting managed root certificate: %w", err)
	}
	if certificate.Len() == 0 || certificate.Len() > maxPKIFileSize {
		return errors.New("exported root certificate has an invalid size")
	}
	if err := validateRootCertificate(certificate.Bytes(), state.RootFingerprint, time.Now()); err != nil {
		return fmt.Errorf("validating exported root certificate: %w", err)
	}
	if err := atomicWriteFile(outputPath, certificate.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Exported managed root CA certificate: %s\nRoot fingerprint: %s\n", outputPath, state.RootFingerprint)
	return nil
}

func atomicWritePrivate(path string, data []byte) error {
	return atomicWriteFile(path, data, 0o600)
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pqnext-cbomkit-output-*")
	if err != nil {
		return fmt.Errorf("creating temporary output: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("installing output file: %w", err)
	}
	return nil
}

func internalImportPKI(args []string, input io.Reader) error {
	fs := flag.NewFlagSet("internal-import-pki", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var target, serverIP, serverDNS, source string
	fs.StringVar(&target, "target", "/pki", "target directory")
	fs.StringVar(&serverIP, "server-ip", "", "server IP")
	fs.StringVar(&serverDNS, "server-dns", "", "server DNS")
	fs.StringVar(&source, "source", "external", "source label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := readPKIArchive(input)
	if err != nil {
		return err
	}
	if err := validatePKI(material, serverIP, serverDNS, time.Now()); err != nil {
		return err
	}
	return installPKI(target, source, material)
}

func internalInstallPKI(args []string) error {
	fs := flag.NewFlagSet("internal-install-pki", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var target, cert, key, ca, serverIP, serverDNS, source string
	fs.StringVar(&target, "target", "/pki", "target directory")
	fs.StringVar(&cert, "server-cert", "", "server certificate")
	fs.StringVar(&key, "server-key", "", "server key")
	fs.StringVar(&ca, "client-ca", "", "client CA")
	fs.StringVar(&serverIP, "server-ip", "", "server IP")
	fs.StringVar(&serverDNS, "server-dns", "", "server DNS")
	fs.StringVar(&source, "source", "managed", "source label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadPKIMaterial(cert, key, ca)
	if err != nil {
		return err
	}
	if err := validatePKI(material, serverIP, serverDNS, time.Now()); err != nil {
		return err
	}
	return installPKI(target, source, material)
}

func internalValidatePKI(args []string) error {
	fs := flag.NewFlagSet("internal-validate-pki", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dir, serverIP, serverDNS string
	fs.StringVar(&dir, "dir", "/pki/current", "active PKI directory")
	fs.StringVar(&serverIP, "server-ip", "", "server IP")
	fs.StringVar(&serverDNS, "server-dns", "", "server DNS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, err := loadPKIMaterial(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.crt"))
	if err != nil {
		return err
	}
	return validatePKI(material, serverIP, serverDNS, time.Now())
}

func internalValidateRecovery(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("internal-validate-recovery accepts no arguments")
	}
	data, err := io.ReadAll(io.LimitReader(input, maxPKIArchive+1))
	if err != nil {
		return fmt.Errorf("reading recovery archive: %w", err)
	}
	if len(data) > maxPKIArchive {
		return errors.New("recovery archive is too large")
	}
	manifest, err := validateRecoveryArchive(data)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, manifest.Fingerprint)
	return err
}
