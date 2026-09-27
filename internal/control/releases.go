package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	publicReleaseBaseURL = "https://github.com/AchilleasEconomopoulos/PQNEXT-CBOMKit-Deployment/releases/download"
	maxStackDownload     = 32 << 20
	maxStackExtracted    = 64 << 20
	maxStackEntries      = 4096
)

var stackVersionPattern = regexp.MustCompile(`^stack-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$`)

func normalizeStackVersion(version string) (string, error) {
	if !strings.HasPrefix(version, "stack-") {
		version = "stack-v" + strings.TrimPrefix(version, "v")
	}
	if len(version) > 128 || !stackVersionPattern.MatchString(version) {
		return "", errors.New("--stack-version must be a version such as 1.0.0, v1.0.0, or stack-v1.0.0 (optional prerelease suffix)")
	}
	return version, nil
}

// Prefer recorded state so lifecycle commands use the installed release even
// when invoked from another deployment checkout.
func resolveProject() (string, error) {
	state, err := loadState()
	if err == nil && state != nil && state.ProjectDir != "" {
		return state.ProjectDir, nil
	}
	// Preserve local uninstall's ability to clean up with unreadable state.
	return locateProject()
}

func (a *app) prepareInstallProject(ctx context.Context, options installOptions, state *deploymentState) error {
	if options.stackVersion != "" {
		if a.projectDir != "" {
			return errors.New("--stack-version cannot be combined with --project-dir")
		}
		tag, err := normalizeStackVersion(options.stackVersion)
		if err != nil {
			return err
		}
		if state != nil && state.StackVersion != tag {
			return errors.New("changing an installed deployment to a different stack release is not supported")
		}
		a.projectDir, err = a.downloadStack(ctx, tag)
		if err != nil {
			return err
		}
	} else if a.projectDir == "" {
		var err error
		a.projectDir, err = resolveProject()
		if err != nil {
			return errors.New("cannot locate deployment; pass --stack-version VERSION to download a release or --project-dir PATH for a local deployment")
		}
	}
	var err error
	a.projectDir, err = filepath.Abs(a.projectDir)
	if err != nil {
		return fmt.Errorf("resolving deployment directory: %w", err)
	}
	if state != nil && state.ProjectDir != "" && filepath.Clean(state.ProjectDir) != a.projectDir {
		return errors.New("deployment directory differs from recorded state; moving an installed deployment is not supported")
	}
	if options.envFile != "" {
		if err := copyDeploymentEnvironment(options.envFile, a.projectDir); err != nil {
			return err
		}
	}
	return nil
}

func copyDeploymentEnvironment(source, dir string) error {
	data, err := readRegularFile(source, "deployment configuration")
	if err != nil {
		return err
	}
	target := filepath.Join(dir, ".env")
	if existing, err := readRegularFile(target, "existing deployment configuration"); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return errors.New("deployment .env already exists with different contents; existing configuration will not be replaced")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating deployment configuration: %w", err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(target)
		return fmt.Errorf("writing deployment configuration: %w", err)
	}
	return nil
}

func (a *app) downloadStack(ctx context.Context, tag string) (string, error) {
	stateFile, err := statePath()
	if err != nil {
		return "", err
	}
	parent := filepath.Join(filepath.Dir(stateFile), "stacks")
	target := filepath.Join(parent, tag)
	if _, err := os.Lstat(target); err == nil {
		if err := validateStackDirectory(target); err != nil {
			return "", fmt.Errorf("existing stack directory is incomplete; remove or repair %s before retrying: %w", target, err)
		}
		fmt.Fprintf(a.stdout, "Using deployment %s from %s\n", tag, target)
		return target, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking stack directory: %w", err)
	}
	asset := "pqnext-cbomkit-" + tag + ".tar.gz"
	base := a.releaseBaseURL
	if base == "" {
		base = publicReleaseBaseURL
	}
	base = strings.TrimRight(base, "/") + "/" + tag + "/"
	fmt.Fprintf(a.stdout, "Downloading deployment %s\n", tag)
	checksums, err := a.downloadReleaseAsset(ctx, base+"SHA256SUMS", 64<<10)
	if err != nil {
		return "", err
	}
	expected, err := stackChecksum(checksums, asset)
	if err != nil {
		return "", err
	}
	archive, err := a.downloadReleaseAsset(ctx, base+asset, maxStackDownload)
	if err != nil {
		return "", err
	}
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != expected {
		return "", errors.New("deployment archive SHA-256 checksum mismatch")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("creating stack directory: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".download-*")
	if err != nil {
		return "", fmt.Errorf("creating stack staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := extractStack(archive, staging); err != nil {
		return "", fmt.Errorf("extracting deployment: %w", err)
	}
	if err := validateStackDirectory(staging); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		return "", fmt.Errorf("activating downloaded stack: %w", err)
	}
	fmt.Fprintf(a.stdout, "Deployment %s saved to %s\n", tag, target)
	return target, nil
}

func (a *app) downloadReleaseAsset(ctx context.Context, url string, limit int64) ([]byte, error) {
	client := a.httpClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("release downloads require HTTPS")
			}
			if len(via) >= 10 {
				return errors.New("too many release download redirects")
			}
			return nil
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading release asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: HTTP %d (check that the public stack release and its assets exist)", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading release asset: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, errors.New("release asset exceeds download size limit")
	}
	return data, nil
}

func stackChecksum(data []byte, asset string) (string, error) {
	var checksum string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size || checksum != "" {
			return "", errors.New("invalid or duplicate deployment checksum")
		}
		checksum = strings.ToLower(fields[0])
	}
	if checksum == "" {
		return "", fmt.Errorf("SHA256SUMS does not contain %s", asset)
	}
	return checksum, nil
}

func extractStack(archive []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer gz.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	// Bound the complete decompressed stream, including tar headers and padding.
	limited := &io.LimitedReader{R: gz, N: maxStackExtracted + 1}
	reader := tar.NewReader(limited)
	for entries := 0; ; entries++ {
		header, err := reader.Next()
		if err == io.EOF {
			// Read through the gzip footer so truncated or corrupt downloads fail.
			if _, err := io.Copy(io.Discard, limited); err != nil {
				return err
			}
			if limited.N == 0 {
				return errors.New("deployment exceeds extraction size limit")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if entries >= maxStackEntries || header.Size < 0 || header.Size > limited.N {
			return errors.New("deployment exceeds extraction limits")
		}
		// git archive includes a global PAX header with the commit identifier.
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "." && header.Typeflag == tar.TypeDir {
			continue
		}
		if name == "" || path.Clean(name) != name || !filepath.IsLocal(filepath.FromSlash(name)) || strings.ContainsAny(name, "\\:") || name == ".env" {
			return fmt.Errorf("unsafe deployment archive path %q", header.Name)
		}
		local := filepath.FromSlash(name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(local, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(local), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			file, err := root.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(file, reader)
			closeErr := file.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported deployment archive entry %q (links and special files are refused)", name)
		}
	}
}

func validateStackDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("deployment directory %s must be a directory", dir)
	}
	for _, name := range []string{
		composeFile, "nginx.conf", ".env.example", ".dockerignore", "go.mod", "go.sum",
		"step-ca/Dockerfile", "step-ca/bin/pqnext-cbomkit-pki",
		"step-ca/templates/server.tpl", "step-ca/templates/client.tpl",
		"opa/quantum_safe.rego", "cmd/pqnext-cbomkitctl/main.go", "internal/control/app.go",
	} {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("deployment bundle is missing required regular file %s", name)
		}
	}
	return nil
}
