package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

var sshUserPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
var dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func (a *app) distributeCA(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pki distribute-ca", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var hostsPath string
	fs.StringVar(&hostsPath, "hosts", "", "file with one user@host per line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(hostsPath) == "" {
		return errors.New("pki distribute-ca requires --hosts PATH")
	}
	hosts, err := readCAHosts(hostsPath)
	if err != nil {
		return err
	}
	certificate, fingerprint, err := a.managedCACertificate(ctx)
	if err != nil {
		return err
	}
	return a.copyCACertificate(ctx, hosts, certificate, fingerprint)
}

func readCAHosts(path string) ([]string, error) {
	data, err := readRegularFile(path, "CA distribution hosts file")
	if err != nil {
		return nil, err
	}
	var hosts []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4096)
	for line := 1; scanner.Scan(); line++ {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		if !validCAHost(entry) {
			return nil, fmt.Errorf("invalid CA distribution host on line %d: expected user@host", line)
		}
		if !seen[entry] {
			hosts = append(hosts, entry)
			seen[entry] = true
		}
		if len(hosts) > 10000 {
			return nil, errors.New("CA distribution hosts file has more than 10000 hosts")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading CA distribution hosts file: %w", err)
	}
	if len(hosts) == 0 {
		return nil, errors.New("CA distribution hosts file has no hosts")
	}
	return hosts, nil
}

func validCAHost(entry string) bool {
	parts := strings.Split(entry, "@")
	if len(parts) != 2 || !sshUserPattern.MatchString(parts[0]) {
		return false
	}
	host := parts[1]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.ParseIP(host[1:len(host)-1]) != nil
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func (a *app) copyCACertificate(ctx context.Context, hosts []string, certificate []byte, fingerprint string) error {
	tmp, err := os.CreateTemp("", "pqnext-cbomkit-ca-*.crt")
	if err != nil {
		return fmt.Errorf("creating temporary CA certificate: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(certificate); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temporary CA certificate: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary CA certificate: %w", err)
	}
	failures := 0
	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "ssh", host, "mkdir -p -m 700 .config/pqnext"); err != nil {
			fmt.Fprintf(a.stderr, "Failed to prepare CA certificate directory on %s: %v\n", host, err)
			failures++
			continue
		}
		if err := a.runner.Run(ctx, a.projectDir, nil, nil, a.stdout, a.stderr, "scp", tmp.Name(), host+":.config/pqnext/ca.crt"); err != nil {
			fmt.Fprintf(a.stderr, "Failed to copy CA certificate to %s: %v\n", host, err)
			failures++
			continue
		}
		fmt.Fprintf(a.stdout, "Copied CA certificate to %s:~/.config/pqnext/ca.crt\n", host)
	}
	if failures != 0 {
		return fmt.Errorf("CA distribution failed for %d of %d hosts", failures, len(hosts))
	}
	fmt.Fprintf(a.stdout, "Distributed root CA certificate to %d hosts. Root fingerprint: %s\n", len(hosts), fingerprint)
	return nil
}
