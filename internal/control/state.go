package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stateVersion = 1

type deploymentState struct {
	Version         int    `json:"version"`
	PKIMode         string `json:"pkiMode"`
	ServerIP        string `json:"serverIp"`
	ServerDNS       string `json:"serverDns,omitempty"`
	RootFingerprint string `json:"rootFingerprint,omitempty"`
	RecoveryArchive string `json:"recoveryArchive,omitempty"`
	BootstrapVolume string `json:"bootstrapVolume,omitempty"`
}

func statePath(projectDir string) string {
	return filepath.Join(projectDir, ".pqnext-cbomkit-state.json")
}

func loadState(projectDir string) (*deploymentState, error) {
	data, err := os.ReadFile(statePath(projectDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading deployment state: %w", err)
	}
	var state deploymentState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing deployment state: %w", err)
	}
	if state.Version != stateVersion {
		return nil, fmt.Errorf("unsupported deployment state version %d", state.Version)
	}
	if state.PKIMode != "managed" && state.PKIMode != "external" {
		return nil, fmt.Errorf("invalid deployment PKI mode %q", state.PKIMode)
	}
	if state.BootstrapVolume != "" && !bootstrapVolumePattern.MatchString(state.BootstrapVolume) {
		return nil, errors.New("deployment state contains an invalid bootstrap volume name")
	}
	return &state, nil
}

func saveState(projectDir string, state deploymentState) error {
	state.Version = stateVersion
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding deployment state: %w", err)
	}
	data = append(data, '\n')
	path := statePath(projectDir)
	tmp, err := os.CreateTemp(projectDir, ".pqnext-cbomkit-state-*")
	if err != nil {
		return fmt.Errorf("creating deployment state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting deployment state permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing deployment state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing deployment state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing deployment state: %w", err)
	}
	if err := replaceFile(tmpName, path); err != nil {
		return fmt.Errorf("installing deployment state: %w", err)
	}
	return nil
}
