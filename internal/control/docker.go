package control

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
)

type commandRunner interface {
	Run(ctx context.Context, dir string, env map[string]string, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, dir string, extraEnv map[string]string, stdin io.Reader, stdout, stderr io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = mergeEnvironment(os.Environ(), extraEnv)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s: %w", name, err)
	}
	return nil
}

func mergeEnvironment(base []string, overrides map[string]string) []string {
	env := make(map[string]string, len(base)+len(overrides))
	for _, item := range base {
		for i := 0; i < len(item); i++ {
			if item[i] == '=' {
				env[item[:i]] = item[i+1:]
				break
			}
		}
	}
	for key, value := range overrides {
		env[key] = value
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+env[key])
	}
	return result
}
