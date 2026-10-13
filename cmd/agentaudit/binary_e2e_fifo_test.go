package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Classifying a symlink through an open reaches the FIFO it targets, so this
// guard fails as a timeout rather than a wrong answer.
func TestBinaryE2E_RecursiveScanOverAFifoCompletes(t *testing.T) {
	bin := buildAgentauditBinary(t)

	container := t.TempDir()
	plugin := filepath.Join(container, "tools", "myplug")
	if err := os.MkdirAll(filepath.Join(plugin, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", plugin, err)
	}
	manifest := filepath.Join(plugin, ".claude-plugin", "plugin.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"myplug","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", manifest, err)
	}
	if out, err := exec.Command("mkfifo", filepath.Join(plugin, "pipe")).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
	}
	if err := os.Symlink("pipe", filepath.Join(plugin, "pipelink")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-r")
	cmd.Dir = container
	out, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("scanning a project containing a symlink to a FIFO never returned; a blocking Open classified the symlink instead of a stat\noutput so far:\n%s", out)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\noutput:\n%s", err, out)
	}
	if got := cmd.ProcessState.ExitCode(); got != 1 {
		t.Fatalf("exit code = %d, want 1 (findings)\noutput:\n%s", got, out)
	}
	if !strings.Contains(string(out), "plugin myplug") {
		t.Fatalf("stdout does not report the nested plugin, so the scan did not reach it\noutput:\n%s", out)
	}
}

// A pipe at a declared config path reaches fs.ReadFile with no walk in
// between, so the refusal has to come from the guard rather than from a
// DirEntry the walk already held.
func TestBinaryE2E_ScanOverAFifoSettingsFileCompletes(t *testing.T) {
	bin := buildAgentauditBinary(t)

	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", project, err)
	}
	settings := filepath.Join(project, ".claude", "settings.json")
	if out, err := exec.Command("mkfifo", settings).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Dir = project
	out, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("scanning a project whose settings.json is a FIFO never returned; the read reached the pipe instead of the guard\noutput so far:\n%s", out)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), `refusing to read ".claude/settings.json"`) {
		t.Fatalf("output never names the refused settings file, so a source nothing read is reported as clean\noutput:\n%s", out)
	}
}
