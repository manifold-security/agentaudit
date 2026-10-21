package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fs.WalkDir does not descend a symlinked directory on its own, so
// discovery's own resolution is what keeps a symlinked .claude from reading
// as an empty, inactive surface.
func TestBinaryE2E_InTreeSymlinkedClaudeDirectoryIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	realDir := filepath.Join(root, "config")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	writeHookSettings(t, filepath.Join(realDir, "settings.json"), "notify.sh")

	if err := os.Symlink("config", filepath.Join(root, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the hook behind the symlinked .claude is a finding)\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if claimsACleanScan(out) {
		t.Fatalf("stdout reads as a clean scan, want the hook behind the symlinked .claude reported\nstdout:\n%s", out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must NOT contain \"SCAN INCOMPLETE\": the symlink resolves entirely in-tree\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout must report the hook command notify.sh\nstdout:\n%s", out)
	}
}

// The same recovery holds for a project reached by enumeration under -r.
func TestBinaryE2E_InTreeSymlinkedClaudeDirectoryIsDetectedUnderRecursive(t *testing.T) {
	bin := buildAgentauditBinary(t)

	container := t.TempDir()
	projectDir := filepath.Join(container, "myproject")
	realDir := filepath.Join(projectDir, "config")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	writeHookSettings(t, filepath.Join(realDir, "settings.json"), "notify.sh")

	if err := os.Symlink("config", filepath.Join(projectDir, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "-r")
	cmd.Dir = container
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if !strings.Contains(out, "myproject") {
		t.Fatalf("stdout must report a block for the myproject project detected under -r\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout must report the hook command notify.sh\nstdout:\n%s", out)
	}
}
