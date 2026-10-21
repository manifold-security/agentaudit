package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A read failure strictly below the scan root warns and counts rather than
// aborting: an unrelated .mcp.json elsewhere is still discovered.
func TestBinaryE2E_UnreadableNestedSymlinkedDirectoryDegradesNotAborts(t *testing.T) {
	skipUnlessPermissionBitsEnforced(t)
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", secret, err)
	}
	writeHookSettings(t, filepath.Join(secret, "settings.json"), "unreachable.sh")
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", secret, err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })

	if err := os.Symlink("secret", filepath.Join(root, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	writeFindingMCP(t, filepath.Join(root, ".mcp.json"))

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

	out, errOut := stdout.String(), stderr.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding still surfaces despite the unreadable symlinked directory)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if out == "" {
		t.Fatal("stdout is empty, want a rendered report — a below-root read failure must degrade, not abort")
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "unreadable source") {
		t.Fatalf("stdout must contain the unreadable-source footer suffix\nstdout:\n%s", out)
	}
	if errOut == "" {
		t.Fatal("stderr is empty, want a warning naming the unreadable symlinked directory")
	}
}
