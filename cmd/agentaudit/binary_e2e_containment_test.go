package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const outsideHookCommand = "exfil-outside-marker"

func writeHookSettings(t *testing.T, path, command string) {
	t.Helper()
	body := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + command + `"}]}]}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeFindingMCP(t *testing.T, path string) {
	t.Helper()
	body := `{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs"]}}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// An escaping symlink at an adapter-owned path is refused rather than
// followed, and the scan degrades instead of rendering a false clean.
func TestBinaryE2E_EscapingSymlinkedSettingsCountsAsUnreadable(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outside := t.TempDir()
	outsideSettings := filepath.Join(outside, "settings.json")
	writeHookSettings(t, outsideSettings, outsideHookCommand)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.Symlink(outsideSettings, filepath.Join(root, ".claude", "settings.json")); err != nil {
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
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding still surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, outsideHookCommand) {
		t.Fatalf("stdout contains the out-of-tree hook command %q, want it never reported\nstdout:\n%s", outsideHookCommand, out)
	}
	if claimsACleanScan(out) {
		t.Fatalf("stdout reads as a clean scan, want that suppressed once the mcp finding surfaces\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "unreadable source") {
		t.Fatalf("stdout must contain the unreadable-source footer suffix\nstdout:\n%s", out)
	}
	if !strings.Contains(errOut, filepath.Join(".claude", "settings.json")) {
		t.Fatalf("stderr = %q, want it to name the in-tree path %q", errOut, filepath.Join(".claude", "settings.json"))
	}
}

func TestBinaryE2E_EscapingSymlinkedSettingsViaRelativeParentTraversal(t *testing.T) {
	bin := buildAgentauditBinary(t)

	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir root/.claude: %v", err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	outsideSettings := filepath.Join(outside, "settings.json")
	writeHookSettings(t, outsideSettings, outsideHookCommand)
	writeFindingMCP(t, filepath.Join(root, ".mcp.json"))

	relTarget := filepath.Join("..", "..", "outside", "settings.json")
	if err := os.Symlink(relTarget, filepath.Join(root, ".claude", "settings.json")); err != nil {
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
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if strings.Contains(out, outsideHookCommand) {
		t.Fatalf("stdout contains the out-of-tree hook command %q, want it never reported\nstdout:\n%s", outsideHookCommand, out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
}

func TestBinaryE2E_InTreeSymlinkedSettingsIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	realSettings := filepath.Join(root, "config", "settings.json")
	writeHookSettings(t, realSettings, "notify.sh")

	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	relTarget := filepath.Join("..", "config", "settings.json")
	if err := os.Symlink(relTarget, filepath.Join(root, ".claude", "settings.json")); err != nil {
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
		t.Fatalf("exit code = %d, want 1 (the in-tree hook is a finding)\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must NOT contain \"SCAN INCOMPLETE\" for a fully in-tree symlink\nstdout:\n%s", out)
	}
	if strings.Contains(out, "unreadable source") {
		t.Fatalf("stdout reports an unreadable source for a fully in-tree symlink\nstdout:\n%s", out)
	}
}

// An unopenable target is an eager, mapped failure at exit 2 rather than a
// clean empty report.
func TestBinaryE2E_MissingOrNonDirectoryTargetExitsTwo(t *testing.T) {
	bin := buildAgentauditBinary(t)

	regularFile := filepath.Join(t.TempDir(), "not-a-directory.txt")
	if err := os.WriteFile(regularFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %s: %v", regularFile, err)
	}

	unreadableDir := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(unreadableDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", unreadableDir, err)
	}
	if err := os.Chmod(unreadableDir, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", unreadableDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadableDir, 0o755) })

	tests := []struct {
		name                string
		target              string
		needsPermissionBits bool
	}{
		{name: "missing directory", target: filepath.Join(t.TempDir(), "does-not-exist")},
		{name: "regular file as target", target: regularFile},
		{name: "permission-denied directory", target: unreadableDir, needsPermissionBits: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.needsPermissionBits {
				skipUnlessPermissionBitsEnforced(t)
			}

			var stdout, stderr bytes.Buffer
			cmd := exec.Command(bin, tt.target)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			code := 0
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
			}

			if code != 2 {
				t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "SCAN INCOMPLETE") {
				t.Fatalf("stdout must not contain \"SCAN INCOMPLETE\": an open failure has no report to degrade\nstdout:\n%s", stdout.String())
			}
			if stdout.String() != "" {
				t.Fatalf("stdout = %q, want empty: an open failure emits no report block", stdout.String())
			}
		})
	}
}
