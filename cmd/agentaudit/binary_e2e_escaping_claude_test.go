package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeAgentFrontmatter's Bash grant makes the agent's presence in a report
// unambiguous evidence the file was read.
func writeAgentFrontmatter(t *testing.T, path, name string) {
	t.Helper()
	body := "---\nname: " + name + "\ntools: [Bash, Read]\n---\nbody\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Refusal covers an entire .claude symlinked out of the scanned root, not
// only a single adapter-owned file.
func TestBinaryE2E_EscapingClaudeDirectoryCountsAsUnreadable(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "agents"), 0o755); err != nil {
		t.Fatalf("mkdir outside/agents: %v", err)
	}
	writeAgentFrontmatter(t, filepath.Join(outside, "agents", "exfil.md"), "exfil")

	root := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".claude")); err != nil {
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
	if strings.Contains(out, "exfil") {
		t.Fatalf("stdout contains the out-of-tree agent name %q, want it never reported\nstdout:\n%s", "exfil", out)
	}
	if claimsACleanScan(out) {
		t.Fatalf("stdout reads as a clean scan, want that suppressed once the mcp finding surfaces\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
	if !strings.Contains(errOut, ".claude") {
		t.Fatalf("stderr = %q, want it to name the in-tree .claude path", errOut)
	}
}

// Containment applies to a nested directory too, not only the outermost. The
// in-tree hook beside the escaping agents/ is what distinguishes "descended,
// inner refusal counted" from "never descended" — a fixture with nothing else
// inside the target cannot tell those apart.
func TestBinaryE2E_InTreeClaudeWithEscapingNestedAgentsCountsAsUnreadable(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outsideAgents := t.TempDir()
	writeAgentFrontmatter(t, filepath.Join(outsideAgents, "exfil.md"), "exfil")

	root := t.TempDir()
	realClaude := filepath.Join(root, "config")
	if err := os.MkdirAll(realClaude, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	writeHookSettings(t, filepath.Join(realClaude, "settings.json"), "notify.sh")
	if err := os.Symlink("config", filepath.Join(root, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	if err := os.Symlink(outsideAgents, filepath.Join(realClaude, "agents")); err != nil {
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
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout must report the in-tree hook notify.sh, proving the outer descent through the symlinked .claude actually happened\nstdout:\n%s", out)
	}
	if strings.Contains(out, "exfil") {
		t.Fatalf("stdout contains the out-of-tree agent name %q, want it never reported\nstdout:\n%s", "exfil", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\" for the inner escaping agents/ directory\nstdout:\n%s", out)
	}
}
