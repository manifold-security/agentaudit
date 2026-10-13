package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// frontmatterFixture carries no .claude/settings*.json and no .mcp.json, so
// only frontmatter-declared capabilities can surface from it.
const frontmatterFixture = "../../testdata/benign/claude-frontmatter"

func TestBinaryE2E_FrontmatterFindings(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(frontmatterFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", frontmatterFixture, err)
	}
	if _, err := os.Stat(absFixture); err != nil {
		t.Fatalf("fixture %q not found: %v", absFixture, err)
	}

	cmd := exec.Command(bin)
	cmd.Dir = absFixture
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\n%s", err, out)
	}
	if err == nil {
		t.Fatalf("binary exited 0, want non-zero (findings are present)\n%s", out)
	}
	// 1 is the findings-present code; 2 would mean the scan errored instead.
	if exitErr.ExitCode() != 1 {
		t.Fatalf("binary ExitCode() = %d, want 1\n%s", exitErr.ExitCode(), out)
	}

	stdout := string(out)
	wantValues := []string{
		"audit.sh",                    // subagent hook command
		"skill-hook.sh",               // skill hook command
		"command-hook.sh",             // command hook command
		"/usr/local/bin/mcp-fs",       // inline mcpServer command
		"acceptEdits",                 // subagent permissionMode
		".claude/agents/reviewer.md",  // subagent provenance
		".claude/skills/foo/SKILL.md", // skill provenance
		".claude/commands/release.md", // command provenance
	}
	for _, want := range wantValues {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing expected value %q\nfull stdout:\n%s", want, stdout)
		}
	}
	for _, want := range []string{"code-execution:", "permissions:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", want, stdout)
		}
	}
}
