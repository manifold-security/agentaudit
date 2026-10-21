package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pluginComponentsFixture executes code through its skills and slash commands
// without ever touching .claude/.
const pluginComponentsFixture = "../../testdata/malicious/claude-plugin-components"

// Widening the agent carve-out to skills and narrowing it to nothing are
// opposite defects, so the visible and suppressed halves are pinned together.
// Each suppressed token below appears only in agents/reviewer.md, so its
// absence proves suppression rather than coincidence.
func TestBinaryE2E_PluginComponentsTree(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(pluginComponentsFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", pluginComponentsFixture, err)
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
	if exitErr.ExitCode() != 1 {
		t.Fatalf("binary ExitCode() = %d, want 1 (findings)\n%s", exitErr.ExitCode(), out)
	}

	stdout := string(out)
	if !strings.Contains(stdout, "code-execution:") {
		t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", "code-execution:", stdout)
	}

	for _, want := range []string{
		"plugin-skill-hook.sh",
		"https://plugin-skill.example/preflight.sh",
		"plugin-command-hook.sh",
		"https://plugin-command.example/preflight.sh",
		"plugin-declared-skill.sh",
		"plugin-root-skill-hook.sh",
		"plugin-root-skill.sh",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}

	for _, suppressed := range []string{
		"suppressed-plugin-agent-hook.sh",
		"suppressed-plugin-agent-mcp",
	} {
		if strings.Contains(stdout, suppressed) {
			t.Errorf("binary stdout contains suppressed plugin-agent token %q; the security carve-out must hold\nfull stdout:\n%s", suppressed, stdout)
		}
	}

	// A subagent body is not scanned for inline shell at all, so this token's
	// absence is not the carve-out at work and belongs apart from it.
	if strings.Contains(stdout, "suppressed-plugin-agent-inline.sh") {
		t.Errorf("binary stdout scanned an agent body for inline shell\nfull stdout:\n%s", stdout)
	}
}
