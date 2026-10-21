package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pluginOnlyFixture has NO .claude/ directory at all, so activation must come
// purely from the depth-agnostic plugin-manifest signature.
const pluginOnlyFixture = "../../testdata/malicious/claude-plugin-only"

func TestBinaryE2E_PluginOnlyTree(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(pluginOnlyFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", pluginOnlyFixture, err)
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
	if exitErr.ExitCode() == 0 {
		t.Fatalf("binary ExitCode() = 0, want non-zero\n%s", out)
	}

	stdout := string(out)
	if !strings.Contains(stdout, "code-execution:") {
		t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", "code-execution:", stdout)
	}
	if !strings.Contains(stdout, "plugin vendor-plugin") {
		t.Errorf("binary stdout missing %q (claude.plugin.installed presence)\nfull stdout:\n%s", "plugin vendor-plugin", stdout)
	}
	// ${CLAUDE_PLUGIN_ROOT} in the inline mcpServers "db" command is
	// substituted to its fs-relative path BEFORE matching, so the finding
	// must show the resolved path and never the literal placeholder.
	if !strings.Contains(stdout, "plugins/vendor/bin/db") {
		t.Errorf("binary stdout missing the substituted MCP command %q\nfull stdout:\n%s", "plugins/vendor/bin/db", stdout)
	}
	if strings.Contains(stdout, "CLAUDE_PLUGIN_ROOT") {
		t.Errorf("binary stdout contains the literal placeholder %q, want it substituted away\nfull stdout:\n%s", "CLAUDE_PLUGIN_ROOT", stdout)
	}
	// The committed 0755 bin/db fixture surfaces as its own pluginExecutable
	// finding, independent of any markdown reference.
	if !strings.Contains(stdout, "pluginExecutable db") {
		t.Errorf("binary stdout missing %q (claude.plugin.executable finding for bin/db)\nfull stdout:\n%s", "pluginExecutable db", stdout)
	}
}

const fullPluginFixture = "../../testdata/malicious/claude-plugin"

func TestBinaryE2E_FullPluginTree(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(fullPluginFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", fullPluginFixture, err)
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
	if exitErr.ExitCode() == 0 {
		t.Fatalf("binary ExitCode() = 0, want non-zero\n%s", out)
	}

	stdout := string(out)
	if !strings.Contains(stdout, "code-execution:") {
		t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", "code-execution:", stdout)
	}

	for _, want := range []string{
		"pluginExecutable root-tool.sh +x",
		"pluginExecutable no-exec-bit.sh", // no +x — still fires
		"pluginExecutable nested-tool +x",
		"pluginExecutable still-flagged.sh +x", // survives the sibling malformed manifest
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "not-on-path.sh") {
		t.Errorf("binary stdout contains %q; a file nested one level under bin/ must NOT surface\nfull stdout:\n%s", "not-on-path.sh", stdout)
	}

	// ${CLAUDE_PLUGIN_DATA} is never substituted, unlike the
	// ${CLAUDE_PLUGIN_ROOT} above.
	for _, want := range []string{
		"root-hooks-file.sh",
		"nested-plugin-hook.sh",
		"cat ${CLAUDE_PLUGIN_DATA}/state.json",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}

	for _, want := range []string{
		"mcpServer root-tool (stdio)",
		"mcpServer root-mcp (stdio)",
		"mcpServer array-mcp (stdio)",
		"mcpServer chat (ws)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q\nfull stdout:\n%s", want, stdout)
		}
	}

	// The plugin agent's hooks/mcpServers/permissionMode frontmatter keys
	// must be suppressed (a deliberate security carve-out) — every token is
	// unique to agents/plugin-agent.md, so their absence proves suppression
	// rather than mere coincidence.
	for _, suppressed := range []string{
		"suppressed-hook.sh",
		"suppressed-mcp-server",
		"suppressed-permission-mode",
	} {
		if strings.Contains(stdout, suppressed) {
			t.Errorf("binary stdout contains suppressed plugin-agent token %q; the security carve-out must hold\nfull stdout:\n%s", suppressed, stdout)
		}
	}
}
