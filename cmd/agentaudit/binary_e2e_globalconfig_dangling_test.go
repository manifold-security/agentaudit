package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dangling ~/.claude.json renders the global block across the process
// boundary. stderr is asserted alongside stdout because a lost warning is
// invisible in the report body. SCAN INCOMPLETE is asserted absent, unlike
// TestBinaryE2E_GlobalConfig_ClaudeJSONAsADirectoryDegradesWithoutASilentClean,
// which pins the case where a source something could have read went unread.
func TestBinaryE2E_GlobalConfig_DanglingClaudeJSONStillRendersTheGlobalBlock(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	if err := os.Symlink("nowhere.json", filepath.Join(home, ".claude.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a global config with nothing behind the link)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout has no global block header for %q\nstdout:\n%s", home, out)
	}
	if !strings.Contains(errOut, ".claude.json") {
		t.Fatalf("stderr = %q, want a warning naming the dangling entry", errOut)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for a link whose target does not exist\nstdout:\n%s", out)
	}
}
