package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The run leaves the scan incomplete and names both keys instead of printing a
// clean report.
func TestBinaryE2E_SettingsKeysDifferingOnlyInCaseLeaveTheScanIncomplete(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	dir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	const settings = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch ./m"}]}]},"Hooks":null}`
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if claimsACleanScan(stdout) {
		t.Fatalf("stdout must NOT read as a clean empty scan\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Fatalf("stdout missing the unparsed SCAN INCOMPLETE line\nstdout:\n%s", stdout)
	}
	if want := `.claude/settings.json: key "Hooks" differs only in case from "hooks"`; !strings.Contains(stderr, want) {
		t.Fatalf("stderr missing %q\nstderr:\n%s", want, stderr)
	}
}
