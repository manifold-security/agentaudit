package main

import (
	"strings"
	"testing"
)

// corruptedFixture holds a truncated .mcp.json beside a readable
// .claude/settings.json that declares a capability of its own.
const corruptedFixture = "../../testdata/malicious/claude-malformed"

// A corrupted-but-readable source is unparsed, never unreadable, and its
// readable sibling's finding must still be reported.
func TestBinaryE2E_CorruptedSourceWarnsAndCompletes(t *testing.T) {
	bin := buildAgentauditBinary(t)
	absFixture := resolveFixture(t, corruptedFixture)

	stdout, stderr, code := runBinary(t, bin, absFixture)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the sibling's finding is present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "hook SessionStart") {
		t.Errorf("stdout missing the sibling's finding\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "warning:") {
		t.Errorf("stderr missing a warning: line\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Errorf("stdout must name the corrupted source as unparsed\nstdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "unreadable source") {
		t.Errorf("stdout must not call a source it did read unreadable\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "· 1 unparsed source\n") {
		t.Errorf("stdout missing the unparsed footer suffix\nstdout:\n%s", stdout)
	}
}
