package main

import (
	"strings"
	"testing"
)

// benignFixture activates the Claude adapter but declares nothing any rule
// matches (see the root package's TestScanBenignFixtureIsClean).
const benignFixture = "../../testdata/benign/claude-clean"

func TestBinaryE2E_BenignFixtureIsClean(t *testing.T) {
	bin := buildAgentauditBinary(t)
	absFixture := resolveFixture(t, benignFixture)

	stdout, stderr, code := runBinary(t, bin, absFixture)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "no capabilities found") {
		t.Fatalf("stdout missing %q\nstdout:\n%s", "no capabilities found", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}
