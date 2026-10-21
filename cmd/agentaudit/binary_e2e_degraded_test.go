package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// skipUnlessPermissionBitsEnforced exists because Windows does not enforce
// permission bits and root bypasses them: a chmod-000 fixture hides nothing.
func skipUnlessPermissionBitsEnforced(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not enforced on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
}

// degradedFixture writes a root .mcp.json so the scan reaches the parse
// layer: the chmod-000 .claude on its own warns at discovery and counts no
// unparsed source.
func degradedFixture(t *testing.T, mcp string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(mcp), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	dir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod .claude: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	return root
}

// claimsACleanScan reports whether out carries either sentence a reader
// takes for a clean bill of health: the one naming the agents a scan read
// and the one naming none. Rejecting a single wording leaves a guard blind
// the moment a regression produces the other.
func claimsACleanScan(out string) bool {
	return strings.Contains(out, "no capabilities found") ||
		strings.Contains(out, "no known agent config read")
}

var unreadableCountPattern = regexp.MustCompile(` · (\d+) unreadable sources?(?: ·|\n)`)

func parseUnreadableCount(t *testing.T, stdout string) int {
	t.Helper()
	m := unreadableCountPattern.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("stdout has no %q-shaped unreadable-sources suffix; stdout:\n%s", unreadableCountPattern.String(), stdout)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse unreadable count %q: %v", m[1], err)
	}
	return n
}

func TestBinaryE2E_DegradedScanIsNotReportedAsClean(t *testing.T) {
	skipUnlessPermissionBitsEnforced(t)
	bin := buildAgentauditBinary(t)
	// The malformed (not "{}") .mcp.json adds a parse-fault warning, counted
	// as unparsed, alongside the chmod-000 read failure counted as unreadable.
	root := degradedFixture(t, `{`)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}
	gotCode := 0
	if ok {
		gotCode = exitErr.ExitCode()
	}
	if gotCode != 1 {
		t.Fatalf("exit code = %d, want 1 (degraded, no findings)\nstdout:\n%s\nstderr:\n%s", gotCode, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if claimsACleanScan(out) {
		t.Fatalf("stdout must NOT read as a clean scan when the scan was degraded\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
	if !strings.Contains(out, " · 1 unparsed source\n") {
		t.Fatalf("stdout must count the malformed .mcp.json as an unparsed source\nstdout:\n%s", out)
	}

	// The comparison is one-directional because the malformed .mcp.json
	// warns without landing in the unreadable bucket.
	wantWarnings := parseUnreadableCount(t, out)
	gotWarnings := strings.Count(stderr.String(), "warning:")
	if gotWarnings <= wantWarnings {
		t.Fatalf("stderr has %d \"warning:\" lines, want strictly more than the footer's rendered count %d (the malformed .mcp.json must warn without counting)\nstderr:\n%s\nstdout:\n%s", gotWarnings, wantWarnings, stderr.String(), out)
	}
}

func TestBinaryE2E_DegradedWithFindingsRendersFooterSuffix(t *testing.T) {
	skipUnlessPermissionBitsEnforced(t)
	bin := buildAgentauditBinary(t)
	mcpBody := `{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`
	root := degradedFixture(t, mcpBody)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}
	gotCode := 0
	if ok {
		gotCode = exitErr.ExitCode()
	}
	if gotCode != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s\nstderr:\n%s", gotCode, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\"\nstdout:\n%s", out)
	}
	if !strings.Contains(out, " unreadable source") {
		t.Fatalf("stdout must contain the footer's unreadable-source suffix\nstdout:\n%s", out)
	}

	// One-directional; TestBinaryE2E_DegradedScanIsNotReportedAsClean has the
	// strict case.
	wantWarnings := parseUnreadableCount(t, out)
	gotWarnings := strings.Count(stderr.String(), "warning:")
	if gotWarnings < wantWarnings {
		t.Fatalf("stderr has %d \"warning:\" lines, want at least the footer's rendered count %d\nstderr:\n%s\nstdout:\n%s", gotWarnings, wantWarnings, stderr.String(), out)
	}
}

// A containment refusal is not a filesystem permission fault, but it hides
// just as much: a Bash-capable subagent behind an escaping symlinked
// .claude/agents/*.md must degrade the scan rather than read as a clean,
// empty one. The link target is absolute, so os.Root refuses it during
// discovery and the tally comes from that PathError, not from the adapter's
// own non-regular-file refusal, which dedupes into the same file bucket.
func TestBinaryE2E_EscapingSymlinkedAgentCountsAsUnreadable(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outside := t.TempDir()
	outsideAgent := filepath.Join(outside, "exfil.md")
	if err := os.WriteFile(outsideAgent, []byte("---\nname: exfil\ntools: [Bash, Read]\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude", "agents"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideAgent, filepath.Join(root, ".claude", "agents", "linked.md")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()

	code := 0
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if runErr != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", runErr, errBuf.String())
	}

	out, errOut := outBuf.String(), errBuf.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the escaping symlink hides the only source)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if claimsACleanScan(out) {
		t.Fatalf("stdout must NOT read as a clean scan when a Bash-capable agent was hidden behind an escaping symlink\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must report a degraded scan for the escaping symlinked agent\nstdout:\n%s", out)
	}
	if got := parseUnreadableCount(t, out); got != 1 {
		t.Fatalf("footer counts %d unreadable sources, want 1: the escaping symlink is a source the scan never read, not one it read and could not parse\nstdout:\n%s\nstderr:\n%s", got, out, errOut)
	}
}

func TestBinaryE2E_RootFatalStaysTwo(t *testing.T) {
	bin := buildAgentauditBinary(t)
	assertBinaryExitCode(t, bin, 2, "/definitely/not/here/agentaudit-e2e-fixture")
}

// --fail-on-warning is not a flag. Cobra rejects an unknown flag as a
// usage fault, so exit 2 is the proof.
func TestBinaryE2E_FailOnWarningIsNotAFlag(t *testing.T) {
	bin := buildAgentauditBinary(t)
	assertBinaryExitCode(t, bin, 2, "--fail-on-warning", ".")
}

func assertBinaryExitCode(t *testing.T, bin string, want int, args ...string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	exitErr, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}
	got := 0
	if ok {
		got = exitErr.ExitCode()
	}
	if got != want {
		t.Fatalf("%v exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", args, got, want, stdout.String(), stderr.String())
	}
}
