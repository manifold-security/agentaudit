package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unreadableHookCommandAgent declares a hook whose command is a list where
// the schema wants a string. The group survives with a blank command (see
// hookGroupsFromNode), so the file's declaration is lost with nothing left to
// report.
const unreadableHookCommandAgent = "---\n" +
	"name: r\n" +
	"hooks:\n" +
	"  PreToolUse:\n" +
	"    - hooks:\n" +
	"        - type: command\n" +
	"          command: [evil.sh]\n" +
	"---\n" +
	"b\n"

// twoUnreadableKeysAgent puts more than one undecodable key in a single file,
// so the per-source count can be checked against the file, not the key.
const twoUnreadableKeysAgent = "---\n" +
	"name: [r]\n" +
	"permissionMode: {mode: bypassPermissions}\n" +
	"---\n" +
	"b\n"

// readableHookAgent differs from the repro only in the value the scanner
// could read, so the silent-when-nothing-was-lost half is checked against it.
const readableHookAgent = "---\n" +
	"name: r\n" +
	"hooks:\n" +
	"  PreToolUse:\n" +
	"    - hooks:\n" +
	"        - type: command\n" +
	"          command: evil.sh\n" +
	"---\n" +
	"b\n"

func writeAgentFile(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".claude", "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func unparsedCount(t *testing.T, bin, root string) countsDocument {
	t.Helper()
	stdout, stderr, _ := runBinary(t, bin, root, "-o", "json")
	var docs []countsDocument
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("decoding -o json stdout: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1\nstdout:\n%s", len(docs), stdout)
	}
	return docs[0]
}

// A key the scanner could not decode must degrade the scan exactly as a
// whole-file parse failure does. Reporting zero capabilities AND no
// degradation is the false clean this asserts against: the run then reads as
// an affirmative clean bill of health over a hook command it never read.
func TestBinaryE2E_UnreadableFrontmatterKeyDegradesInsteadOfReadingClean(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	writeAgentFile(t, root, "a.md", unreadableHookCommandAgent)

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (an undecodable key leaves the scan incomplete)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if claimsACleanScan(stdout) {
		t.Errorf("stdout must NOT read as a clean empty scan\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Errorf("stdout missing the unparsed SCAN INCOMPLETE line\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "· 1 unparsed source\n") {
		t.Errorf("stdout missing the unparsed footer suffix\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "a.md") {
		t.Errorf("stderr must name the file whose key was lost\nstderr:\n%s", stderr)
	}
	// The line yaml.v3 reports is relative to the frontmatter block, not to
	// the file: line 6 of the block is line 7 of a.md.
	if !strings.Contains(stderr, "line 6") {
		t.Errorf("stderr must name the offending line\nstderr:\n%s", stderr)
	}

	if got := unparsedCount(t, bin, root).Counts; got.UnparsedSources != 1 || got.UnreadableSources != 0 {
		t.Errorf("counts = %+v, want unparsedSources 1 and unreadableSources 0 (the file was read)", got)
	}
}

// One source is counted once however many of its keys were lost.
func TestBinaryE2E_TwoUnreadableKeysInOneFileCountOneUnparsedSource(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	writeAgentFile(t, root, "a.md", twoUnreadableKeysAgent)

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "· 1 unparsed source\n") {
		t.Errorf("stdout must count the file once, not once per key\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "name") || !strings.Contains(stderr, "permissionMode") {
		t.Errorf("the single warning must name both lost keys\nstderr:\n%s", stderr)
	}
	if got := unparsedCount(t, bin, root).Counts; got.UnparsedSources != 1 {
		t.Errorf("counts.unparsedSources = %d, want 1", got.UnparsedSources)
	}
}

// The other half of the contract: a file whose keys all decoded, and whose
// absent keys are simply absent, must stay silent. Warning here would make
// every ordinary config read as a degraded scan.
func TestBinaryE2E_ReadableAgentDegradesNothing(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	writeAgentFile(t, root, "a.md", readableHookAgent)

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the hook is a finding)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty for a file with nothing lost", stderr)
	}
	if strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Errorf("stdout must not degrade a scan that lost nothing\nstdout:\n%s", stdout)
	}
	if got := unparsedCount(t, bin, root).Counts; got.UnparsedSources != 0 {
		t.Errorf("counts.unparsedSources = %d, want 0", got.UnparsedSources)
	}
}
