package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// multiTargetProjectFixture's two projects each declare something the
// embedded ruleset flags.
func multiTargetProjectFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	proj1 := filepath.Join(root, "proj1", ".claude")
	if err := os.MkdirAll(proj1, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", proj1, err)
	}
	if err := os.WriteFile(filepath.Join(proj1, "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}}`), 0o644); err != nil {
		t.Fatalf("write proj1 settings.json: %v", err)
	}

	proj2 := filepath.Join(root, "proj2")
	if err := os.MkdirAll(proj2, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", proj2, err)
	}
	if err := os.WriteFile(filepath.Join(proj2, ".mcp.json"),
		[]byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`), 0o644); err != nil {
		t.Fatalf("write proj2 .mcp.json: %v", err)
	}

	return root
}

func cleanTargetDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// findings only in the first target still yields exit 1, guarding the exit
// fold against a mutation that inspects only the last block.
func TestBinaryE2E_MultiTarget_FindingsOnlyInFirstTargetExits1(t *testing.T) {
	bin := buildAgentauditBinary(t)
	dirty := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirty, ".mcp.json"),
		[]byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	clean := cleanTargetDir(t)

	stdout, stderr, code := runBinary(t, bin, ".", dirty, "--scan-dir", clean)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// An incomplete scan only in the last target still yields exit 1, guarding
// the exit fold against a mutation that inspects only the first block.
func TestBinaryE2E_MultiTarget_DegradedOnlyInLastTargetExits1(t *testing.T) {
	bin := buildAgentauditBinary(t)
	clean := cleanTargetDir(t)
	degraded := t.TempDir()
	if err := os.WriteFile(filepath.Join(degraded, ".mcp.json"), []byte(`{`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, ".", clean, "--scan-dir", degraded)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Fatalf("stdout must report the unparsed source of the last target\nstdout:\n%s", stdout)
	}
}

// a project three directory levels beneath a container is found under -r and
// its finding moves the exit code: enumeration has no depth bound.
func TestBinaryE2E_MultiTarget_RecursiveFindsProjectThreeLevelsDeepExits1(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", deep, err)
	}
	if err := os.WriteFile(filepath.Join(deep, ".mcp.json"),
		[]byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, root, "-r", ".")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// an empty --scan-dir value in any spelling is a usage fault: pflag's own
// String()/Conv round trip silently drops exactly one empty value if the flag
// is read back through GetStringArray instead of a bound variable.
func TestBinaryE2E_MultiTarget_EmptyScanDirValueExits2(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := cleanTargetDir(t)

	tests := []struct {
		name string
		args []string
	}{
		{"bare empty value", []string{"--scan-dir", ""}},
		{"equals-form empty value", []string{"--scan-dir="}},
		{"positional plus empty value", []string{"x", "--scan-dir", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runBinary(t, bin, root, tt.args...)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want no report rendered for a usage fault", stdout)
			}
		})
	}
}

func TestBinaryE2E_MultiTarget_RecursiveOverContainerYieldsPerProjectBlocksAndExit1(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := multiTargetProjectFixture(t)

	stdout, stderr, code := runBinary(t, bin, root, "-r", ".")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "agentaudit · ./proj1") && !strings.Contains(stdout, "agentaudit · proj1") {
		t.Fatalf("stdout missing a block headed by proj1\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "agentaudit · ./proj2") && !strings.Contains(stdout, "agentaudit · proj2") {
		t.Fatalf("stdout missing a block headed by proj2\nstdout:\n%s", stdout)
	}
}

func TestBinaryE2E_MultiTarget_SameContainerWithoutRecursiveYieldsOneBlock(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := multiTargetProjectFixture(t)

	stdout, stderr, code := runBinary(t, bin, root)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "proj1") || strings.Contains(stdout, "proj2") {
		t.Fatalf("stdout must carry no per-project block without -r\nstdout:\n%s", stdout)
	}
	if strings.Count(stdout, "agentaudit ·") != 1 {
		t.Fatalf("stdout must carry exactly one block\nstdout:\n%s", stdout)
	}
}

func TestBinaryE2E_MultiTarget_PositionalPlusScanDirDuplicateSpellingsDedupe(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	a := filepath.Join(root, "a")
	if err := os.MkdirAll(a, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", a, err)
	}

	stdout, stderr, code := runBinary(t, bin, root, "a", "--scan-dir", "./a", "--scan-dir", "a/")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if got := strings.Count(stdout, "agentaudit ·"); got != 1 {
		t.Fatalf("stdout has %d blocks, want exactly 1 (every spelling of \"a\" must dedupe)\nstdout:\n%s", got, stdout)
	}
}

func TestBinaryE2E_MultiTarget_FindingsOnlyInSecondTargetExits1(t *testing.T) {
	bin := buildAgentauditBinary(t)
	clean := cleanTargetDir(t)
	dirty := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirty, ".mcp.json"),
		[]byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, ".", clean, "--scan-dir", dirty)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// A permission fault with no finding exits 1, even beside a clean target.
func TestBinaryE2E_MultiTarget_DegradedPlusCleanNoFindingsExits1(t *testing.T) {
	skipUnlessPermissionBitsEnforced(t)
	bin := buildAgentauditBinary(t)
	degraded := degradedFixture(t, `{}`)
	clean := cleanTargetDir(t)

	stdout, stderr, code := runBinary(t, bin, ".", degraded, "--scan-dir", clean)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must report SCAN INCOMPLETE for the degraded target\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "no known agent config read") {
		t.Fatalf("stdout must still report a clean read of the clean target\nstdout:\n%s", stdout)
	}
}

func TestBinaryE2E_MultiTarget_BadScanDirTargetExits2WithNoReport(t *testing.T) {
	bin := buildAgentauditBinary(t)
	clean := cleanTargetDir(t)

	stdout, stderr, code := runBinary(t, bin, ".", clean, "--scan-dir", "/definitely/not/here/agentaudit-e2e")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want no report rendered for any target on a fatal fault", stdout)
	}
}

func TestBinaryE2E_MultiTarget_RecursiveOutputFilesWritesExactlyTwoDefaultNames(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := multiTargetProjectFixture(t)

	stdout, stderr, code := runBinary(t, bin, root, "-r", "-O", "all", ".")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", root, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	wantFiles := map[string]bool{"agentaudit-report.json": false, "agentaudit-report.md": false}
	for _, name := range names {
		if name == "proj1" || name == "proj2" {
			continue
		}
		if _, ok := wantFiles[name]; !ok {
			t.Fatalf("unexpected file %q written, want only the two default report filenames (dir listing: %v)", name, names)
		}
		wantFiles[name] = true
	}
	for name, found := range wantFiles {
		if !found {
			t.Fatalf("%s was not written (dir listing: %v)", name, names)
		}
	}

	data, err := os.ReadFile(filepath.Join(root, "agentaudit-report.json"))
	if err != nil {
		t.Fatalf("ReadFile(agentaudit-report.json) error = %v", err)
	}
	var docs []struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &docs); err != nil {
		t.Fatalf("Unmarshal(agentaudit-report.json) error = %v, content:\n%s", err, data)
	}
	if len(docs) != 2 {
		t.Fatalf("len(docs) = %d, want 2 (one per project block)\ncontent:\n%s", len(docs), data)
	}
}
