package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recursiveDegradedFixture(t *testing.T, mcp string) string {
	t.Helper()
	root := t.TempDir()

	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatalf("mkdir proj: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".mcp.json"), []byte(mcp), 0o644); err != nil {
		t.Fatalf("write proj/.mcp.json: %v", err)
	}

	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocked/file.txt: %v", err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("chmod blocked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	return root
}

// A genuine chmod-000 read failure, not a synthetic fs.FS stub, must degrade
// the container's own block under -r while a sibling project's block keeps
// rendering, and the degradation exits 1 whether or not the project has a
// finding.
func TestBinaryE2E_RecursiveScanDegradesContainerAlongsideReadableProject(t *testing.T) {
	bin := buildAgentauditBinary(t)

	tests := []struct {
		name string
		mcp  string
	}{
		{"clean project", `{}`},
		{"project with a finding", `{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipUnlessPermissionBitsEnforced(t)
			root := recursiveDegradedFixture(t, tt.mcp)

			stdout, _, code := runBinary(t, bin, root, "-r", ".")
			if code != 1 {
				t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, stdout)
			}
			if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be read") {
				t.Fatalf("stdout must contain the single-source SCAN INCOMPLETE banner for the degraded container block\nstdout:\n%s", stdout)
			}
			if !strings.Contains(stdout, "agentaudit · ./proj") && !strings.Contains(stdout, "agentaudit · proj") {
				t.Fatalf("stdout must render the readable project's own block\nstdout:\n%s", stdout)
			}
		})
	}
}

// An unparsable nested project fails a -r run although the container's own
// block, rendered first, is clean.
func TestBinaryE2E_RecursiveDegradedOnlyInLastProjectExits1(t *testing.T) {
	bin := buildAgentauditBinary(t)

	tests := []struct {
		name       string
		nested     string
		wantCode   int
		incomplete bool
	}{
		{"unparsable nested project", `{`, 1, true},
		{"clean nested project", `{}`, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
				t.Fatalf("mkdir sub: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(`{}`), 0o644); err != nil {
				t.Fatalf("write .mcp.json: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, "sub", ".mcp.json"), []byte(tt.nested), 0o644); err != nil {
				t.Fatalf("write sub/.mcp.json: %v", err)
			}

			stdout, stderr, code := runBinary(t, bin, root, "-r", ".")
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			subIdx := strings.Index(stdout, "agentaudit · sub")
			if subIdx == -1 {
				t.Fatalf("stdout has no block headed by sub\nstdout:\n%s", stdout)
			}
			if strings.Contains(stdout[:subIdx], "SCAN INCOMPLETE") {
				t.Fatalf("the container's block, rendered before sub's, must be complete\nstdout:\n%s", stdout)
			}
			if got := strings.Contains(stdout[subIdx:], "SCAN INCOMPLETE: 1 source could not be parsed"); got != tt.incomplete {
				t.Fatalf("sub's block reports the unparsed source = %v, want %v\nstdout:\n%s", got, tt.incomplete, stdout)
			}
		})
	}
}
