package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A deliberate choice: aliases resolving to the identical real project each
// render their own block rather than being deduplicated. A visible duplicate
// costs a reader little; deduplicating by resolved target risks silently
// collapsing two DIFFERENT attacker-controlled paths sharing a target.
func TestBinaryE2E_SymlinkAliasesToTheSameProjectEachRenderTheirOwnBlock(t *testing.T) {
	bin := buildAgentauditBinary(t)

	container := t.TempDir()
	realProject := filepath.Join(container, "real-project")
	if err := os.MkdirAll(realProject, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", realProject, err)
	}
	writeFindingMCP(t, filepath.Join(realProject, ".mcp.json"))

	aliasNames := []string{"alias-a", "alias-b"}
	for _, alias := range aliasNames {
		if err := os.Symlink("real-project", filepath.Join(container, alias)); err != nil {
			t.Skipf("symlinks unavailable on this platform: %v", err)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, "-r")
	cmd.Dir = container
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}

	blockCount := strings.Count(out, "mcpServer fs")
	wantBlocks := 1 + len(aliasNames)
	if blockCount != wantBlocks {
		t.Fatalf("stdout renders the finding %d times, want %d (one for real-project plus one per alias, unresolved-target deduplication is deliberately not performed)\nstdout:\n%s", blockCount, wantBlocks, out)
	}
	for _, alias := range aliasNames {
		if !strings.Contains(out, "agentaudit · "+alias+"\n") {
			t.Fatalf("stdout has no block header for alias %q, want its own block despite sharing a target with real-project\nstdout:\n%s", alias, out)
		}
	}
}
