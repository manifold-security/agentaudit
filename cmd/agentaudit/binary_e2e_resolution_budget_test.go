package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A container holding more in-tree symlinked aliases than discovery's
// resolution budget allows must degrade honestly rather than escalate.
func TestBinaryE2E_SymlinkResolutionBudgetExhaustionDegradesHonestly(t *testing.T) {
	bin := buildAgentauditBinary(t)

	container := t.TempDir()
	// aliasCount deliberately exceeds discovery's symlinkResolutionBudget.
	const aliasCount = 41
	for i := 0; i < aliasCount; i++ {
		target := filepath.Join(container, fmt.Sprintf("target%02d", i))
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", target, err)
		}
		writeFindingMCP(t, filepath.Join(target, ".mcp.json"))

		alias := filepath.Join(container, fmt.Sprintf("alias%02d", i))
		if err := os.Symlink(fmt.Sprintf("target%02d", i), alias); err != nil {
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

	out, errOut := stdout.String(), stderr.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings from the projects reached within budget), not escalated by the exhaustion\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\" once the budget exhausts\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "unreadable source") {
		t.Fatalf("stdout must contain the unreadable-source footer suffix\nstdout:\n%s", out)
	}
	if !strings.Contains(errOut, "symlink resolution budget exhausted") {
		t.Fatalf("stderr must name the budget-exhaustion warning\nstderr:\n%s", errOut)
	}
	if !strings.Contains(errOut, "alias") {
		t.Fatalf("stderr must name the unfollowed alias path\nstderr:\n%s", errOut)
	}
}
