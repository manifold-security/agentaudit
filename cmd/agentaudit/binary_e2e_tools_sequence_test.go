package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The delta over the adapter-level tests is the process exit code: a lost
// capability renders as exit 0, indistinguishable from a genuinely clean
// scan.
func TestBinaryE2E_SequenceToolsAgentStillReportsPermissionMode(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	agents := filepath.Join(root, ".claude", "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir .claude/agents: %v", err)
	}
	agent := "---\n" +
		"name: sequence-tools\n" +
		"tools: [\"Read\", \"Bash\"]\n" +
		"permissionMode: acceptEdits\n" +
		"---\nbody\n"
	if err := os.WriteFile(filepath.Join(agents, "sequence-tools.md"), []byte(agent), 0o644); err != nil {
		t.Fatalf("write agent: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
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
		t.Fatalf("exit code = %d, want 1 (the acceptEdits capability is present)\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if !strings.Contains(out, "acceptEdits") {
		t.Errorf("stdout must report the acceptEdits mode\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "sequence-tools.md") {
		t.Errorf("stdout must name the agent file as provenance\nstdout:\n%s", out)
	}
	if claimsACleanScan(out) {
		t.Errorf("stdout reads as a clean scan, want the finding reported\nstdout:\n%s", out)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty (the frontmatter is well-formed)", stderr.String())
	}
}
