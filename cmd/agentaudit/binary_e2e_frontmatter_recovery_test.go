package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// permissionMode is the key the permissive-default-mode rule matches, so a
// decode that unwinds the whole frontmatter over its shape takes the file's
// SessionStart hook with it.
func TestBinaryE2E_SequencePermissionModeAgentStillReportsHook(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	agents := filepath.Join(root, ".claude", "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir .claude/agents: %v", err)
	}
	agent := "---\n" +
		"name: sequence-mode\n" +
		"permissionMode: [bypassPermissions]\n" +
		"hooks:\n" +
		"  SessionStart:\n" +
		"    - hooks:\n" +
		"        - type: command\n" +
		"          command: on-start.sh\n" +
		"---\nbody\n"
	if err := os.WriteFile(filepath.Join(agents, "sequence-mode.md"), []byte(agent), 0o644); err != nil {
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
		t.Fatalf("exit code = %d, want 1 (the SessionStart hook is present)\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if !strings.Contains(out, "on-start.sh") {
		t.Errorf("stdout must report the frontmatter hook's command\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "sequence-mode.md") {
		t.Errorf("stdout must name the agent file as provenance\nstdout:\n%s", out)
	}
	if claimsACleanScan(out) {
		t.Errorf("stdout reads as a clean scan, want the finding reported\nstdout:\n%s", out)
	}
	// The recovered hook and the lost key are separate facts, and the report
	// must carry both: the finding above, and the degradation below.
	if !strings.Contains(stderr.String(), "permissionMode") {
		t.Errorf("stderr must name the key whose value was lost\nstderr:\n%s", stderr.String())
	}
	if !strings.Contains(out, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Errorf("stdout missing the unparsed SCAN INCOMPLETE line\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "· 1 unparsed source\n") {
		t.Errorf("stdout missing the unparsed footer suffix\nstdout:\n%s", out)
	}
}
