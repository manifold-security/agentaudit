package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const bundledPayloadFixture = "../../testdata/malicious/claude-bundled-payload"

func TestBinaryE2E_BundledPayloadFindings(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(bundledPayloadFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", bundledPayloadFixture, err)
	}
	if _, err := os.Stat(absFixture); err != nil {
		t.Fatalf("fixture %q not found: %v", absFixture, err)
	}

	cmd := exec.Command(bin)
	cmd.Dir = absFixture
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\n%s", err, out)
	}
	if err == nil {
		t.Fatalf("binary exited 0, want non-zero (findings are present)\n%s", out)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("binary ExitCode() = 0, want non-zero\n%s", out)
	}

	stdout := string(out)
	// No owner names orphan.py — SKILL.md wires only validate.sh — yet a
	// payload shipped with the skill stays runnable, so it must surface.
	wantValues := []string{
		".claude/skills/demo/scripts/validate.sh",
		".claude/skills/demo/scripts/orphan.py",
		".claude/commands/tool",
	}
	for _, want := range wantValues {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing expected value %q\nfull stdout:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stdout, "code-execution:") {
		t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", "code-execution:", stdout)
	}
	if strings.Contains(stdout, "reference.md") {
		t.Errorf("binary stdout must not mention reference.md (never a payload)\nfull stdout:\n%s", stdout)
	}
}
