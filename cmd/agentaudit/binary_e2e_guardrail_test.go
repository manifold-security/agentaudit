package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const guardrailFixture = "../../testdata/malicious/claude-guardrail"

// The rule's host-access annotation lives in finding.Message, which
// the pretty reporter prints only under --explain, so this test asserts the
// default surface;
// TestScanRealGuardrailFixtureSurfacesSandboxPermissionsAndMCPSignals asserts
// Finding.Message in process.
func TestBinaryE2E_GuardrailFindings(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture, err := filepath.Abs(guardrailFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", guardrailFixture, err)
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
	wantValues := []string{
		"/var/run/docker.sock",
		"/tmp/app.sock",
		"acceptEdits",
		"memory",
	}
	for _, want := range wantValues {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing expected value %q\nfull stdout:\n%s", want, stdout)
		}
	}
	for _, want := range []string{"sandbox:", "permissions:"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", want, stdout)
		}
	}
}
