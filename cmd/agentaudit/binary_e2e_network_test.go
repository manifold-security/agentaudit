package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	agentauditBinaryOnce sync.Once
	agentauditBinaryPath string
	agentauditBinaryErr  error
	agentauditBinaryDir  string
)

// A failed build is fatal rather than a skip: `go test` already built this
// package, so the failure is in the tree, not in the environment.
func buildAgentauditBinary(t *testing.T) string {
	t.Helper()

	agentauditBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "agentaudit-e2e-")
		if err != nil {
			agentauditBinaryErr = fmt.Errorf("os.MkdirTemp: %w", err)
			return
		}
		agentauditBinaryDir = dir

		bin := filepath.Join(dir, "agentaudit-e2e")
		cmd := exec.Command("go", "build", "-o", bin, ".")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			agentauditBinaryErr = fmt.Errorf("go build -o %s . failed: %w\n%s", bin, err, out)
			return
		}
		agentauditBinaryPath = bin
	})

	if agentauditBinaryErr != nil {
		t.Fatalf("%v", agentauditBinaryErr)
	}
	return agentauditBinaryPath
}

// resolveFixture returns the absolute path of a committed fixture directory
// and fails the test when nothing exists there: a missing fixture would
// otherwise scan as a clean tree and read as a passing test.
func resolveFixture(t *testing.T, path string) string {
	t.Helper()

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixture %q not found: %v", abs, err)
	}
	return abs
}

// TestMain owns the shared binary's build directory because that directory
// is process-scoped rather than t.TempDir()-scoped: the binary outlives
// whichever test happened to build it.
func TestMain(m *testing.M) {
	code := m.Run()
	if agentauditBinaryDir != "" {
		os.RemoveAll(agentauditBinaryDir)
	}
	os.Exit(code)
}

// networkEgressFixture is a Claude Code project whose settings env block
// redirects the agent's outbound traffic.
const networkEgressFixture = "../../testdata/benign/claude-egress"

// The compiled binary prints the fixture's env-var findings with their
// concrete values and exits non-zero, so an egress redirect is visible in
// the artifact users run rather than only through in-process test wiring.
func TestBinaryE2E_EnvVarFindings(t *testing.T) {
	bin := buildAgentauditBinary(t)

	absFixture := resolveFixture(t, networkEgressFixture)

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
		"https://proxy.example.com",
		"http://192.0.2.1:8080",
		"--require /tmp/inject.js",
	}
	for _, want := range wantValues {
		if !strings.Contains(stdout, want) {
			t.Errorf("binary stdout missing expected value %q\nfull stdout:\n%s", want, stdout)
		}
	}
	for _, header := range []string{"network-access:", "code-execution:"} {
		if !strings.Contains(stdout, header) {
			t.Errorf("binary stdout missing %q group header\nfull stdout:\n%s", header, stdout)
		}
	}
}

// -V and --version report version info and exit 0 on the compiled binary, so
// the non-zero exit a scan uses to signal findings does not leak into an
// informational flag.
func TestBinaryE2E_VersionFlagUnaffected(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, flag := range []string{"-V", "--version"} {
		t.Run(flag, func(t *testing.T) {
			cmd := exec.Command(bin, flag)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s failed: %v\n%s", flag, err, out)
			}
			if !strings.Contains(string(out), "agentaudit ") {
				t.Errorf("%s stdout = %q, want it to contain \"agentaudit \"", flag, out)
			}
		})
	}
}
