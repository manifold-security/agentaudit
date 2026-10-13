package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runTarget passes the target positionally rather than through the working
// directory: Getwd() answers with the canonical spelling, silently repairing
// a fixture whose link text is not canonical.
func runTarget(t *testing.T, bin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the scan never returned within the deadline\nstdout so far:\n%s\nstderr so far:\n%s", outBuf.String(), errBuf.String())
	}
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, errBuf.String())
	}
	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

func TestBinaryE2E_AbsoluteInRootSymlinkedClaudeDirectoryIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := canonicalDir(t)
	realDir := filepath.Join(root, "dotfiles", "claude")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", realDir, err)
	}
	writeHookSettings(t, filepath.Join(realDir, "settings.json"), "notify.sh")
	if err := os.Symlink(realDir, filepath.Join(root, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	out, errOut, code := runTarget(t, bin, root)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the hook behind the absolute symlink is a finding)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains \"SCAN INCOMPLETE\": the absolute symlink resolves entirely in-tree\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout must report the hook command notify.sh\nstdout:\n%s", out)
	}
}

func TestBinaryE2E_AbsoluteInRootSymlinkedSettingsFileIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := canonicalDir(t)
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	realDir := filepath.Join(root, "dotfiles")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", realDir, err)
	}
	realFile := filepath.Join(realDir, "settings.json")
	writeHookSettings(t, realFile, "notify.sh")
	if err := os.Symlink(realFile, filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	out, errOut, code := runTarget(t, bin, root)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains \"SCAN INCOMPLETE\" for an in-root absolute file symlink\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout must report the hook command notify.sh\nstdout:\n%s", out)
	}
}

func TestBinaryE2E_AbsoluteOutOfRootSymlinkedClaudeStillDegrades(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outside := canonicalDir(t)
	writeHookSettings(t, filepath.Join(outside, "settings.json"), "outside.sh")
	root := canonicalDir(t)
	if err := os.Symlink(outside, filepath.Join(root, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	out, errOut, code := runTarget(t, bin, root)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a refusal degrades, it never escalates)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, "outside.sh") {
		t.Fatalf("stdout names the out-of-tree hook command, want it never surfaced\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\" for a refused escaping symlink\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
	if !strings.Contains(errOut, ".claude") {
		t.Fatalf("stderr must name the refused path in the caller's own spelling\nstderr:\n%s", errOut)
	}
}

func TestBinaryE2E_GlobalConfig_AbsoluteInBaseSymlinkIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := canonicalDir(t)
	real := filepath.Join(home, "dotfiles", "claude")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", real, err)
	}
	if err := os.WriteFile(filepath.Join(real, "settings.json"), []byte(globalConfigSettingsJSON), 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout does not contain the global block header for %q\nstdout:\n%s", home, out)
	}
	if !strings.Contains(out, ".claude/settings.json") {
		t.Fatalf("stdout does not attribute the finding to .claude/settings.json provenance\nstdout:\n%s", out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for an absolute in-Base symlink\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
}

// The absolute spelling of a self-referential link must render the same
// block shape the relative spelling does.
func TestBinaryE2E_AbsoluteSelfLoopUnderRecursiveMatchesTheRelativeSpelling(t *testing.T) {
	bin := buildAgentauditBinary(t)

	build := func(t *testing.T, absolute bool) string {
		container := canonicalDir(t)
		proj := filepath.Join(container, "proj")
		if err := os.MkdirAll(proj, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", proj, err)
		}
		writeFindingMCP(t, filepath.Join(proj, ".mcp.json"))
		target := "loop"
		if absolute {
			target = filepath.Join(proj, "loop")
		}
		if err := os.Symlink(target, filepath.Join(proj, "loop")); err != nil {
			t.Skipf("symlinks unavailable on this platform: %v", err)
		}
		return container
	}

	absOut, absErr, absCode := runTarget(t, bin, "-r", build(t, true))
	relOut, relErr, relCode := runTarget(t, bin, "-r", build(t, false))

	if absCode != relCode {
		t.Fatalf("absolute spelling exit code = %d, relative = %d, want them equal\nabsolute stdout:\n%s\nrelative stdout:\n%s", absCode, relCode, absOut, relOut)
	}
	if got, want := strings.Count(absOut, "agentaudit ·"), strings.Count(relOut, "agentaudit ·"); got != want {
		t.Fatalf("absolute spelling rendered %d blocks, relative rendered %d, want them equal\nabsolute stdout:\n%s\nrelative stdout:\n%s", got, want, absOut, relOut)
	}
	if got, want := strings.Contains(absOut, "SCAN INCOMPLETE"), strings.Contains(relOut, "SCAN INCOMPLETE"); got != want {
		t.Fatalf("absolute spelling SCAN INCOMPLETE = %v, relative = %v, want them equal\nabsolute stdout:\n%s\nrelative stdout:\n%s", got, want, absOut, relOut)
	}
	if !strings.Contains(absOut, "mcpServer fs") {
		t.Fatalf("stdout must still report the project's own capability beside the loop\nstdout:\n%s", absOut)
	}
	if absErr == "" || relErr == "" {
		t.Fatalf("both spellings must warn about the loop\nabsolute stderr:\n%s\nrelative stderr:\n%s", absErr, relErr)
	}
	if !strings.Contains(absErr, "loop") {
		t.Fatalf("stderr must name the looping path in the caller's own spelling\nstderr:\n%s", absErr)
	}
}
