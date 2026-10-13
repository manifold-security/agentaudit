package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A symlink to an ancestor directory is legitimately in-tree, so containment
// permits it; the containment root's own hop limit is what terminates the
// scan, surfacing as a read failure that degrades the report. No hop count
// is asserted here: the limit is implementation- and platform-dependent.
func TestBinaryE2E_SymlinkLoopTerminatesAndDegrades(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	aDir := root + "/a"
	if err := os.MkdirAll(aDir, 0o755); err != nil {
		t.Fatalf("mkdir a: %v", err)
	}
	if err := os.Symlink("..", aDir+"/up"); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	writeFindingMCP(t, root+"/.mcp.json")

	done := make(chan struct{})
	var stdout, stderr bytes.Buffer
	var runErr error
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	go func() {
		runErr = cmd.Run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("binary did not terminate within 10s scanning a symlink loop, want it to terminate honestly")
	}

	code := 0
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if runErr != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", runErr, stderr.String())
	}

	out, errOut := stdout.String(), stderr.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding still surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\" for the symlink loop\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "unreadable source") {
		t.Fatalf("stdout must contain the unreadable-source footer suffix\nstdout:\n%s", out)
	}
	if errOut == "" {
		t.Fatal("stderr is empty, want a warning naming the looping symlink")
	}
}
