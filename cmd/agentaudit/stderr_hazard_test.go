package main

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
)

// A hostile project directory name or a scanned config value can provoke a
// warning embedding a control byte; the CLI must not write it raw.
func TestRun_Warning_EscapesHazardByteInStderr(t *testing.T) {
	withScan(t, func(fsys fs.FS, warn func(error)) (finding.Report, error) {
		warn(errors.New("discover: bad\x1b[2Jdir: read failed"))
		return finding.NewReport(nil), nil
	})

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
	}
	got := stderr.String()

	if !strings.Contains(got, "warning:") {
		t.Fatalf("stderr = %q, want it to contain the \"warning:\" prefix (execution proof the warn call ran)", got)
	}
	if !strings.Contains(got, `bad\x1b[2Jdir`) {
		t.Fatalf("stderr = %q, want it to contain the escaped hazard spelling", got)
	}
	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("stderr = %q, want no raw ESC byte", got)
	}
}

// A scan error carries the same scanned-tree text to a different run() sink
// than a warning does.
func TestRun_ScanError_EscapesHazardByteInStderr(t *testing.T) {
	withScan(t, func(fsys fs.FS, warn func(error)) (finding.Report, error) {
		return finding.Report{}, errors.New("open bad\x1b[2Jdir: permission denied")
	})

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
	}
	got := stderr.String()

	if !strings.Contains(got, "agentaudit:") {
		t.Fatalf("stderr = %q, want it to contain the \"agentaudit:\" error prefix (execution proof the error path ran)", got)
	}
	if !strings.Contains(got, `bad\x1b[2Jdir`) {
		t.Fatalf("stderr = %q, want it to contain the escaped hazard spelling", got)
	}
	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("stderr = %q, want no raw ESC byte", got)
	}
}

// An error already carrying agentaudit's own prefix — the shape an
// engine-originated error has — reaches the branch that adds no second
// prefix, which has its own escape call to exercise.
func TestRun_ScanError_PrefixedErrorEscapesHazardByteInStderr(t *testing.T) {
	withScan(t, func(fsys fs.FS, warn func(error)) (finding.Report, error) {
		return finding.Report{}, errors.New("agentaudit: discover: bad\x1b[2Jdir: permission denied")
	})

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
	}
	got := stderr.String()

	if n := strings.Count(got, "agentaudit:"); n != 1 {
		t.Fatalf("stderr = %q, want exactly one \"agentaudit:\" prefix (proof the already-prefixed branch ran, not the branch that adds a second one), got %d", got, n)
	}
	if !strings.Contains(got, `bad\x1b[2Jdir`) {
		t.Fatalf("stderr = %q, want it to contain the escaped hazard spelling", got)
	}
	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("stderr = %q, want no raw ESC byte", got)
	}
}

func TestRun_Warning_HazardByteDoesNotReachStdout(t *testing.T) {
	withScan(t, func(fsys fs.FS, warn func(error)) (finding.Report, error) {
		warn(errors.New("discover: bad\x1b[2Jdir: read failed"))
		return finding.NewReport(nil), nil
	})

	var stdout, stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0", got)
	}
	if !strings.Contains(stderr.String(), `bad\x1b[2Jdir`) {
		t.Fatalf("stderr = %q, want the escaped hazard spelling (execution proof the warn call ran)", stderr.String())
	}
	if strings.ContainsRune(stdout.String(), '\x1b') {
		t.Fatalf("stdout = %q, want no ESC byte from a warning that belongs on stderr only", stdout.String())
	}
}
