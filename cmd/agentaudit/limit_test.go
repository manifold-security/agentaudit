package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/limits"
)

// A refused file contributes no finding to flag it, yet the run exits 1; the
// scanner is the one this command builds, run over each tree in place of the
// opened directory.
func TestRun_ExitsOneWhenALimitRefusesAFile(t *testing.T) {
	commandHooks := strings.TrimSuffix(strings.Repeat(`{"type":"command","command":"x"},`, 10001), ",")
	overEntities := `{"hooks":{"PreToolUse":[{"hooks":[` + commandHooks + `]}]}}`

	overDepth := `{"z":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`

	oneFile := []byte(strings.Repeat(" ", 512<<10))
	overBudget := fstest.MapFS{".claude/agents/z.md": {Data: []byte(" ")}}
	for i := range 128 {
		overBudget[fmt.Sprintf(".claude/agents/a%03d.md", i)] = &fstest.MapFile{Data: oneFile}
	}

	realScan := scan
	for _, tc := range []struct {
		name   string
		tree   fstest.MapFS
		warned string
	}{
		{"over-size file", fstest.MapFS{".claude/settings.json": {Data: append([]byte("{}"), oneFile...)}}, ".claude/settings.json: over the 512 KiB limit for one file"},
		{"over-budget scan", overBudget, ".claude/agents/z.md: past the scan's 64 MiB read budget"},
		{"over-entity file", fstest.MapFS{".claude/settings.json": {Data: []byte(overEntities)}}, ".claude/settings.json: would take the scan past 10000 entities"},
		{"over-depth file", fstest.MapFS{".claude/settings.json": {Data: []byte(overDepth)}}, "exceeded max depth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withScan(t, func(_ fs.FS, warn func(error)) (finding.Report, error) { return realScan(tc.tree, warn) })

			var stdout, stderr bytes.Buffer
			if got := run(nil, &stdout, &stderr); got != 1 {
				t.Errorf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "warning: ") || !strings.Contains(stderr.String(), tc.warned) {
				t.Errorf("stderr = %q, want a warning naming %q", stderr.String(), tc.warned)
			}
		})
	}
}

// A limit refusal exits 1 whatever the scan counted: this report carries no
// unread or unparsed source, so the refusal alone sets the code. The same
// report beside a warning no limit raised is the arm that exits 0.
func TestRun_ALimitRefusalExitsOneWithNothingCounted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		warned error
		code   int
		hint   bool
	}{
		{"a limit refusal", fmt.Errorf("agentaudit: .claude/settings.json: %w", limits.ErrFileSize), 1, true},
		{"a warning no limit raised", errors.New("agentaudit: .claude/settings.json: simulated fault"), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withScan(t, func(_ fs.FS, warn func(error)) (finding.Report, error) {
				warn(tc.warned)
				return finding.NewReport(nil), nil
			})

			var stdout, stderr bytes.Buffer
			if got := run(nil, &stdout, &stderr); got != tc.code {
				t.Fatalf("run() = %d, want %d\nstdout: %s\nstderr: %s", got, tc.code, stdout.String(), stderr.String())
			}
			if got := strings.Contains(stderr.String(), "hint: raise --max-file-size"); got != tc.hint {
				t.Errorf("hint naming --max-file-size = %v, want %v\nstderr: %s", got, tc.hint, stderr.String())
			}
			if strings.Contains(stdout.String(), "SCAN INCOMPLETE") {
				t.Errorf("stdout = %q, want no SCAN INCOMPLETE from a report that counts nothing", stdout.String())
			}
		})
	}
}
