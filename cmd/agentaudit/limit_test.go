package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/finding"
)

// A refused file contributes no finding to flag it, so the refusal alone
// sets the exit code; the scanner is the one this command builds, run over
// each tree in place of the opened directory.
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
		want   int
	}{
		{"over-size file", fstest.MapFS{".claude/settings.json": {Data: append([]byte("{}"), oneFile...)}}, ".claude/settings.json: over the 512 KiB limit for one file", 1},
		{"over-budget scan", overBudget, ".claude/agents/z.md: past the scan's 64 MiB read budget", 1},
		{"over-entity file", fstest.MapFS{".claude/settings.json": {Data: []byte(overEntities)}}, ".claude/settings.json: would take the scan past 10000 entities", 1},
		{"over-depth file", fstest.MapFS{".claude/settings.json": {Data: []byte(overDepth)}}, "exceeded max depth", 1},
		{"malformed file", fstest.MapFS{".claude/settings.json": {Data: []byte("{not valid json")}}, ".claude/settings.json: invalid character", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withScan(t, func(_ fs.FS, warn func(error)) (finding.Report, error) { return realScan(tc.tree, warn) })

			var stdout, stderr bytes.Buffer
			if got := run(nil, &stdout, &stderr); got != tc.want {
				t.Errorf("run() = %d, want %d\nstdout: %s\nstderr: %s", got, tc.want, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "warning: ") || !strings.Contains(stderr.String(), tc.warned) {
				t.Errorf("stderr = %q, want a warning naming %q", stderr.String(), tc.warned)
			}
		})
	}
}
