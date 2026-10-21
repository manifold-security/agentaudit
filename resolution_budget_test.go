package agentaudit_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

// The resolution budget lives in one Scan call's own state, never
// package-level: the fixture's findings sit behind a symlinked directory,
// so every call must reach them regardless of what ran before it in this
// binary. Comparing the two calls against each other would not do: a budget
// an earlier test exhausted misses them on both, identically.
func TestScanSymlinkResolutionBudgetIsPerCall(t *testing.T) {
	fsys := fstest.MapFS{
		"real-config/settings.json": &fstest.MapFile{Data: []byte(hookSettingsJSON("notify.sh"))},
		".claude":                   &fstest.MapFile{Data: []byte("real-config"), Mode: fs.ModeSymlink},
	}

	s := agentaudit.New()

	for _, call := range []string{"first", "second"} {
		report, err := s.Scan(fsys)
		if err != nil {
			t.Fatalf("%s Scan() error = %v, want nil", call, err)
		}
		if !report.HasFindings() {
			t.Fatalf("%s Scan() reported no findings, want the hook behind the symlinked .claude reported — a fresh per-call budget must resolve a symlinked directory regardless of prior calls in this process", call)
		}
		if got := report.UnreadableSources(); got != 0 {
			t.Fatalf("%s Scan() UnreadableSources() = %d, want 0 — one resolution is well within a fresh budget", call, got)
		}
	}
}

func hookSettingsJSON(command string) string {
	return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + command + `"}]}]}}`
}
