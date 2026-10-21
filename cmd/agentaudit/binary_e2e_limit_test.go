package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The built binary applies the default file limit to a tree on disk: its
// refusal exits 1 with the hint naming the flag, while a malformed file no
// limit refused exits 1 with no hint.
func TestBinaryE2E_ALimitRefusalExitsOne(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, tc := range []struct {
		name     string
		settings string
		warned   string
		hint     bool
	}{
		{"file past the default limit", "{}" + strings.Repeat(" ", 512<<10), ".claude/settings.json: over the 512 KiB limit for one file; not scanned", true},
		{"malformed file", "{not valid json", ".claude/settings.json: invalid character", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
				t.Fatalf("mkdir .claude: %v", err)
			}
			if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(tc.settings), 0o644); err != nil {
				t.Fatalf("write settings.json: %v", err)
			}

			stdout, stderr, code := runBinary(t, bin, root)
			if code != 1 {
				t.Errorf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.warned) {
				t.Errorf("stderr = %q, want a warning naming %q", stderr, tc.warned)
			}
			if got := strings.Contains(stderr, "hint: raise --max-file-size"); got != tc.hint {
				t.Errorf("hint naming --max-file-size = %v, want %v\nstderr:\n%s", got, tc.hint, stderr)
			}
		})
	}
}
