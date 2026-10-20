package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The built binary applies the default file limit to a tree on disk and exits
// 1 on its refusal; a malformed file no limit refused leaves it at 0.
func TestBinaryE2E_ALimitRefusalExitsOne(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, tc := range []struct {
		name     string
		settings string
		warned   string
		want     int
	}{
		{"file past the default limit", "{}" + strings.Repeat(" ", 512<<10), ".claude/settings.json: over the 512 KiB limit for one file; not scanned", 1},
		{"malformed file", "{not valid json", ".claude/settings.json: invalid character", 0},
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
			if code != tc.want {
				t.Errorf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.warned) {
				t.Errorf("stderr = %q, want a warning naming %q", stderr, tc.warned)
			}
		})
	}
}
