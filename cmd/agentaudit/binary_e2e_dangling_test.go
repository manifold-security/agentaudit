package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dangling .claude directory link is warned but leaves the scan complete,
// so the run exits 0, plain and under -r. The same dangling link at .mcp.json,
// a file the adapter refuses to read, is the arm that renders SCAN INCOMPLETE
// and exits 1.
func TestBinaryE2E_DanglingLinkExitCodeFollowsWhetherItIsCounted(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, tc := range []struct {
		link       string
		code       int
		incomplete bool
	}{
		{".claude", 0, false},
		{".mcp.json", 1, true},
	} {
		for _, args := range [][]string{nil, {"-r", "."}} {
			t.Run(strings.Join(append([]string{tc.link}, args...), " "), func(t *testing.T) {
				root := t.TempDir()
				if err := os.Symlink("missing", filepath.Join(root, tc.link)); err != nil {
					t.Skipf("symlinks unavailable on this platform: %v", err)
				}

				stdout, stderr, code := runBinary(t, bin, root, args...)
				if code != tc.code {
					t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.code, stdout, stderr)
				}
				if !strings.Contains(stderr, "warning:") || !strings.Contains(stderr, tc.link) {
					t.Fatalf("stderr = %q, want a warning naming %s", stderr, tc.link)
				}
				if got := strings.Contains(stdout, "SCAN INCOMPLETE"); got != tc.incomplete {
					t.Fatalf("SCAN INCOMPLETE = %v, want %v\nstdout:\n%s", got, tc.incomplete, stdout)
				}
			})
		}
	}
}
