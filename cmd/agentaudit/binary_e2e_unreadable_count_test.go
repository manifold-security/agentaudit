package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sink's merged tally through the real binary: a json consumer, who
// never sees the stderr lines that explain the fault, is told one escaping
// source is one missed source.
func TestBinaryE2E_OneEscapingSourceCountsAsOneUnreadableSource(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.Symlink("/nonexistent-abs/settings.json", filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, root, "-o", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (an escaping source leaves the scan incomplete)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	var docs []countsDocument
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("decoding -o json stdout: %v\nstdout:\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1\nstdout:\n%s", len(docs), stdout)
	}
	c := docs[0].Counts
	if c.UnreadableSources != 1 {
		t.Fatalf("counts.unreadableSources = %d, want 1 (one file is one unreadable source)\nstdout:\n%s\nstderr:\n%s", c.UnreadableSources, stdout, stderr)
	}
	if c.UnparsedSources != 0 {
		t.Fatalf("counts.unparsedSources = %d, want 0 (the file was never read)\nstdout:\n%s", c.UnparsedSources, stdout)
	}

	// Merging the tally does not merge the diagnostics.
	warnings := strings.Count(stderr, "warning: ")
	if warnings != 2 {
		t.Fatalf("stderr holds %d warning lines, want 2 (both layers still explain themselves)\nstderr:\n%s", warnings, stderr)
	}
	for _, want := range []string{"discover: ", "parse claude-code: "} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing the %q layer's warning\nstderr:\n%s", want, stderr)
		}
	}
}
