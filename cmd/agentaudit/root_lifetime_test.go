package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
)

// countingOpener stands in for openTarget so a test can assert fd lifetime
// without a real os.Root.
type countingOpener struct {
	mu          sync.Mutex
	byPath      map[string]fs.FS
	opens       int
	closes      int
	currentOpen int
	peakOpen    int
}

func (c *countingOpener) open(path string) (fs.FS, func() error, error) {
	fsys, ok := c.byPath[path]
	if !ok {
		return nil, nil, fmt.Errorf("agentaudit: no target fixture for %q", path)
	}

	c.mu.Lock()
	c.opens++
	c.currentOpen++
	if c.currentOpen > c.peakOpen {
		c.peakOpen = c.currentOpen
	}
	c.mu.Unlock()

	var closed bool
	closer := func() error {
		c.mu.Lock()
		if !closed {
			closed = true
			c.closes++
			c.currentOpen--
		}
		c.mu.Unlock()
		return nil
	}
	return fsys, closer, nil
}

func withCountingOpener(t *testing.T, byPath map[string]fs.FS) *countingOpener {
	t.Helper()
	c := &countingOpener{byPath: byPath}
	original := openTarget
	openTarget = c.open
	t.Cleanup(func() { openTarget = original })
	return c
}

// A leaked root file descriptor compounds across targets and recursive
// projects, so every path through run() must close what it opened.
func TestRun_ClosesOneRootPerTarget(t *testing.T) {
	t.Run("three targets", func(t *testing.T) {
		fixtures := map[string]fs.FS{
			"a": fstest.MapFS{},
			"b": fstest.MapFS{},
			"c": fstest.MapFS{},
		}
		c := withCountingOpener(t, fixtures)

		var stdout, stderr bytes.Buffer
		if got := run([]string{"a", "--scan-dir", "b", "--scan-dir", "c"}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
		}
		if c.opens != 3 || c.closes != 3 {
			t.Fatalf("opens=%d closes=%d, want 3 and 3", c.opens, c.closes)
		}
		if c.peakOpen != 1 {
			t.Fatalf("peakOpen=%d, want 1 (roots opened and closed sequentially)", c.peakOpen)
		}
	})

	t.Run("recursive container opens one root for every project", func(t *testing.T) {
		container := fstest.MapFS{
			"proja/.mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{}}`)},
			"projb/.mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{}}`)},
		}
		c := withCountingOpener(t, map[string]fs.FS{"container": container})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"container", "-r"}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 (one root shared across every project)", c.opens, c.closes)
		}
	})

	t.Run("scan error still closes the root", func(t *testing.T) {
		c := withCountingOpener(t, map[string]fs.FS{"a": fstest.MapFS{}})
		withScan(t, func(fs.FS, func(error)) (finding.Report, error) {
			return finding.Report{}, fmt.Errorf("boom")
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"a"}, &stdout, &stderr); got != 2 {
			t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 even when scan errors", c.opens, c.closes)
		}
	})

	t.Run("recursive scan error still closes the root", func(t *testing.T) {
		c := withCountingOpener(t, map[string]fs.FS{"a": fstest.MapFS{}})
		withScanRecursive(t, func(fs.FS, func(error)) ([]agentaudit.ProjectReport, error) {
			return nil, fmt.Errorf("boom")
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"a", "-r"}, &stdout, &stderr); got != 2 {
			t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 even when the recursive scan errors", c.opens, c.closes)
		}
	})

	// The global target closes its root via explicit calls rather than
	// defer, so each branch below exercises one of those call sites.
	t.Run("global target with a declared entry present closes its root", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		c := withCountingOpener(t, map[string]fs.FS{
			".":  fstest.MapFS{},
			home: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte("{}")}},
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"--global-config"}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 (the global target alone)", c.opens, c.closes)
		}
	})

	t.Run("global target scanGlobal error still closes its root", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		c := withCountingOpener(t, map[string]fs.FS{
			".":  fstest.MapFS{},
			home: fstest.MapFS{".claude/settings.json": &fstest.MapFile{}},
		})
		withScanGlobal(t, func(fs.FS, func(error)) (finding.Report, error) {
			return finding.Report{}, fmt.Errorf("boom")
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"--global-config"}, &stdout, &stderr); got != 2 {
			t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 even when scanGlobal errors", c.opens, c.closes)
		}
	})

	t.Run("global target with no declared entry present still closes its root", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		c := withCountingOpener(t, map[string]fs.FS{
			".":  fstest.MapFS{},
			home: fstest.MapFS{},
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"--global-config"}, &stdout, &stderr); got != 0 {
			t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
		}
		if c.opens != 1 || c.closes != 1 {
			t.Fatalf("opens=%d closes=%d, want 1 and 1 (the global root opens and closes even with nothing present)", c.opens, c.closes)
		}
	})
}
