package main

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// withOpenTarget swaps only the target's fs.FS, so the REAL scan runs behind
// the fixture rather than a stub.
func withOpenTarget(t *testing.T, byPath map[string]fs.FS) {
	t.Helper()
	original := openTarget
	openTarget = func(path string) (fs.FS, func() error, error) {
		fsys, ok := byPath[path]
		if !ok {
			return nil, nil, fmt.Errorf("agentaudit: no target fixture for %q", path)
		}
		return fsys, func() error { return nil }, nil
	}
	t.Cleanup(func() { openTarget = original })
}

func cleanTargetFS() fstest.MapFS {
	return fstest.MapFS{}
}

func findingTargetFS() fstest.MapFS {
	return fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)},
	}
}

func TestRun_MultiTarget_ExitCodeAggregatesAcrossTargets(t *testing.T) {
	tests := []struct {
		name     string
		fixtures map[string]fs.FS
		want     int
	}{
		{"both targets clean", map[string]fs.FS{"a": cleanTargetFS(), "b": cleanTargetFS()}, 0},
		{"findings only in the second target", map[string]fs.FS{"a": cleanTargetFS(), "b": findingTargetFS()}, 1},
		{"findings only in the first target", map[string]fs.FS{"a": findingTargetFS(), "b": cleanTargetFS()}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withOpenTarget(t, tt.fixtures)
			var stdout, stderr bytes.Buffer
			if got := run([]string{"a", "--scan-dir", "b"}, &stdout, &stderr); got != tt.want {
				t.Fatalf("run() = %d, want %d\nstdout: %s\nstderr: %s", got, tt.want, stdout.String(), stderr.String())
			}
		})
	}
}

// Asserting the array's length alone would pass even if both elements named
// the same block.
func TestRun_MultiTarget_OutputJSON_EachElementPathIdentifiesItsOwnBlock(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"a": cleanTargetFS(), "b": findingTargetFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"a", "--scan-dir", "b", "-o", "json"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	var docs []struct {
		Path string `json:"path"`
	}
	if err := stdjson.Unmarshal(stdout.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, stdout.String())
	}
	if len(docs) != 2 {
		t.Fatalf("len(docs) = %d, want 2\nstdout: %s", len(docs), stdout.String())
	}
	if docs[0].Path != "a" || docs[1].Path != "b" {
		t.Fatalf("docs paths = [%q, %q], want [\"a\", \"b\"] in block order\nstdout: %s", docs[0].Path, docs[1].Path, stdout.String())
	}
}

func TestRun_MultiTarget_OneHeaderPerTargetInResolvedOrderSeparatedByBlankLine(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"a": cleanTargetFS(), "b": cleanTargetFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"a", "--scan-dir", "b"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstderr: %s", got, stderr.String())
	}

	want := "agentaudit · a\n\nno known agent config read\n0 capabilities · 0 files · 0 categories\n\nagentaudit · b"
	if !strings.Contains(stdout.String(), want) {
		t.Fatalf("stdout = %q, want blocks for a then b in order, separated by a blank line", stdout.String())
	}
}

type degradedTargetFS struct {
	m       fstest.MapFS
	failDir string
}

func (f degradedTargetFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f degradedTargetFS) ReadFile(name string) ([]byte, error) { return f.m.ReadFile(name) }

func (f degradedTargetFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f degradedTargetFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f degradedTargetFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f degradedTargetFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failDir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("simulated read error")}
	}
	return f.m.ReadDir(name)
}

// Degradation aggregates per block, never globally, and the exit code stays 0
// because neither block has an actual finding.
func TestRun_MultiTarget_DegradedPlusCleanNoFindingsExitsZero(t *testing.T) {
	degraded := degradedTargetFS{
		m:       fstest.MapFS{"broken/file.txt": &fstest.MapFile{Data: []byte("x")}},
		failDir: "broken",
	}
	withOpenTarget(t, map[string]fs.FS{"a": degraded, "b": cleanTargetFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"a", "--scan-dir", "b"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	bIdx := strings.Index(out, "agentaudit · b")
	if bIdx == -1 {
		t.Fatalf("stdout = %q, want a block headed by b", out)
	}
	blockA := out[:bIdx]
	blockB := out[bIdx:]

	if !strings.Contains(blockA, "SCAN INCOMPLETE") {
		t.Fatalf("block a = %q, want it to report SCAN INCOMPLETE", blockA)
	}
	if claimsACleanScan(blockA) {
		t.Fatalf("block a = %q, want neither clean claim on a degraded block", blockA)
	}
	if !strings.Contains(blockB, "no known agent config read") {
		t.Fatalf("block b = %q, want the clean block to report a clean read", blockB)
	}
	if strings.Contains(blockB, "SCAN INCOMPLETE") {
		t.Fatalf("block b = %q, want no SCAN INCOMPLETE on the clean block", blockB)
	}
}

func TestRun_MultiTarget_TwoPositionalArgsStillExit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"one", "two"}, &stdout, &stderr); got != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %s", got, stderr.String())
	}
}
