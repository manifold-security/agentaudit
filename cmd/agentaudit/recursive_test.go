package main

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// twoProjectContainerFS gives each project something the embedded ruleset
// flags.
func twoProjectContainerFS() fstest.MapFS {
	return fstest.MapFS{
		"proj1/.claude/settings.json": &fstest.MapFile{
			Data: []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}}`),
		},
		"proj2/.mcp.json": &fstest.MapFile{
			Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`),
		},
	}
}

func TestRun_Recursive_ContainerOfTwoProjectsYieldsOneBlockPerProject(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"container": twoProjectContainerFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "container"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "agentaudit · container/proj1\n") {
		t.Fatalf("stdout = %q, want a block headed by container/proj1", out)
	}
	if !strings.Contains(out, "agentaudit · container/proj2\n") {
		t.Fatalf("stdout = %q, want a block headed by container/proj2", out)
	}
	idx1 := strings.Index(out, "container/proj1")
	idx2 := strings.Index(out, "container/proj2")
	if idx1 == -1 || idx2 == -1 || idx1 > idx2 {
		t.Fatalf("stdout = %q, want the proj1 block before the proj2 block (lexical order)", out)
	}
}

func TestRun_Recursive_SameContainerWithoutRecursiveYieldsOneBlockForContainer(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"container": twoProjectContainerFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"container"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0 (a container's own anchored signatures never reach a nested project's config)\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "agentaudit · container\n") {
		t.Fatalf("stdout = %q, want a single block headed by the container path", out)
	}
	if strings.Contains(out, "proj1") || strings.Contains(out, "proj2") {
		t.Fatalf("stdout = %q, want no per-project block without -r", out)
	}
}

func TestRun_Recursive_ComposesWithScanDirAcrossTwoContainers(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{
		"c1": fstest.MapFS{"proj1/.claude/settings.json": &fstest.MapFile{
			Data: []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo hi"}]}]}}`),
		}},
		"c2": fstest.MapFS{"proj2/.mcp.json": &fstest.MapFile{
			Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`),
		}},
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "c1", "--scan-dir", "c2"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	idx1 := strings.Index(out, "c1/proj1")
	idx2 := strings.Index(out, "c2/proj2")
	if idx1 == -1 || idx2 == -1 || idx1 > idx2 {
		t.Fatalf("stdout = %q, want c1's project block before c2's (target-major order)", out)
	}
}

func TestRun_Recursive_EmptyContainerStillYieldsOneBlock(t *testing.T) {
	withOpenTarget(t, map[string]fs.FS{"empty": fstest.MapFS{}})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "empty"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "agentaudit · empty") {
		t.Fatalf("stdout = %q, want the container's own block", out)
	}
	if !strings.Contains(out, "no known agent config read") {
		t.Fatalf("stdout = %q, want the empty container to report that it reached no known agent config", out)
	}
	if strings.Count(out, "agentaudit ·") != 1 {
		t.Fatalf("stdout = %q, want exactly one block for an empty container", out)
	}
	if strings.Contains(out, "\n(") {
		t.Fatalf("stdout = %q, want no agent heading (nothing produced anything to attribute)", out)
	}
}

func TestRun_Recursive_EnumerationReadFailureDegradesContainerAlongsideReadableProject(t *testing.T) {
	degraded := degradedTargetFS{
		m: fstest.MapFS{
			"good/.mcp.json":  &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)},
			"broken/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "broken",
	}
	withOpenTarget(t, map[string]fs.FS{"container": degraded})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "container"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	containerIdx := strings.Index(out, "agentaudit · container\n")
	goodIdx := strings.Index(out, "agentaudit · container/good\n")
	if containerIdx == -1 {
		t.Fatalf("stdout = %q, want the container's own block rendered even though enumeration could not read part of it", out)
	}
	if goodIdx == -1 {
		t.Fatalf("stdout = %q, want good's own block rendered", out)
	}
	// A guard that panics takes the whole test binary down and hides every
	// other test's result, so fail with a diagnostic instead of slicing blind.
	if containerIdx >= goodIdx {
		t.Fatalf("stdout = %q, want the container block (at %d) before good's block (at %d)", out, containerIdx, goodIdx)
	}

	containerBlock := out[containerIdx:goodIdx]
	goodBlock := out[goodIdx:]
	// The single unreadable directory is reachable by both the enumeration
	// walk and the container's own rescan, so asserting the exact count is
	// what catches a fold that double-counts one shared fault.
	if !strings.Contains(containerBlock, "SCAN INCOMPLETE: 1 source could not be read") {
		t.Fatalf("container block = %q, want the exact single-source SCAN INCOMPLETE banner", containerBlock)
	}
	if !strings.Contains(containerBlock, "1 unreadable source\n") {
		t.Fatalf("container block = %q, want the footer to count exactly 1 unreadable source", containerBlock)
	}
	if !strings.Contains(goodBlock, "MCP") && !strings.Contains(goodBlock, "mcp") {
		t.Fatalf("good block = %q, want good's mcp finding still reported", goodBlock)
	}
	if strings.Contains(goodBlock, "SCAN INCOMPLETE") {
		t.Fatalf("good block = %q, want no SCAN INCOMPLETE on the readable project", goodBlock)
	}
}

func TestRun_Recursive_DanglingSymlinkConjuresNoContainerEntry(t *testing.T) {
	container := fstest.MapFS{
		"good/.mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)},
		"ghost":          &fstest.MapFile{Data: []byte("missingdir"), Mode: fs.ModeSymlink},
	}
	withOpenTarget(t, map[string]fs.FS{"container": container})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"-r", "container"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if got := strings.Count(out, "agentaudit ·"); got != 1 {
		t.Fatalf("stdout has %d \"agentaudit ·\" headers, want exactly 1\nstdout: %q", got, out)
	}
	if !strings.Contains(out, "agentaudit · container/good\n") {
		t.Fatalf("stdout = %q, want good's own block rendered", out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout = %q, want no SCAN INCOMPLETE conjured by a dangling symlink", out)
	}
}
