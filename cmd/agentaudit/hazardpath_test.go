package main

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// Under a recursive scan a project directory name comes from the scanned
// tree, not the operator's command line, so whoever controls the tree
// controls the name a block's display path renders.
func TestRun_Recursive_ProjectPathWithHazardByteCannotForgeExtraLineOrHeading(t *testing.T) {
	const hazardProject = "proj\r1"
	container := fstest.MapFS{
		hazardProject + "/.mcp.json": &fstest.MapFile{
			Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`),
		},
	}
	withOpenTarget(t, map[string]fs.FS{"container": container})

	t.Run("pretty", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if got := run([]string{"-r", "container"}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
		}
		out := stdout.String()
		if got := strings.Count(out, "agentaudit ·"); got != 1 {
			t.Fatalf("pretty output has %d \"agentaudit ·\" headers, want exactly 1\nstdout: %q", got, out)
		}
		if strings.ContainsRune(out, '\r') {
			t.Fatalf("pretty output = %q, want the hazard byte escaped exactly like every other rendered field", out)
		}
		if !strings.Contains(out, `proj\\r1`) {
			t.Fatalf("pretty output = %q, want it to contain the escaped hazard spelling %q, not a folded or dropped byte", out, `proj\\r1`)
		}
	})

	t.Run("markdown", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var stdout, stderr bytes.Buffer
		if got := run([]string{"-r", "-O", "md", "container"}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
		}
		data, err := os.ReadFile(mdReportFilename)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
		}
		out := string(data)
		if got := strings.Count(out, "# agentaudit"); got != 1 {
			t.Fatalf("%s has %d H1 headers, want exactly 1\ncontent: %q", mdReportFilename, got, out)
		}
		if strings.ContainsRune(out, '\r') {
			t.Fatalf("%s = %q, want the hazard byte escaped, never a raw CommonMark line ending", mdReportFilename, out)
		}
		if !strings.Contains(out, `proj\\r1`) {
			t.Fatalf("%s = %q, want it to contain the escaped hazard spelling %q, not a folded or dropped byte", mdReportFilename, out, `proj\\r1`)
		}
	})
}

// A hostile project name can embed a line feed followed by text spelling
// out another project's own header line. Escaped, that text stays literal on
// the hostile project's single line, so at most one line in the output can
// match the genuine header.
func TestRun_Recursive_HostileProjectNameCannotForgeAnotherBlocksHeaderLine(t *testing.T) {
	benignMCP := []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)

	t.Run("pretty", func(t *testing.T) {
		const benignHeaderLine = "agentaudit · benign"
		hostileProject := "hostile\n" + benignHeaderLine + "\nend"
		escapedPath := strings.ReplaceAll(hostileProject, "\n", `\n`)
		escapedPath = strings.ReplaceAll(escapedPath, `\`, `\\`)
		escapedPath = strings.ReplaceAll(escapedPath, "·", "\\u00b7")
		wantHostileLine := "agentaudit · " + escapedPath

		withOpenTarget(t, map[string]fs.FS{
			".": fstest.MapFS{
				"benign/.mcp.json":            &fstest.MapFile{Data: benignMCP},
				hostileProject + "/.mcp.json": &fstest.MapFile{Data: benignMCP},
			},
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"-r"}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
		}
		out := stdout.String()

		matches := 0
		for _, line := range strings.Split(out, "\n") {
			if line == benignHeaderLine {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("stdout has %d lines exactly matching the benign block's header line %q, want exactly 1\nstdout: %q", matches, benignHeaderLine, out)
		}
		if !strings.Contains(out, wantHostileLine) {
			t.Fatalf("stdout = %q, want it to contain the hostile project's own escaped header line %q, proof the hostile block rendered rather than being skipped", out, wantHostileLine)
		}
	})

	t.Run("markdown", func(t *testing.T) {
		const benignHeaderLine = "# agentaudit · benign"
		hostileProject := "hostile\n" + benignHeaderLine + "\nend"
		escapedPath := strings.ReplaceAll(hostileProject, "\n", `\n`)
		escapedPath = strings.ReplaceAll(escapedPath, `\`, `\\`)
		escapedPath = strings.ReplaceAll(escapedPath, "·", "\\u00b7")
		escapedPath = strings.ReplaceAll(escapedPath, "#", "&#35;")
		wantHostileLine := "# agentaudit · " + escapedPath

		withOpenTarget(t, map[string]fs.FS{
			".": fstest.MapFS{
				"benign/.mcp.json":            &fstest.MapFile{Data: benignMCP},
				hostileProject + "/.mcp.json": &fstest.MapFile{Data: benignMCP},
			},
		})
		t.Chdir(t.TempDir())

		var stdout, stderr bytes.Buffer
		if got := run([]string{"-r", "-O", "md"}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
		}
		data, err := os.ReadFile(mdReportFilename)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
		}
		out := string(data)

		matches := 0
		for _, line := range strings.Split(out, "\n") {
			if line == benignHeaderLine {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("%s has %d lines exactly matching the benign block's header line %q, want exactly 1\ncontent: %q", mdReportFilename, matches, benignHeaderLine, out)
		}
		if !strings.Contains(out, wantHostileLine) {
			t.Fatalf("%s = %q, want it to contain the hostile project's own escaped header line %q, proof the hostile block rendered rather than being skipped", mdReportFilename, out, wantHostileLine)
		}
	})
}

// The same forgery from a target typed on the CLI via --scan-dir, which
// reaches the renderer by a different route than the scanned-tree project
// name above.
func TestRun_HostileTargetNameCannotForgeAnotherBlocksHeaderLine(t *testing.T) {
	benignMCP := []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)

	t.Run("pretty", func(t *testing.T) {
		const benignHeaderLine = "agentaudit · benign"
		hostileTarget := "hostile\n" + benignHeaderLine + "\nend"
		escapedPath := strings.ReplaceAll(hostileTarget, "\n", `\n`)
		escapedPath = strings.ReplaceAll(escapedPath, `\`, `\\`)
		escapedPath = strings.ReplaceAll(escapedPath, "·", "\\u00b7")
		wantHostileLine := "agentaudit · " + escapedPath

		withOpenTarget(t, map[string]fs.FS{
			"benign":      fstest.MapFS{".mcp.json": &fstest.MapFile{Data: benignMCP}},
			hostileTarget: fstest.MapFS{".mcp.json": &fstest.MapFile{Data: benignMCP}},
		})

		var stdout, stderr bytes.Buffer
		if got := run([]string{"benign", "--scan-dir", hostileTarget}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
		}
		out := stdout.String()

		matches := 0
		for _, line := range strings.Split(out, "\n") {
			if line == benignHeaderLine {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("stdout has %d lines exactly matching the benign block's header line %q, want exactly 1\nstdout: %q", matches, benignHeaderLine, out)
		}
		if !strings.Contains(out, wantHostileLine) {
			t.Fatalf("stdout = %q, want it to contain the hostile block's own escaped header line %q, proof the hostile block rendered rather than being skipped", out, wantHostileLine)
		}
	})

	t.Run("markdown", func(t *testing.T) {
		const benignHeaderLine = "# agentaudit · benign"
		hostileTarget := "hostile\n" + benignHeaderLine + "\nend"
		escapedPath := strings.ReplaceAll(hostileTarget, "\n", `\n`)
		escapedPath = strings.ReplaceAll(escapedPath, `\`, `\\`)
		escapedPath = strings.ReplaceAll(escapedPath, "·", "\\u00b7")
		escapedPath = strings.ReplaceAll(escapedPath, "#", "&#35;")
		wantHostileLine := "# agentaudit · " + escapedPath

		withOpenTarget(t, map[string]fs.FS{
			"benign":      fstest.MapFS{".mcp.json": &fstest.MapFile{Data: benignMCP}},
			hostileTarget: fstest.MapFS{".mcp.json": &fstest.MapFile{Data: benignMCP}},
		})
		t.Chdir(t.TempDir())

		var stdout, stderr bytes.Buffer
		if got := run([]string{"-O", "md", "benign", "--scan-dir", hostileTarget}, &stdout, &stderr); got != 1 {
			t.Fatalf("run() = %d, want 1\nstderr: %s", got, stderr.String())
		}
		data, err := os.ReadFile(mdReportFilename)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
		}
		out := string(data)

		matches := 0
		for _, line := range strings.Split(out, "\n") {
			if line == benignHeaderLine {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("%s has %d lines exactly matching the benign block's header line %q, want exactly 1\ncontent: %q", mdReportFilename, matches, benignHeaderLine, out)
		}
		if !strings.Contains(out, wantHostileLine) {
			t.Fatalf("%s = %q, want it to contain the hostile block's own escaped header line %q, proof the hostile block rendered rather than being skipped", mdReportFilename, out, wantHostileLine)
		}
	})
}
