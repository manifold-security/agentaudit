package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// forgedColumnMCP names a server after a whole benign record spelled with the
// pretty finding line's own " · " separator: unescaped, the row closes early
// and the real command reads as text past a benign-looking end of line.
const forgedColumnMCP = `{"mcpServers":{"ok (stdio) · /usr/bin/true · .mcp.json:mcpServers.ok":{"command":"/tmp/evil.sh"}}}`

// prettyFindingLine keys on the indent a finding line carries, so it counts
// rendered findings without depending on the column separator this file is
// asserting about.
var prettyFindingLine = regexp.MustCompile(`(?m)^  \S.*$`)

// A server name spelling the column separator must render as one row, with
// the command the config actually declares still on it.
func TestBinaryE2E_ScannedNameCannotForgePrettyColumns(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(forgedColumnMCP), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	out, errOut, code := runBinary(t, bin, root)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}

	lines := prettyFindingLine.FindAllString(out, -1)
	if len(lines) != 1 {
		t.Fatalf("stdout holds %d finding lines, want exactly 1\nstdout:\n%s", len(lines), out)
	}
	if n := strings.Count(lines[0], "·"); n != 2 {
		t.Fatalf("finding line %q holds %d middle dots, want 2 (the reporter's own separators)", lines[0], n)
	}
	if !strings.Contains(lines[0], "\\u00b7") {
		t.Fatalf("finding line %q, want the forged separators kept visible as escapes", lines[0])
	}
	if !strings.Contains(lines[0], "/tmp/evil.sh") {
		t.Fatalf("finding line %q, want the declared command on the line it belongs to", lines[0])
	}
}

// A directory named with the header's own separator cannot pass part of its
// name off as the scanned path.
func TestBinaryE2E_ScannedDirectoryNameCannotForgeThePrettyHeader(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	const project = "proj · evil"
	if err := os.MkdirAll(filepath.Join(root, project), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", project, err)
	}
	writeFindingMCP(t, filepath.Join(root, project, ".mcp.json"))

	out, errOut, code := runBinary(t, bin, root, project)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}

	header := strings.SplitN(out, "\n", 2)[0]
	if n := strings.Count(header, "·"); n != 1 {
		t.Fatalf("header %q holds %d middle dots, want 1 (the reporter's own separator)", header, n)
	}
	if !strings.Contains(header, "\\u00b7") {
		t.Fatalf("header %q, want the forged separator kept visible as an escape", header)
	}
}
