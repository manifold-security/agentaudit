package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The saved Markdown artifact heads each block with "# agentaudit · <path>",
// so a scanned directory named with that separator passes the tail of its own
// name off as text beyond the path unless the reporter escapes it.
func TestBinaryE2E_ScannedDirectoryNameCannotForgeTheMarkdownH1(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	const project = "proj · evil"
	if err := os.MkdirAll(filepath.Join(root, project), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", project, err)
	}
	writeFindingMCP(t, filepath.Join(root, project, ".mcp.json"))

	out, errOut, code := runBinary(t, bin, root, "-O", "md", project)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}

	data, err := os.ReadFile(filepath.Join(root, mdReportFilename))
	if err != nil {
		t.Fatalf("read %s: %v", mdReportFilename, err)
	}
	h1 := strings.SplitN(string(data), "\n", 2)[0]

	if n := strings.Count(h1, "·"); n != 1 {
		t.Fatalf("H1 %q holds %d middle dots, want 1 (the reporter's own separator)", h1, n)
	}
	if !strings.HasSuffix(h1, `proj \u00b7 evil`) {
		t.Fatalf("H1 %q, want the scanned name whole with its separator escaped", h1)
	}
}
