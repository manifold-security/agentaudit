package main

import (
	stdjson "encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// argsMCPConfig declares a stdio server whose command names only a runtime,
// so every identifying token of what it actually runs lives in the vector.
const argsMCPConfig = `{"mcpServers":{"tools":{"command":"npx","args":["-y","chrome-devtools-mcp@latest","--headless"]}}}`

// argsMCPPayload appears in argsMCPConfig only inside the vector, so finding
// it in the output is unambiguous evidence the args were rendered.
const argsMCPPayload = "chrome-devtools-mcp@latest"

// A declared argument vector reaches -o json as an array and the pretty
// finding line after the command it is passed to.
func TestBinaryE2E_MCPServerArgsSurfaceInJSONAndPretty(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(argsMCPConfig), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	stdout, stderr, code := runBinary(t, bin, root, "-o", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the mcp finding is present)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	var docs []struct {
		Findings []struct {
			Capability struct {
				Kind  string   `json:"kind"`
				Value string   `json:"value"`
				Args  []string `json:"args"`
			} `json:"capability"`
		} `json:"findings"`
	}
	if err := stdjson.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v\nstdout:\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("decoded %d documents, want 1\nstdout:\n%s", len(docs), stdout)
	}

	var found bool
	for _, f := range docs[0].Findings {
		if f.Capability.Kind != "mcpServer" {
			continue
		}
		found = true
		if f.Capability.Value != "npx" {
			t.Errorf("capability.value = %q, want the bare command with no arg folded in", f.Capability.Value)
		}
		want := []string{"-y", argsMCPPayload, "--headless"}
		if len(f.Capability.Args) != len(want) {
			t.Fatalf("capability.args = %#v, want %#v", f.Capability.Args, want)
		}
		for i, w := range want {
			if f.Capability.Args[i] != w {
				t.Errorf("capability.args[%d] = %q, want %q", i, f.Capability.Args[i], w)
			}
		}
	}
	if !found {
		t.Fatalf("no mcpServer capability in the decoded document\nstdout:\n%s", stdout)
	}

	prettyOut, _, prettyCode := runBinary(t, bin, root)
	if prettyCode != 1 {
		t.Fatalf("pretty exit code = %d, want 1\nstdout:\n%s", prettyCode, prettyOut)
	}
	const wantLine = "  mcpServer tools (stdio) · npx -y " + argsMCPPayload + " --headless · .mcp.json:mcpServers.tools\n"
	if !strings.Contains(prettyOut, wantLine) {
		t.Fatalf("pretty stdout missing %q\nstdout:\n%s", wantLine, prettyOut)
	}
}
