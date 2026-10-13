package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unparsableAgent reproduces the frontmatter shape that fails to parse in a
// real global config: an unquoted description scalar whose text carries a
// bare ": ", which YAML reads as a nested mapping key.
const unparsableAgent = "---\n" +
	"name: silent-failure-hunter\n" +
	"description: Use this agent when: a command exits 0 but did nothing\n" +
	"tools: Bash, Read\n" +
	"---\n\nbody\n"

// countsDocument mirrors internal/report/json's counts object.
type countsDocument struct {
	Counts struct {
		Findings          int `json:"findings"`
		UnreadableSources int `json:"unreadableSources"`
		UnparsedSources   int `json:"unparsedSources"`
	} `json:"counts"`
}

func writeUnparsableAgent(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".claude", "agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hunter.md"), []byte(unparsableAgent), 0o644); err != nil {
		t.Fatalf("write hunter.md: %v", err)
	}
}

// json must count a source whose declarations a parse failure discarded: a
// stderr warning does not reach a json consumer, so without the count the
// run reads as clean coverage while an agent file contributed nothing.
func TestBinaryE2E_UnparsableAgentIsCountedInJSON(t *testing.T) {
	bin := buildAgentauditBinary(t)
	root := t.TempDir()
	writeUnparsableAgent(t, root)

	stdout, stderr, code := runBinary(t, bin, root, "-o", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a degraded scan with no findings is not an escalation)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	var docs []countsDocument
	if err := json.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("decoding -o json stdout: %v\nstdout:\n%s", err, stdout)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1\nstdout:\n%s", len(docs), stdout)
	}
	c := docs[0].Counts
	if c.UnparsedSources != 1 {
		t.Fatalf("counts.unparsedSources = %d, want 1\nstdout:\n%s\nstderr:\n%s", c.UnparsedSources, stdout, stderr)
	}
	if c.UnreadableSources != 0 {
		t.Fatalf("counts.unreadableSources = %d, want 0 (the file was read)\nstdout:\n%s", c.UnreadableSources, stdout)
	}
	if c.Findings != 0 {
		t.Fatalf("counts.findings = %d, want 0 (the agent file's declarations were discarded)\nstdout:\n%s", c.Findings, stdout)
	}
}

// The same tree on the pretty surface: the run must not read as clean, and
// its exit code must stay 0 — "I could not parse this" is information, not
// the claim that something was found.
func TestBinaryE2E_UnparsableAgentDegradesPrettyWithoutChangingExitCode(t *testing.T) {
	bin := buildAgentauditBinary(t)

	t.Run("no findings", func(t *testing.T) {
		root := t.TempDir()
		writeUnparsableAgent(t, root)

		stdout, stderr, code := runBinary(t, bin, root)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if claimsACleanScan(stdout) {
			t.Fatalf("stdout must NOT read as a clean empty scan\nstdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
			t.Fatalf("stdout missing the unparsed SCAN INCOMPLETE line\nstdout:\n%s", stdout)
		}
		if !strings.Contains(stdout, "· 1 unparsed source\n") {
			t.Fatalf("stdout missing the unparsed footer suffix\nstdout:\n%s", stdout)
		}
		if !strings.Contains(stderr, "warning:") {
			t.Fatalf("stderr missing the warning line\nstderr:\n%s", stderr)
		}
	})

	t.Run("findings present", func(t *testing.T) {
		root := t.TempDir()
		writeUnparsableAgent(t, root)
		writeFindingMCP(t, filepath.Join(root, ".mcp.json"))

		stdout, stderr, code := runBinary(t, bin, root)
		if code != 1 {
			t.Fatalf("exit code = %d, want 1 (findings decide the code, degradation never does)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "· 1 unparsed source\n") {
			t.Fatalf("stdout missing the unparsed footer suffix\nstdout:\n%s", stdout)
		}
	})
}
