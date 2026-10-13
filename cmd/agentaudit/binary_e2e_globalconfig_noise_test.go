package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGlobalNoise reaches its rotating log through a symlink to an absolute
// path. The mask denies .claude/debug before any resolution runs: walking it
// would turn a scope error into a containment error the user can do nothing
// about.
func writeGlobalNoise(t *testing.T, dir string) {
	t.Helper()

	debug := filepath.Join(dir, ".claude", "debug")
	if err := os.MkdirAll(debug, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", debug, err)
	}
	rotated := filepath.Join(debug, "2971b499.txt")
	if err := os.WriteFile(rotated, []byte("debug log\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", rotated, err)
	}
	if err := os.Symlink(rotated, filepath.Join(debug, "latest")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	projects := filepath.Join(dir, ".claude", "projects", "-Users-x")
	if err := os.MkdirAll(projects, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", projects, err)
	}
	transcript := filepath.Join(projects, "transcript.jsonl")
	if err := os.WriteFile(transcript, []byte(`{"text":"npx --yes evil-server"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", transcript, err)
	}
}

// The absolute-symlink log directory costs no SCAN INCOMPLETE: it is out of
// scope rather than unreadable.
func TestBinaryE2E_GlobalConfig_RuntimeStateIsNeverWalked(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	writeGlobalSettings(t, home)
	writeGlobalNoise(t, home)
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config", "-o", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}

	var docs []struct {
		Path     string `json:"path"`
		Findings []struct {
			Capability struct {
				File string `json:"file"`
			} `json:"capability"`
		} `json:"findings"`
		Counts struct {
			UnreadableSources int `json:"unreadableSources"`
			UnparsedSources   int `json:"unparsedSources"`
		} `json:"counts"`
	}
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, out)
	}

	if len(docs) != 1 || docs[0].Path != home {
		t.Fatalf("decoded %d documents, want exactly one at %q\nstdout:\n%s", len(docs), home, out)
	}
	global := docs[0]
	files := map[string]bool{}
	for _, f := range global.Findings {
		files[f.Capability.File] = true
	}
	if !files[".claude/settings.json"] {
		t.Fatalf("global findings provenance = %v, want the declared settings.json among them", files)
	}
	for file := range files {
		if strings.HasPrefix(file, ".claude/projects/") || strings.HasPrefix(file, ".claude/debug/") {
			t.Errorf("global findings name %q, want nothing outside a declared load path", file)
		}
	}
	if global.Counts.UnreadableSources != 0 {
		t.Errorf("unreadableSources = %d, want 0: the log directory is out of scope, not unreadable", global.Counts.UnreadableSources)
	}
	if global.Counts.UnparsedSources != 0 {
		t.Errorf("unparsedSources = %d, want 0", global.Counts.UnparsedSources)
	}
	if strings.Contains(errOut, "debug") || strings.Contains(errOut, "projects") {
		t.Errorf("stderr = %q, want no warning about a path the scan has no business walking", errOut)
	}

	pretty, _, code := runWithHome(t, bin, project, home, "--global-config")
	if code != 1 {
		t.Fatalf("pretty exit code = %d, want 1\nstdout:\n%s", code, pretty)
	}
	if strings.Contains(pretty, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for out-of-scope runtime state\nstdout:\n%s", pretty)
	}
}
