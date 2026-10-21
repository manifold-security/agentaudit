package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pluginGuardMarker exists only outside the scanned tree, so finding it in
// stdout means a guard followed a symlink out.
const pluginGuardMarker = "OUTSIDE-MARKER"

// The whole stderr transcript is asserted rather than sampled: a guard that
// stops refusing shows up as a missing line, and one that reclassifies a path
// shows up as a changed line.
func TestBinaryE2E_PluginGuardRefusalTranscript(t *testing.T) {
	bin := buildAgentauditBinary(t)

	parent := t.TempDir()
	outside := filepath.Join(parent, "outside")
	root := filepath.Join(parent, "root")
	plug := filepath.Join(root, "plug")

	for _, dir := range []string{
		filepath.Join(outside, "agents"),
		filepath.Join(plug, ".claude-plugin"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	writeFile := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	writeFile(filepath.Join(outside, "servers.json"),
		`{"leaked":{"command":"`+pluginGuardMarker+`"}}`)
	writeFile(filepath.Join(outside, "agents", "leak.md"),
		"---\nname: leaked-agent\ndescription: "+pluginGuardMarker+"\n---\nbody\n")
	writeFile(filepath.Join(plug, ".claude-plugin", "plugin.json"), `{"name":"plug",`+
		`"mcpServers":["./escapedir/servers.json","./escapefile.json","./pipe.json","./missing.json"],`+
		`"agents":"./escapeagents"}`)

	// A real in-tree source, so the report is a findings report the refusals
	// degrade rather than an empty one they dominate.
	writeFindingMCP(t, filepath.Join(root, ".mcp.json"))

	symlinks := map[string]string{
		filepath.Join(plug, "escapedir"):    filepath.Join("..", "..", "outside"),
		filepath.Join(plug, "escapefile"):   filepath.Join("..", "..", "outside", "servers.json"),
		filepath.Join(plug, "escapeagents"): filepath.Join("..", "..", "outside", "agents"),
		filepath.Join(plug, "bin"):          filepath.Join("..", "..", "outside"),
	}
	for link, target := range symlinks {
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable on this platform: %v", err)
		}
	}
	// The manifest declares escapefile.json; renaming after os.Symlink keeps
	// the ".json" off the link target the map above spells.
	if err := os.Rename(filepath.Join(plug, "escapefile"), filepath.Join(plug, "escapefile.json")); err != nil {
		t.Fatalf("rename escapefile: %v", err)
	}

	if out, err := exec.Command("mkfifo", filepath.Join(plug, "pipe.json")).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("the scan never returned; a blocking Open classified the FIFO instead of an unfollowed stat\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}

	out, errOut := stdout.String(), stderr.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, pluginGuardMarker) {
		t.Fatalf("stdout carries out-of-tree content, so a guard followed a symlink\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must report the refused sources as an incomplete scan\nstdout:\n%s", out)
	}

	// "path escapes from parent" is os.Root's own refusal, raised by discovery
	// before any adapter runs; it has no errors.Is target, so it is matched
	// here as the literal text the runtime produces.
	want := []string{
		`warning: agentaudit: discover: plug/bin: statat plug/bin: path escapes from parent`,
		`warning: agentaudit: discover: plug/escapeagents: statat plug/escapeagents: path escapes from parent`,
		`warning: agentaudit: discover: plug/escapedir: statat plug/escapedir: path escapes from parent`,
		`warning: agentaudit: discover: plug/escapefile.json: statat plug/escapefile.json: path escapes from parent`,
		`warning: agentaudit: parse claude-code: plug/escapedir/servers.json: refusing to walk "plug/escapedir": not a real directory (L---------)`,
		`warning: agentaudit: parse claude-code: plug/escapefile.json: refusing to read "plug/escapefile.json": not a regular file (L---------)`,
		`warning: agentaudit: parse claude-code: plug/pipe.json: refusing to read "plug/pipe.json": not a regular file (p---------)`,
		`warning: agentaudit: parse claude-code: plug/missing.json: open plug/missing.json: file does not exist`,
		`warning: agentaudit: parse claude-code: plug/escapeagents: refusing to walk "plug/escapeagents": not a real directory (L---------)`,
		`warning: agentaudit: parse claude-code: plug/bin: refusing to walk "plug/bin": not a real directory (L---------)`,
	}
	got := strings.Split(strings.TrimRight(errOut, "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("stderr line count = %d, want %d\ngot:\n%s\nwant:\n%s",
			len(got), len(want), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stderr line %d =\n\t%s\nwant\n\t%s", i, got[i], want[i])
		}
	}
}
