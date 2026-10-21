package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const globalConfigSettingsJSON = `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]},"env":{"ANTHROPIC_BASE_URL":"https://example.com"}}`

func writeGlobalSettings(t *testing.T, dir string) {
	t.Helper()
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", claudeDir, err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(globalConfigSettingsJSON), 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}
}

// runWithHome sets HOME by appending it, which os/exec resolves in favour of
// the last duplicate.
func runWithHome(t *testing.T, bin, dir, home string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runWithEnv(t, bin, dir, append(os.Environ(), "HOME="+home), args...)
}

// runWithEnv builds the child's environment rather than calling t.Setenv,
// which would mutate the test binary's own environment mid-run.
func runWithEnv(t *testing.T, bin, dir string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = env

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("the scan never returned within the deadline\nstdout so far:\n%s\nstderr so far:\n%s", outBuf.String(), errBuf.String())
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstdout:\n%s\nstderr:\n%s", err, outBuf.String(), errBuf.String())
	}
	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

func TestBinaryE2E_GlobalConfig_PopulatedHomeReportsHookAndBaseURL(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	writeGlobalSettings(t, home)
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, out)
	}
	if !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout does not contain the global block header for %q\nstdout:\n%s", home, out)
	}
	if !strings.Contains(out, "notify.sh") {
		t.Fatalf("stdout does not report the global hook\nstdout:\n%s", out)
	}
	if got := strings.Count(out, "agentaudit ·"); got != 1 {
		t.Fatalf("stdout = %q, want the home block alone", out)
	}
}

func TestBinaryE2E_GlobalConfig_EmptyHomeStaysSilent(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s", code, out)
	}
	if strings.Contains(out, home) {
		t.Fatalf("stdout contains the empty fake home's path\nstdout:\n%s", out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for an absent global config\nstdout:\n%s", out)
	}
}

// The scanned target is the Base, not the declared location, so a
// non-directory .claude never reaches os.OpenRoot and the run cannot exit 2
// over one.
func TestBinaryE2E_GlobalConfig_ClaudeAsARegularFileNeverExitsFatally(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude"), []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write .claude file: %v", err)
	}
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code == 2 {
		t.Fatalf("exit code = 2, want never 2 when .claude is a regular file\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout does not contain the global block header for %q\nstdout:\n%s", home, out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout does not render SCAN INCOMPLETE for the unreadable .claude entries\nstdout:\n%s", out)
	}
}

func TestBinaryE2E_GlobalConfig_InBaseSymlinkIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	real := filepath.Join(home, "dotfiles", "claude")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", real, err)
	}
	if err := os.WriteFile(filepath.Join(real, "settings.json"), []byte(globalConfigSettingsJSON), 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}
	if err := os.Symlink(filepath.Join("dotfiles", "claude"), filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, out)
	}
	if !strings.Contains(out, ".claude/settings.json") {
		t.Fatalf("stdout does not attribute the finding to .claude/settings.json provenance\nstdout:\n%s", out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for an in-Base symlink\nstdout:\n%s", out)
	}
}

func TestBinaryE2E_GlobalConfig_EscapingSymlinkDegradesWithoutASilentClean(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte(globalConfigSettingsJSON), 0o644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (an incomplete scan)\nstdout:\n%s", code, out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout does not contain SCAN INCOMPLETE for an escaping symlink\nstdout:\n%s", out)
	}
	if strings.Contains(out, "no known agent config read") || strings.Contains(out, "no capabilities found") {
		t.Fatalf("stdout = %q, want no clean claim for the degraded global block", out)
	}
}

// A real symlink to a FIFO behind the mask, across the process boundary. The
// deadline, not an assertion, is what catches a regression here; maskfs.go's
// forwarder block carries why the hang happens.
func TestBinaryE2E_GlobalConfig_FifoBehindTheMaskNeverHangs(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	skillDir := filepath.Join(home, ".claude", "skills", "x")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", skillDir, err)
	}
	if out, err := exec.Command("mkfifo", filepath.Join(skillDir, "pipe")).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
	}
	if err := os.Symlink("pipe", filepath.Join(skillDir, "pipelink")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a bare FIFO under skills/ declares no capability)\nstdout:\n%s", code, out)
	}
	if strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout contains SCAN INCOMPLETE for an in-tree symlink\nstdout:\n%s", out)
	}
}

// runWithoutHome leaves HOME out of the child's environment entirely, which
// needs a filtered copy: t.Setenv can only ever set HOME to some value.
func runWithoutHome(t *testing.T, bin, dir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HOME=") {
			env = append(env, kv)
		}
	}
	return runWithEnv(t, bin, dir, env, args...)
}

func TestBinaryE2E_GlobalConfig_UnresolvableHomeWarnsAndSaysNoConfigFound(t *testing.T) {
	bin := buildAgentauditBinary(t)

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"fs":{"command":"npx"}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	out, errOut, code := runWithoutHome(t, bin, project, "--global-config")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if want := "no user-level agent config found\n"; out != want {
		t.Fatalf("stdout = %q, want %q: the working directory is not a target", out, want)
	}
	if !strings.Contains(errOut, "HOME") {
		t.Fatalf("stderr does not warn about the unresolved global config base\nstderr:\n%s", errOut)
	}
}

func TestBinaryE2E_GlobalConfig_JSONHoldsOnlyTheHomeDocument(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	writeGlobalSettings(t, home)
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config", "-o", "json")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, out)
	}

	var docs []struct {
		Path     string `json:"path"`
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, out)
	}
	if len(docs) != 1 || docs[0].Path != home {
		t.Fatalf("decoded %d documents, want exactly one at %q\nstdout:\n%s", len(docs), home, out)
	}
	ruleIDs := map[string]bool{}
	for _, f := range docs[0].Findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["claude.hook.command"] || !ruleIDs["claude.env.anthropic-base-url"] {
		t.Fatalf("document rule ids = %v, want both the hook and base-url rules", ruleIDs)
	}
}

func TestBinaryE2E_GlobalConfig_MDFileInTheWorkingDirectoryHoldsOnlyTheHomeDocument(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	writeGlobalSettings(t, home)
	project := t.TempDir()

	_, _, code := runWithHome(t, bin, project, home, "--global-config", "-O", "md")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	data, err := os.ReadFile(filepath.Join(project, "agentaudit-report.md"))
	if err != nil {
		t.Fatalf("ReadFile(agentaudit-report.md) error = %v", err)
	}
	out := string(data)
	if got := strings.Count(out, "# agentaudit ·"); got != 1 || !strings.Contains(out, "# agentaudit · "+home) {
		t.Fatalf("agentaudit-report.md = %q, want exactly one document, the home's", out)
	}
}

// A .claude.json that is a FIFO must not block forever on a read with no
// writer. The context deadline fails loudly as a timeout, not a wrong answer,
// if the read reaches fs.ReadFile before the directory-entry regularity check.
func TestBinaryE2E_GlobalConfig_ClaudeJSONAsAFIFOCompletesUnderADeadline(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	if out, err := exec.Command("mkfifo", filepath.Join(home, ".claude.json")).CombinedOutput(); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (a degraded global block, no findings)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout = %q, want the global block to render SCAN INCOMPLETE", out)
	}
	if !strings.Contains(errOut, ".claude.json") {
		t.Fatalf("stderr = %q, want a warning naming .claude.json", errOut)
	}
}

func TestBinaryE2E_GlobalConfig_ClaudeJSONAsADirectoryDegradesWithoutASilentClean(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude.json"), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Join(home, ".claude.json"), err)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (a degraded global block, no findings)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout = %q, want the global block to render SCAN INCOMPLETE", out)
	}
	if !strings.Contains(errOut, ".claude.json") {
		t.Fatalf("stderr = %q, want a warning naming .claude.json", errOut)
	}
	// A directory fails to read anyway (os returns "is a directory"), so the
	// assertions above would pass whether or not the regularity check ran.
	if !strings.Contains(errOut, "not a regular file") {
		t.Fatalf("stderr = %q, want the directory-entry regularity check's own wording, not a raw read error", errOut)
	}
}

// A .claude.json symlinked outside $HOME must never surface the target's
// content. The warning count is recorded, not asserted on: discovery's
// classification and the adapter's regularity check can each observe one.
func TestBinaryE2E_GlobalConfig_ClaudeJSONAsASymlinkEscapingHomeNeverLeaksTheTarget(t *testing.T) {
	bin := buildAgentauditBinary(t)

	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.json")
	if err := os.WriteFile(outsideFile, []byte(`{"mcpServers":{"leaked":{"command":"npx"}}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", outsideFile, err)
	}
	home := t.TempDir()
	if err := os.Symlink(outsideFile, filepath.Join(home, ".claude.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (a degraded global block, no findings)\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if strings.Contains(out, "leaked") {
		t.Fatalf("stdout = %q, want the symlink target's content never surfaced", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout = %q, want the global block to render SCAN INCOMPLETE", out)
	}
	if !strings.Contains(errOut, ".claude.json") {
		t.Fatalf("stderr = %q, want at least one warning naming .claude.json", errOut)
	}
	// os.Root's own containment is a second, independent reason a raw read
	// would fail here; this wording isolates the regularity check from it.
	if !strings.Contains(errOut, "not a regular file") {
		t.Fatalf("stderr = %q, want the directory-entry regularity check's own wording, not only a containment refusal", errOut)
	}
}

// A $HOME carrying only ~/.cursor still renders exactly one global block,
// end to end through the built binary.
func TestBinaryE2E_GlobalConfig_CursorHomeIsScanned(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", cursorDir, err)
	}
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(`{"mcpServers":{"ship-tool":{"command":"/usr/local/bin/build"}}}`), 0o644); err != nil {
		t.Fatalf("write mcp.json: %v", err)
	}
	project := t.TempDir()

	out, _, code := runWithHome(t, bin, project, home, "--global-config")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s", code, out)
	}
	if got := strings.Count(out, "agentaudit · "+home); got != 1 {
		t.Fatalf("stdout = %q, want exactly ONE global block for %q, got %d", out, home, got)
	}
	if !strings.Contains(out, ".cursor/mcp.json") {
		t.Fatalf("stdout does not attribute a finding to .cursor/mcp.json\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "mcpServer ship-tool") {
		t.Fatalf("stdout does not report the Cursor mcpServer entity\nstdout:\n%s", out)
	}
}

// The home .codex/config.toml reaches the shipped rules through the real
// binary, and the plaintext token in the auth.json beside it reaches
// neither stream.
func TestBinaryE2E_GlobalConfig_CodexHomeConfigIsScannedAndAuthJSONIsNot(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", codexDir, err)
	}
	body := "sandbox_mode = \"danger-full-access\"\n"
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}
	sentinel := "SENTINEL-AUTH-JSON-MUST-NEVER-APPEAR"
	if err := os.WriteFile(filepath.Join(codexDir, "auth.json"), []byte(`{"api_key":"`+sentinel+`"}`), 0o644); err != nil {
		t.Fatalf("write auth.json: %v", err)
	}
	project := t.TempDir()

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config", "-v")

	if code != 1 {
		t.Fatalf("exit code = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if !strings.Contains(out, "codex.sandbox.full-access") {
		t.Fatalf("stdout does not report codex.sandbox.full-access\nstdout:\n%s", out)
	}
	if !strings.Contains(out, "sandbox mode · danger-full-access") {
		t.Fatalf("stdout does not report the Codex sandbox entity\nstdout:\n%s", out)
	}
	if strings.Contains(out, sentinel) || strings.Contains(errOut, sentinel) {
		t.Fatalf("auth.json sentinel leaked into output\nstdout:\n%s\nstderr:\n%s", out, errOut)
	}
}

func TestBinaryE2E_GlobalConfig_WithAPathIsAUsageErrorThatScansNothing(t *testing.T) {
	bin := buildAgentauditBinary(t)

	home := t.TempDir()
	writeGlobalSettings(t, home)
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"fs":{"command":"npx"}}}`), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	out, errOut, code := runWithHome(t, bin, project, home, "--global-config", "-O", "json", ".")

	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want nothing rendered for a usage error", out)
	}
	if !strings.Contains(errOut, "cannot be combined with PATH") {
		t.Fatalf("stderr = %q, want it to name the conflicting PATH", errOut)
	}
	if _, err := os.Stat(filepath.Join(project, "agentaudit-report.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(agentaudit-report.json) error = %v, want ErrNotExist: a usage error writes no report file", err)
	}
}

func TestBinaryE2E_GlobalConfig_EmptyRunNamesWhetherTheHomeCouldBeRead(t *testing.T) {
	bin := buildAgentauditBinary(t)

	tests := []struct {
		name string
		home func(t *testing.T) string
		want string
		code int
	}{
		{"a home that does not exist", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "missing")
		}, "no user-level agent config found\n", 0},
		{"a home that is a regular file", func(t *testing.T) string {
			home := filepath.Join(t.TempDir(), "home")
			if err := os.WriteFile(home, []byte("not a directory"), 0o644); err != nil {
				t.Fatalf("write %s: %v", home, err)
			}
			return home
		}, "user-level agent config could not be read\n", 1},
		{"a home with mode 000", func(t *testing.T) string {
			if os.Geteuid() == 0 {
				t.Skip("root ignores directory permissions")
			}
			home := t.TempDir()
			writeGlobalSettings(t, home)
			if err := os.Chmod(home, 0); err != nil {
				t.Fatalf("chmod %s: %v", home, err)
			}
			t.Cleanup(func() { os.Chmod(home, 0o755) })
			return home
		}, "user-level agent config could not be read\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := tt.home(t)
			out, errOut, code := runWithHome(t, bin, t.TempDir(), home, "--global-config")
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.code, out, errOut)
			}
			if out != tt.want {
				t.Fatalf("stdout = %q, want %q", out, tt.want)
			}
			if !strings.Contains(errOut, home) {
				t.Fatalf("stderr = %q, want a warning naming %q", errOut, home)
			}
		})
	}
}
