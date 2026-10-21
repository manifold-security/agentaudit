package main

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// A symlinked skill script is refused and counted rather than silently
// dropped. Its target is in-tree and real, so containment follows it
// cleanly, isolating the payload classifier's own refusal from an escaping
// symlink discovery's walk would warn about independently.
func TestBinaryE2E_SymlinkedSkillPayloadRendersScanIncomplete(t *testing.T) {
	bin := buildAgentauditBinary(t)

	root := t.TempDir()
	realScriptsDir := filepath.Join(root, "real-scripts")
	if err := os.MkdirAll(realScriptsDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", realScriptsDir, err)
	}
	realScript := filepath.Join(realScriptsDir, "run.sh")
	if err := os.WriteFile(realScript, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("write %s: %v", realScript, err)
	}

	skillDir := filepath.Join(root, ".claude", "skills", "demo", "scripts")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", skillDir, err)
	}
	relTarget := filepath.Join("..", "..", "..", "..", "real-scripts", "run.sh")
	if err := os.Symlink(relTarget, filepath.Join(skillDir, "run.sh")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	writeFindingMCP(t, filepath.Join(root, ".mcp.json"))

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running built binary failed to start/exit cleanly: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (the .mcp.json finding still surfaces)\nstdout:\n%s\nstderr:\n%s", code, out, stderr.String())
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout must contain \"SCAN INCOMPLETE\" for the symlinked skill payload\nstdout:\n%s", out)
	}
}

// A symlinked skill folder is named on stderr and counted, while the real
// skill beside it keeps its script in the report.
func TestBinaryE2E_SymlinkedSkillFolderIsNamedRatherThanSilentlyDropped(t *testing.T) {
	bin := buildAgentauditBinary(t)

	for _, agentDir := range []string{".claude", ".cursor"} {
		t.Run(agentDir, func(t *testing.T) {
			root := t.TempDir()
			for name, body := range map[string]string{
				agentDir + "/skills/ship/SKILL.md":        "---\nname: ship\ndescription: ship\n---\n",
				agentDir + "/skills/ship/scripts/ship.sh": "#!/bin/sh\n",
				"shared/linked/SKILL.md":                  "---\nname: linked\ndescription: linked\n---\n",
				"shared/linked/scripts/linked.sh":         "#!/bin/sh\n",
			} {
				file := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatalf("building fixture: %v", err)
				}
				if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
					t.Fatalf("building fixture: %v", err)
				}
			}
			link := filepath.Join(root, agentDir, "skills", "linked")
			if err := os.Symlink(filepath.Join("..", "..", "shared", "linked"), link); err != nil {
				t.Skipf("symlinks unavailable on this platform: %v", err)
			}

			stdout, stderr, code := runBinary(t, bin, root)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1 (the sibling skill's script is a finding)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, agentDir+"/skills/ship/scripts/ship.sh") {
				t.Errorf("binary stdout missing the sibling skill's script\nfull stdout:\n%s", stdout)
			}
			if strings.Contains(stdout, "linked.sh") {
				t.Errorf("binary stdout reports a script behind the refused link\nfull stdout:\n%s", stdout)
			}
			if !strings.Contains(stderr, agentDir+"/skills/linked") {
				t.Errorf("binary stderr does not name the refused link\nstderr:\n%s", stderr)
			}
			if !strings.Contains(stdout, "SCAN INCOMPLETE") {
				t.Errorf("stdout must carry \"SCAN INCOMPLETE\" for the refused link\nstdout:\n%s", stdout)
			}
			if got := parseUnreadableCount(t, stdout); got != 1 {
				t.Errorf("footer counts %d unreadable sources, want 1\nstdout:\n%s", got, stdout)
			}
		})
	}
}

// A link on a Markdown surface is named on stderr and counted wherever it
// hides a folder, one over nothing is named and left uncounted, and one over
// a file or a pipe under a name nothing reads is as silent as that file. The
// command beside it keeps its finding either way.
func TestBinaryE2E_MarkdownSurfaceLinksAreNamedRatherThanSilentlyDropped(t *testing.T) {
	bin := buildAgentauditBinary(t)

	const agentBody = "---\nname: helper\ndescription: helps\n---\nbody\n"
	tests := []struct {
		name           string
		link           string
		files          map[string]string
		fifo           string
		wantIncomplete bool
		wantSilent     bool
	}{
		{
			name:           "a project agents folder",
			link:           ".claude/agents/team",
			files:          map[string]string{"shared/team/helper.md": agentBody},
			wantIncomplete: true,
		},
		{
			name:           "a plugin commands folder",
			link:           "plugins/toolkit/commands/ns",
			files:          map[string]string{"shared/ns/deploy.md": "Run !`shared.sh` now.\n"},
			wantIncomplete: true,
		},
		{
			name:           "a plugin agents folder",
			link:           "plugins/toolkit/agents/team",
			files:          map[string]string{"shared/team/helper.md": agentBody},
			wantIncomplete: true,
		},
		{
			name:           "a skill folder under a Markdown name",
			link:           ".claude/skills/evil.md",
			files:          map[string]string{"shared/evil.md/SKILL.md": "---\nname: evil\n---\nRun !`shared.sh` now.\n"},
			wantIncomplete: true,
		},
		{
			name:       "a Markdown name over a pipe",
			link:       ".claude/skills/demo/notes.md",
			fifo:       "shared/notes.md",
			wantSilent: true,
		},
		{
			name:       "an ignored name over a file",
			link:       ".claude/agents/notes.txt",
			files:      map[string]string{"shared/notes.txt": "notes\n"},
			wantSilent: true,
		},
		{
			name: "a Markdown name over nothing",
			link: ".claude/skills/demo/notes.md",
		},
		{
			name: "a Claude skill folder over nothing",
			link: ".claude/skills/linked",
		},
		{
			name: "a Cursor skill folder over nothing",
			link: ".cursor/skills/linked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				".claude/commands/real.md":                   "Run !`in-tree.sh` now.\n",
				"plugins/toolkit/.claude-plugin/plugin.json": `{"name":"toolkit"}`,
			}
			for name, body := range tt.files {
				files[name] = body
			}
			for name, body := range files {
				file := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
					t.Fatalf("building fixture: %v", err)
				}
				if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
					t.Fatalf("building fixture: %v", err)
				}
			}
			if tt.fifo != "" {
				pipe := filepath.Join(root, filepath.FromSlash(tt.fifo))
				if err := os.MkdirAll(filepath.Dir(pipe), 0o755); err != nil {
					t.Fatalf("building fixture: %v", err)
				}
				if out, err := exec.Command("mkfifo", pipe).CombinedOutput(); err != nil {
					t.Skipf("mkfifo unavailable on this platform: %v (%s)", err, out)
				}
			}
			link := filepath.Join(root, filepath.FromSlash(tt.link))
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatalf("building fixture: %v", err)
			}
			target := strings.Repeat("../", strings.Count(tt.link, "/")) + "shared/" + path.Base(tt.link)
			if err := os.Symlink(filepath.FromSlash(target), link); err != nil {
				t.Skipf("symlinks unavailable on this platform: %v", err)
			}

			stdout, stderr, code := runWithEnv(t, bin, root, os.Environ())
			if code != 1 {
				t.Fatalf("exit code = %d, want 1 (the sibling command is a finding)\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, "in-tree.sh") {
				t.Errorf("binary stdout missing the sibling command\nfull stdout:\n%s", stdout)
			}
			if strings.Contains(stdout, "shared") {
				t.Errorf("binary stdout reports content behind the link\nfull stdout:\n%s", stdout)
			}
			if named := strings.Contains(stderr, tt.link); named == tt.wantSilent {
				t.Errorf("stderr names the link = %v, want %v\nstderr:\n%s", named, !tt.wantSilent, stderr)
			}
			if got := strings.Contains(stdout, "SCAN INCOMPLETE"); got != tt.wantIncomplete {
				t.Errorf("SCAN INCOMPLETE shown = %v, want %v\nstdout:\n%s\nstderr:\n%s", got, tt.wantIncomplete, stdout, stderr)
			}
			if tt.wantIncomplete {
				if got := parseUnreadableCount(t, stdout); got != 1 {
					t.Errorf("footer counts %d unreadable sources, want 1\nstdout:\n%s", got, stdout)
				}
			}
		})
	}
}
