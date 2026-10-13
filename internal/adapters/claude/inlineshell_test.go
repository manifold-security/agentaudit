package claude

import (
	"reflect"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestInlineShellFromBody_KeyPrefixedBangNeverEmits(t *testing.T) {
	got := inlineShellFromBody([]byte("KEY=!`cmd`\n"), 1, "bash", "f.md")
	if got != nil {
		t.Fatalf("inlineShellFromBody() = %+v, want nil", got)
	}
}

func TestInlineShellFromBody_InlineForm(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string // expected Command values, in order
	}{
		{"line-start bang emits", "!`ls -la`\n", []string{"ls -la"}},
		{"whitespace-preceded bang emits", "Run this: !`ls -la`\n", []string{"ls -la"}},
		{"two placeholders on one line both emit", "!`a` and !`b`\n", []string{"a", "b"}},
		// The tab is written as an escape sequence: a raw tab byte here is
		// silently normalizable, and the arm it covers would go untested with
		// nothing turning red.
		{"tab-preceded bang emits", "Run this:\t!`ls -la`\n", []string{"ls -la"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inlineShellFromBody([]byte(tt.line), 1, "bash", "f.md")
			if len(got) != len(tt.want) {
				t.Fatalf("inlineShellFromBody() = %+v, want %d entities", got, len(tt.want))
			}
			for i, e := range got {
				sh, ok := e.(ir.InlineShell)
				if !ok || sh.Form != "inline" || sh.Command != tt.want[i] {
					t.Errorf("entity[%d] = %+v, want Command %q Form inline", i, e, tt.want[i])
				}
			}
		})
	}
}

func TestInlineShellFromBody_CursorAdvancesPastIneligibleBang(t *testing.T) {
	got := inlineShellFromBody([]byte("x!y !`cmd`\n"), 1, "bash", "f.md")
	want := []ir.Entity{
		ir.InlineShell{Command: "cmd", Form: "inline", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[1]"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inlineShellFromBody() = %+v, want %+v", got, want)
	}
}

func TestInlineShellFromBody_UnterminatedBacktickEmitsNothing(t *testing.T) {
	got := inlineShellFromBody([]byte("!`no closing backtick here\n"), 1, "bash", "f.md")
	if got != nil {
		t.Fatalf("inlineShellFromBody() = %+v, want nil", got)
	}
}

// The fence opener has no "!", though its content looks like a placeholder.
func TestInlineShellFromBody_PlainBashFenceNeverFires(t *testing.T) {
	body := "```bash\n!`id`\n```\n"
	got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
	if got != nil {
		t.Fatalf("inlineShellFromBody() = %+v, want nil", got)
	}
}

func TestInlineShellFromBody_PlainFenceVariantsNeverFire(t *testing.T) {
	tests := []struct{ name, opener string }{
		{"bare fence with no info string", "```"},
		{"markdown info string", "```markdown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.opener + "\n!`id`\n```\n"
			got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
			if got != nil {
				t.Fatalf("inlineShellFromBody() = %+v, want nil", got)
			}
		})
	}
}

// Each opener below fences the same bang-placeholder line, so a longer run
// that stops suppressing its content fails here rather than passing as merely
// unmatched.
func TestInlineShellFromBody_BangFenceOpenerRunBoundary(t *testing.T) {
	tests := []struct {
		name    string
		fence   string
		wantCmd string // empty means no entity at all
	}{
		{"documented opener enters the bang state", "```", "!`id`"},
		{"a longer run reads as a plain fence", "````", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.fence + "!\n!`id`\n" + tt.fence + "\n"
			var want []ir.Entity
			if tt.wantCmd != "" {
				want = []ir.Entity{ir.InlineShell{
					Command:  tt.wantCmd,
					Form:     "fenced",
					Shell:    "bash",
					Location: ir.Location{File: "f.md", Key: "body[2]"},
				}}
			}

			got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("inlineShellFromBody() = %+v, want %+v", got, want)
			}
		})
	}
}

// A ```! fence emits one entity per non-blank command line, with
// Location.Key's body[N] anchored to the original file.
func TestInlineShellFromBody_FencedFormEmitsPerNonBlankLine(t *testing.T) {
	body := "```!\necho one\n\necho two\necho three\n```\n"
	got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
	want := []ir.Entity{
		ir.InlineShell{Command: "echo one", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[2]"}},
		ir.InlineShell{Command: "echo two", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[4]"}},
		ir.InlineShell{Command: "echo three", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[5]"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inlineShellFromBody() = %+v, want %+v", got, want)
	}
}

// A ```! fence left open at EOF still yields every complete line seen.
func TestInlineShellFromBody_UnterminatedFencedFormAtEOF(t *testing.T) {
	body := "```!\necho one\necho two\n"
	got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
	want := []ir.Entity{
		ir.InlineShell{Command: "echo one", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[2]"}},
		ir.InlineShell{Command: "echo two", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[3]"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inlineShellFromBody() = %+v, want %+v", got, want)
	}
}

// A fenced command line containing its own !`...` text emits exactly ONE
// fenced entity, never an additional inline one.
func TestInlineShellFromBody_BangFenceLineDoesNotDoubleEmit(t *testing.T) {
	body := "```!\n!`curl -s https://x.tld/i.sh`\n```\n"
	got := inlineShellFromBody([]byte(body), 1, "bash", "f.md")
	want := []ir.Entity{
		ir.InlineShell{Command: "!`curl -s https://x.tld/i.sh`", Form: "fenced", Shell: "bash", Location: ir.Location{File: "f.md", Key: "body[2]"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inlineShellFromBody() = %+v, want %+v (exactly one fenced entity, no inline double-emit)", got, want)
	}
}

// A "!"-looking placeholder inside the frontmatter block never emits:
// frontmatterBody excludes that block from the body it returns.
func TestInlineShellFromBody_FrontmatterNeverScanned(t *testing.T) {
	const file = ".claude/skills/demo/SKILL.md"
	data := []byte("---\nname: demo\ndescription: \"looks like !`cmd` but is frontmatter\"\n---\nJust prose, no placeholder.\n")

	entities, warning := parseSkillFile(data, file)
	if warning != nil {
		t.Fatalf("parseSkillFile() warning = %+v, want nil", warning)
	}
	for _, e := range entities {
		if _, ok := e.(ir.InlineShell); ok {
			t.Fatalf("parseSkillFile() emitted an InlineShell from frontmatter text: %+v", entities)
		}
	}
}

// Shell defaults to "bash" when unset and carries an unrecognized frontmatter
// value VERBATIM.
func TestInlineShellFromBody_ShellDefaultAndCarry(t *testing.T) {
	const file = ".claude/skills/demo/SKILL.md"

	t.Run("absent shell defaults to bash", func(t *testing.T) {
		data := []byte("---\nname: demo\n---\nRun !`cmd`.\n")
		entities, _ := parseSkillFile(data, file)
		sh := onlyInlineShell(t, entities)
		if sh.Shell != "bash" {
			t.Errorf("Shell = %q, want %q", sh.Shell, "bash")
		}
	})

	t.Run("unrecognized shell value carried verbatim", func(t *testing.T) {
		data := []byte("---\nname: demo\nshell: zsh\n---\nRun !`cmd`.\n")
		entities, _ := parseSkillFile(data, file)
		sh := onlyInlineShell(t, entities)
		if sh.Shell != "zsh" {
			t.Errorf("Shell = %q, want %q", sh.Shell, "zsh")
		}
	})
}

// Parse walks .claude/commands recursively and scans each body independently
// of frontmatter validity.
func TestParse_CommandsDirectory(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/commands/deploy/run.md": &fstest.MapFile{Data: []byte(
			"Run !`echo hi` to deploy.\n",
		)},
		".claude/commands/bad.md": &fstest.MapFile{Data: []byte(
			"---\nname: [unterminated\nRun !`cmd`\n",
		)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("Parse() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	if warnings[0].File != ".claude/commands/bad.md" {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, ".claude/commands/bad.md")
	}
	want := []ir.Entity{
		ir.InlineShell{
			Command:  "echo hi",
			Form:     "inline",
			Shell:    "bash",
			Location: ir.Location{File: ".claude/commands/deploy/run.md", Key: "body[1]"},
		},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Errorf("Parse() entities = %+v, want %+v", entities, want)
	}
}

func TestCommandSiblingNonMarkdownStaysUnread(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/commands/run.md":    inlineBody("md-inline.sh"),
		".claude/commands/notes.txt": inlineBody("txt-inline.sh"),
	}

	entities, warnings, err := commandEntities(fsys)
	if err != nil {
		t.Fatalf("commandEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("commandEntities() warnings = %+v, want none", warnings)
	}
	if got := inlineShellCommands(entities); !slices.Equal(got, []string{"md-inline.sh"}) {
		t.Errorf("inline shell commands = %v, want [md-inline.sh] only", got)
	}
}

// Pins which capabilities a command file may declare. Each case asserts the
// exact entity slice, so an entity the adapter must not invent fails as
// loudly as one it must emit.
func TestParseCommandFile_Frontmatter(t *testing.T) {
	const file = ".claude/commands/deploy.md"

	tests := []struct {
		name        string
		data        string
		want        []ir.Entity
		wantWarning bool
	}{
		{
			name: "hooks emit ir.Hook before the body's inline shell",
			data: "---\nname: deploy\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: audit.sh\n---\nRun !`echo hi`.\n",
			want: []ir.Entity{
				ir.Hook{
					Event:    "PreToolUse",
					Matcher:  "Bash",
					Command:  "audit.sh",
					Location: ir.Location{File: file, Key: "hooks.PreToolUse[0].hooks[0]"},
				},
				ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "bash", Location: ir.Location{File: file, Key: "body[10]"}},
			},
		},
		{
			name: "frontmatter without hooks emits no presence entity",
			data: "---\nname: deploy\nshell: powershell\n---\nRun !`echo hi`.\n",
			want: []ir.Entity{
				ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "powershell", Location: ir.Location{File: file, Key: "body[5]"}},
			},
		},
		{
			name: "keys a command file cannot declare stay unsurfaced",
			data: "---\nname: deploy\nmcpServers:\n  fs:\n    command: /usr/local/bin/mcp-fs\npermissionMode: bypassPermissions\n---\nRun !`echo hi`.\n",
			want: []ir.Entity{
				ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "bash", Location: ir.Location{File: file, Key: "body[8]"}},
			},
		},
		{
			// A false negative hands out a clean bill of health while a
			// false positive only gets investigated, so a key's shape is
			// never allowed to silence the hook declared beside it.
			name: "a wrong-shaped key keeps the hook and raises no warning",
			data: "---\nname: [deploy]\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: attacker.sh\n---\nRun !`echo hi`.\n",
			want: []ir.Entity{
				ir.Hook{
					Event:    "PreToolUse",
					Command:  "attacker.sh",
					Location: ir.Location{File: file, Key: "hooks.PreToolUse[0].hooks[0]"},
				},
				ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "bash", Location: ir.Location{File: file, Key: "body[9]"}},
			},
		},
		{
			// An unclosed flow sequence is a SYNTAX error, so nothing
			// in the block is readable and no hook survives it.
			name: "unparseable frontmatter warns and still scans the body",
			data: "---\nname: [deploy\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: attacker.sh\n---\nRun !`echo hi`.\n",
			want: []ir.Entity{
				ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "bash", Location: ir.Location{File: file, Key: "body[9]"}},
			},
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warning := parseCommandFile([]byte(tt.data), file)

			if got := warning != nil; got != tt.wantWarning {
				t.Fatalf("parseCommandFile() warning present = %v, want %v: %+v", got, tt.wantWarning, warning)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Errorf("parseCommandFile() = %+v, want %+v", entities, tt.want)
			}
		})
	}
}

func TestCommandEntitiesUnreadableSubdirWarnsAndKeepsSiblings(t *testing.T) {
	fsys := failingReadDirFS{
		m: fstest.MapFS{
			".claude/commands/good.md":    &fstest.MapFile{Data: []byte("Run !`echo good`.\n")},
			".claude/commands/bad/cmd.md": &fstest.MapFile{Data: []byte("Run !`echo bad`.\n")},
		},
		failPath: ".claude/commands/bad",
	}

	entities, warnings, err := commandEntities(fsys)
	if err != nil {
		t.Fatalf("commandEntities() error = %v, want nil (a below-root failure must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("commandEntities() warnings = none, want a warning for the unreadable bad/ directory")
	}

	var commands []string
	for _, e := range entities {
		if sh, ok := e.(ir.InlineShell); ok {
			commands = append(commands, sh.Command)
		}
	}
	if len(commands) != 1 || commands[0] != "echo good" {
		t.Fatalf("commandEntities() Commands = %v, want exactly [echo good] (the sibling must survive the unreadable directory)", commands)
	}
}

func TestCommandEntitiesUnreadableFileWarnsAndKeepsSiblings(t *testing.T) {
	fsys := failingReadFileFS{
		m: fstest.MapFS{
			".claude/commands/good.md": &fstest.MapFile{Data: []byte("Run !`echo good`.\n")},
			".claude/commands/bad.md":  &fstest.MapFile{Data: []byte("Run !`echo bad`.\n")},
		},
		failPath: ".claude/commands/bad.md",
	}

	entities, warnings, err := commandEntities(fsys)
	if err != nil {
		t.Fatalf("commandEntities() error = %v, want nil (an unreadable file must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("commandEntities() warnings = none, want a warning for the unreadable bad.md")
	}

	var commands []string
	for _, e := range entities {
		if sh, ok := e.(ir.InlineShell); ok {
			commands = append(commands, sh.Command)
		}
	}
	if len(commands) != 1 || commands[0] != "echo good" {
		t.Fatalf("commandEntities() Commands = %v, want exactly [echo good] (the sibling must survive the unreadable file)", commands)
	}
}

func TestCommandEntitiesMissingRootStaysSilent(t *testing.T) {
	entities, warnings, err := commandEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("commandEntities() error = %v, want nil", err)
	}
	if entities != nil || warnings != nil {
		t.Fatalf("commandEntities() = (%v, %v), want (nil, nil) for a missing root", entities, warnings)
	}
}

func onlyInlineShell(t *testing.T, entities []ir.Entity) ir.InlineShell {
	t.Helper()
	var found []ir.InlineShell
	for _, e := range entities {
		if sh, ok := e.(ir.InlineShell); ok {
			found = append(found, sh)
		}
	}
	if len(found) != 1 {
		t.Fatalf("InlineShell count = %d, want 1: %+v", len(found), entities)
	}
	return found[0]
}
