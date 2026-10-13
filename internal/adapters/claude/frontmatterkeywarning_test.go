package claude

import (
	"reflect"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// warningText fails when the resolvers reported no warning at all.
func warningText(t *testing.T, w *adapter.Warning) string {
	t.Helper()
	if w == nil {
		t.Fatal("warning = nil, want a warning naming the key whose value was lost")
	}
	return w.Err.Error()
}

// A key the resolvers could not decode is a declaration the report never
// carries, so it must reach the caller as a warning. Silence here is the
// false clean this table exists to prevent: the same zero capabilities a
// genuinely empty file produces, with no signal separating them.
func TestParseSubagentFile_UnreadableKeyWarns(t *testing.T) {
	const file = ".claude/agents/reviewer.md"

	hooksBlock := "hooks:\n  SessionStart:\n    - hooks:\n        - type: command\n          command: on-start.sh\n"
	tests := []struct {
		name  string
		data  string
		wants []string
	}{
		{
			name:  "a hook command yaml reports only after populating its group",
			data:  "---\nname: r\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: [evil.sh]\n---\nb\n",
			wants: []string{"hooks", "PreToolUse[0]", "line 6"},
		},
		{
			name:  "a sequence permissionMode",
			data:  "---\nname: reviewer\npermissionMode: [bypassPermissions]\n" + hooksBlock + "---\nbody\n",
			wants: []string{"permissionMode", "line 2"},
		},
		{
			name:  "a mapping name",
			data:  "---\nname: {a: b}\n---\nbody\n",
			wants: []string{"name", "line 1"},
		},
		{
			name:  "a mapping tools",
			data:  "---\nname: reviewer\ntools: {a: b}\n---\nbody\n",
			wants: []string{"tools", "line 2"},
		},
		{
			name:  "a non-scalar tools item",
			data:  "---\nname: reviewer\ntools: [Read, [nested]]\n---\nbody\n",
			wants: []string{"tools", "line 2"},
		},
		{
			name:  "a sequence hooks block",
			data:  "---\nname: reviewer\nhooks:\n  - PreToolUse\n---\nbody\n",
			wants: []string{"hooks", "line 3"},
		},
		{
			name:  "a mapping under an event name",
			data:  "---\nname: reviewer\nhooks:\n  PreToolUse:\n    matcher: Bash\n---\nbody\n",
			wants: []string{"hooks", "PreToolUse", "line 4"},
		},
		{
			name:  "a scalar where a hook group belongs",
			data:  "---\nname: reviewer\nhooks:\n  PreToolUse:\n    - not-a-group\n---\nbody\n",
			wants: []string{"hooks", "PreToolUse[0]", "line 4"},
		},
		{
			name:  "a scalar mcpServers",
			data:  "---\nname: reviewer\nmcpServers: db\n---\nbody\n",
			wants: []string{"mcpServers", "line 2"},
		},
		{
			name:  "a sequence mcpServers holding a non-string",
			data:  "---\nname: reviewer\nmcpServers: [db, [nested]]\n---\nbody\n",
			wants: []string{"mcpServers", "line 2"},
		},
		{
			name:  "an mcpServers entry of an unreadable shape",
			data:  "---\nname: reviewer\nmcpServers:\n  db: [mcp-db]\n---\nbody\n",
			wants: []string{"mcpServers", "db", "line 3"},
		},
		{
			name:  "an event name of an unreadable shape",
			data:  "---\nname: reviewer\nhooks:\n  ? [PreToolUse]\n  : - hooks:\n      - type: command\n        command: x.sh\n---\nbody\n",
			wants: []string{"hooks", "entry 0", "line 3"},
		},
		{
			name:  "an mcpServers entry name of an unreadable shape",
			data:  "---\nname: reviewer\nmcpServers:\n  ? [db]\n  : {command: mcp-db}\n---\nbody\n",
			wants: []string{"mcpServers", "entry 0", "line 3"},
		},
		{
			name:  "an mcpServers list item key of an unreadable shape",
			data:  "---\nname: reviewer\nmcpServers:\n  - ? [db]\n    : {command: mcp-db}\n---\nbody\n",
			wants: []string{"mcpServers", "entry 0", "line 3"},
		},
		{
			name:  "a name scalar the decoder rejects",
			data:  "---\nname: !!binary \"not base64 @@\"\n---\nbody\n",
			wants: []string{"name", "base64"},
		},
		{
			name:  "a tools scalar the decoder rejects",
			data:  "---\nname: reviewer\ntools: !!binary \"not base64 @@\"\n---\nbody\n",
			wants: []string{"tools", "base64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, warning := parseSubagentFile([]byte(tt.data), file, false)
			got := warningText(t, warning)
			if warning.File != file {
				t.Errorf("warning.File = %q, want %q", warning.File, file)
			}
			// A warning is one line of stderr; yaml.v3 renders a
			// TypeError across several.
			if strings.Contains(got, "\n") {
				t.Errorf("warning = %q, want a single line", got)
			}
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Errorf("warning = %q, want it to name %q", got, want)
				}
			}
		})
	}
}

// A key that is merely ABSENT — never written, or written with an empty
// value — declares nothing and loses nothing, so it must stay silent. A
// warning here would degrade every ordinary agent file.
func TestParseSubagentFile_AbsentAndEmptyKeysStaySilent(t *testing.T) {
	const file = ".claude/agents/reviewer.md"

	tests := []struct {
		name string
		data string
	}{
		{name: "every optional key absent", data: "---\nname: reviewer\n---\nbody\n"},
		{
			name: "every optional key present but empty",
			data: "---\nname:\npermissionMode:\ntools:\nmcpServers:\nhooks:\n---\nbody\n",
		},
		{
			name: "readable but empty collections",
			data: "---\nname: reviewer\ntools: []\nmcpServers: {}\nhooks: {}\n---\nbody\n",
		},
		{
			name: "an empty event list",
			data: "---\nname: reviewer\nhooks:\n  PreToolUse: []\n  SessionStart:\n---\nbody\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, warning := parseSubagentFile([]byte(tt.data), file, false); warning != nil {
				t.Errorf("parseSubagentFile() warning = %v, want nil", warning.Err)
			}
		})
	}
}

// The entity and the warning must COEXIST: asserting one is not asserting
// the other, so this pins that a readable sibling still surfaces.
func TestParseSubagentFile_UnreadableKeyWarnsAndKeepsSiblingEntities(t *testing.T) {
	const file = ".claude/agents/reviewer.md"
	loc := func(key string) ir.Location { return ir.Location{File: file, Key: key} }

	data := "---\nname: reviewer\npermissionMode: [bypassPermissions]\n" +
		"hooks:\n  SessionStart:\n    - hooks:\n        - type: command\n          command: on-start.sh\n---\nbody\n"

	entities, warning := parseSubagentFile([]byte(data), file, false)
	want := []ir.Entity{
		ir.Hook{Event: "SessionStart", Command: "on-start.sh", Location: loc("hooks.SessionStart[0].hooks[0]")},
		ir.Subagent{Name: "reviewer", Location: loc("name")},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Errorf("parseSubagentFile() = %+v, want %+v", entities, want)
	}
	if got := warningText(t, warning); !strings.Contains(got, "permissionMode") {
		t.Errorf("warning = %q, want it to name permissionMode", got)
	}
}

// Several lost keys in one file are one warning, so the facade's per-source
// tally counts the file once.
func TestParseSubagentFile_SeveralUnreadableKeysWarnOnce(t *testing.T) {
	const file = ".claude/agents/reviewer.md"

	data := "---\nname: [r]\npermissionMode: {mode: bypassPermissions}\ntools: {a: b}\n---\nbody\n"

	_, warning := parseSubagentFile([]byte(data), file, false)
	got := warningText(t, warning)
	for _, key := range []string{"name", "permissionMode", "tools"} {
		if !strings.Contains(got, key) {
			t.Errorf("warning = %q, want it to name %q", got, key)
		}
	}
}

// The fault half of entitiesFromSubagent's carve-out: a suppressed key
// stays silent, permissionMode does not.
func TestParseSubagentFile_PluginCarveOut(t *testing.T) {
	const file = "plugins/vendor/agents/foo.md"

	suppressed := "---\nname: foo\nmcpServers: db\n" +
		"hooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n          command: [evil.sh]\n---\nbody\n"

	if _, warning := parseSubagentFile([]byte(suppressed), file, true); warning != nil {
		t.Errorf("parseSubagentFile(isPlugin=true) warning = %v, want nil", warning.Err)
	}

	displayed := "---\nname: foo\npermissionMode: [bypassPermissions]\n---\nbody\n"

	_, warning := parseSubagentFile([]byte(displayed), file, true)
	if got := warningText(t, warning); !strings.Contains(got, "permissionMode") {
		t.Errorf("warning = %q, want it to name permissionMode", got)
	}
}

// shell: is the skill surface's own key, and its fault costs the body the
// shell it declared.
func TestParseSkillFile_UnreadableKeyWarns(t *testing.T) {
	const file = ".claude/skills/demo/SKILL.md"

	hooksBlock := "hooks:\n  SessionStart:\n    - hooks:\n        - type: command\n          command: on-start.sh\n"
	tests := []struct {
		name  string
		data  string
		wants []string
	}{
		{
			name:  "a sequence name",
			data:  "---\nname: [demo]\n" + hooksBlock + "---\nbody\n",
			wants: []string{"name"},
		},
		{
			name:  "a sequence shell",
			data:  "---\nname: demo\nshell: [powershell]\n" + hooksBlock + "---\nbody\n",
			wants: []string{"shell"},
		},
		{
			name:  "an unreadable hook command",
			data:  "---\nname: demo\nhooks:\n  SessionStart:\n    - hooks:\n        - type: command\n          command: [evil.sh]\n---\nbody\n",
			wants: []string{"hooks", "SessionStart[0]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, warning := parseSkillFile([]byte(tt.data), file)
			got := warningText(t, warning)
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Errorf("warning = %q, want it to name %q", got, want)
				}
			}
		})
	}
}

// The command surface decodes the same hooks key, and its body command must
// survive the warning exactly as the skill's does.
func TestParseCommandFile_UnreadableHookWarnsAndKeepsTheBodyCommand(t *testing.T) {
	const file = ".claude/commands/demo.md"

	data := "---\nhooks:\n  SessionStart:\n    - hooks:\n        - type: command\n          command: [evil.sh]\n---\nRun !`echo hi`.\n"

	entities, warning := parseCommandFile([]byte(data), file)
	want := []ir.Entity{
		ir.Hook{Event: "SessionStart", Location: ir.Location{File: file, Key: "hooks.SessionStart[0].hooks[0]"}},
		ir.InlineShell{Command: "echo hi", Form: "inline", Shell: "bash", Location: ir.Location{File: file, Key: "body[8]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Errorf("parseCommandFile() = %+v, want %+v", entities, want)
	}
	if got := warningText(t, warning); !strings.Contains(got, "hooks") {
		t.Errorf("warning = %q, want it to name hooks", got)
	}
}
