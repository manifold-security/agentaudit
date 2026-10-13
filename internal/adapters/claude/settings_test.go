package claude

import (
	"fmt"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func parseEntities(fsys fstest.MapFS) ([]ir.Entity, error) {
	entities, _, err := New().Parse(fsys)
	return entities, err
}

func mapFS(file, data string) fstest.MapFS {
	return fstest.MapFS{
		".claude/" + file: &fstest.MapFile{Data: []byte(data)},
	}
}

func TestParse_HookFanOut(t *testing.T) {
	fsys := mapFS("settings.json", `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [
					{"type": "command", "command": "audit1.sh"},
					{"type": "command", "command": "audit2.sh"}
				]},
				{"matcher": "Edit", "hooks": [
					{"type": "command", "command": "audit3.sh"},
					{"type": "command", "command": "audit4.sh"}
				]}
			]
		}
	}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 4 {
		t.Fatalf("Parse() entities len = %d, want 4: %+v", len(entities), entities)
	}

	wantKeys := []string{
		"hooks.PreToolUse[0].hooks[0]",
		"hooks.PreToolUse[0].hooks[1]",
		"hooks.PreToolUse[1].hooks[0]",
		"hooks.PreToolUse[1].hooks[1]",
	}
	wantCommands := []string{"audit1.sh", "audit2.sh", "audit3.sh", "audit4.sh"}
	wantMatchers := []string{"Bash", "Bash", "Edit", "Edit"}

	for i, e := range entities {
		hook, ok := e.(ir.Hook)
		if !ok {
			t.Fatalf("entities[%d] type = %T, want ir.Hook", i, e)
		}
		if hook.Event != "PreToolUse" {
			t.Errorf("entities[%d].Event = %q, want %q", i, hook.Event, "PreToolUse")
		}
		if hook.Matcher != wantMatchers[i] {
			t.Errorf("entities[%d].Matcher = %q, want %q", i, hook.Matcher, wantMatchers[i])
		}
		if hook.Command != wantCommands[i] {
			t.Errorf("entities[%d].Command = %q, want %q", i, hook.Command, wantCommands[i])
		}
		if hook.Location.Key != wantKeys[i] {
			t.Errorf("entities[%d].Location.Key = %q, want %q", i, hook.Location.Key, wantKeys[i])
		}
		if hook.Location.File != ".claude/settings.json" {
			t.Errorf("entities[%d].Location.File = %q, want %q", i, hook.Location.File, ".claude/settings.json")
		}
	}
}

func TestParse_StatusLine(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		fsys := mapFS("settings.json", `{"statusLine": {"type": "command", "command": "statusline.sh"}}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 1 {
			t.Fatalf("Parse() entities len = %d, want 1: %+v", len(entities), entities)
		}
		sl, ok := entities[0].(ir.StatusLine)
		if !ok {
			t.Fatalf("entities[0] type = %T, want ir.StatusLine", entities[0])
		}
		if sl.Command != "statusline.sh" {
			t.Errorf("Command = %q, want %q", sl.Command, "statusline.sh")
		}
		if sl.Location.Key != "statusLine.command" {
			t.Errorf("Location.Key = %q, want %q", sl.Location.Key, "statusLine.command")
		}
	})

	t.Run("absent", func(t *testing.T) {
		fsys := mapFS("settings.json", `{}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 0 {
			t.Fatalf("Parse() entities len = %d, want 0: %+v", len(entities), entities)
		}
	})
}

func TestParse_CredentialHelpers(t *testing.T) {
	t.Run("all three present", func(t *testing.T) {
		fsys := mapFS("settings.json", `{
			"apiKeyHelper": "get-key.sh",
			"awsAuthRefresh": "refresh.sh",
			"awsCredentialExport": "export.sh"
		}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 3 {
			t.Fatalf("Parse() entities len = %d, want 3: %+v", len(entities), entities)
		}

		wantVariants := []string{ir.VariantAPIKeyHelper, ir.VariantAWSAuthRefresh, ir.VariantAWSCredentialExport}
		wantCommands := []string{"get-key.sh", "refresh.sh", "export.sh"}
		wantKeys := []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport"}

		for i, e := range entities {
			ch, ok := e.(ir.CredentialHelper)
			if !ok {
				t.Fatalf("entities[%d] type = %T, want ir.CredentialHelper", i, e)
			}
			if ch.Variant != wantVariants[i] {
				t.Errorf("entities[%d].Variant = %q, want %q", i, ch.Variant, wantVariants[i])
			}
			if ch.Command != wantCommands[i] {
				t.Errorf("entities[%d].Command = %q, want %q", i, ch.Command, wantCommands[i])
			}
			if ch.Location.Key != wantKeys[i] {
				t.Errorf("entities[%d].Location.Key = %q, want %q", i, ch.Location.Key, wantKeys[i])
			}
		}
	})

	t.Run("only apiKeyHelper present", func(t *testing.T) {
		fsys := mapFS("settings.json", `{"apiKeyHelper": "get-key.sh"}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 1 {
			t.Fatalf("Parse() entities len = %d, want 1: %+v", len(entities), entities)
		}
		ch, ok := entities[0].(ir.CredentialHelper)
		if !ok {
			t.Fatalf("entities[0] type = %T, want ir.CredentialHelper", entities[0])
		}
		if ch.Variant != ir.VariantAPIKeyHelper {
			t.Errorf("Variant = %q, want %q", ch.Variant, ir.VariantAPIKeyHelper)
		}
	})
}

func TestParse_EnvBlock(t *testing.T) {
	fsys := mapFS("settings.json", `{"env": {"ZETA": "z", "ALPHA": "a"}}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 2 {
		t.Fatalf("Parse() entities len = %d, want 2: %+v", len(entities), entities)
	}

	wantNames := []string{"ALPHA", "ZETA"}
	wantValues := []string{"a", "z"}
	for i, e := range entities {
		ev, ok := e.(ir.EnvVar)
		if !ok {
			t.Fatalf("entities[%d] type = %T, want ir.EnvVar", i, e)
		}
		if ev.Name != wantNames[i] {
			t.Errorf("entities[%d].Name = %q, want %q", i, ev.Name, wantNames[i])
		}
		if ev.Value != wantValues[i] {
			t.Errorf("entities[%d].Value = %q, want %q", i, ev.Value, wantValues[i])
		}
		wantKey := "env." + wantNames[i]
		if ev.Location.Key != wantKey {
			t.Errorf("entities[%d].Location.Key = %q, want %q", i, ev.Location.Key, wantKey)
		}
	}
}

func TestParse_SandboxFanOut(t *testing.T) {
	fsys := mapFS("settings.json", `{"sandbox": {"network": {"allowUnixSockets": ["/tmp/a.sock", "/tmp/b.sock"]}}}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 2 {
		t.Fatalf("Parse() entities len = %d, want 2: %+v", len(entities), entities)
	}

	wantPaths := []string{"/tmp/a.sock", "/tmp/b.sock"}
	wantKeys := []string{"sandbox.network.allowUnixSockets[0]", "sandbox.network.allowUnixSockets[1]"}
	for i, e := range entities {
		sb, ok := e.(ir.Sandbox)
		if !ok {
			t.Fatalf("entities[%d] type = %T, want ir.Sandbox", i, e)
		}
		if sb.SocketPath != wantPaths[i] {
			t.Errorf("entities[%d].SocketPath = %q, want %q", i, sb.SocketPath, wantPaths[i])
		}
		if sb.Location.Key != wantKeys[i] {
			t.Errorf("entities[%d].Location.Key = %q, want %q", i, sb.Location.Key, wantKeys[i])
		}
	}
}

// The socket list reaches the IR only through the sandbox.network nesting.
// A flat sandbox.allowUnixSockets key is inert in Claude Code, so an entity
// built from it would report a grant the config does not make.
func TestParse_SandboxSocketsComeOnlyFromNetwork(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		want     int
	}{
		{"documented nesting", `{"sandbox": {"network": {"allowUnixSockets": ["/tmp/a.sock"]}}}`, 1},
		{"flat spelling", `{"sandbox": {"allowUnixSockets": ["/tmp/a.sock"]}}`, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entities, err := parseEntities(mapFS("settings.json", tc.settings))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(entities) != tc.want {
				t.Fatalf("Parse() entities len = %d, want %d: %+v", len(entities), tc.want, entities)
			}
		})
	}
}

func TestParse_DefaultMode(t *testing.T) {
	fsys := mapFS("settings.json", `{"permissions": {"defaultMode": "bypassPermissions"}}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() entities len = %d, want 1: %+v", len(entities), entities)
	}

	mode, ok := entities[0].(ir.PermissionMode)
	if !ok {
		t.Fatalf("entities[0] type = %T, want ir.PermissionMode", entities[0])
	}
	if mode.Mode != "bypassPermissions" {
		t.Errorf("Mode = %q, want %q", mode.Mode, "bypassPermissions")
	}
	if mode.Location.Key != "permissions.defaultMode" {
		t.Errorf("Location.Key = %q, want %q", mode.Location.Key, "permissions.defaultMode")
	}
	if mode.Source != "permissions.defaultMode" {
		t.Errorf("Source = %q, want %q", mode.Source, "permissions.defaultMode")
	}
}

// permissions.defaultMode is read from its own key, not inferred from the
// permissions object's presence.
func TestParse_DefaultModeAbsent(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"no permissions object", `{}`},
		{"permissions object without defaultMode", `{"permissions": {"allow": ["Bash(git *)"], "deny": ["Read(.env)"]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapFS("settings.json", tt.json)

			entities, err := parseEntities(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(entities) != 0 {
				t.Fatalf("Parse() entities = %+v, want empty (no permissions.defaultMode present)", entities)
			}
		})
	}
}

func TestParse_MCPApprovalEnableAll(t *testing.T) {
	tests := []struct {
		name string
		json string
		want []string // nil means "no entity"; non-nil is the single Value
	}{
		{"true", `{"enableAllProjectMcpServers": true}`, []string{"true"}},
		{"false", `{"enableAllProjectMcpServers": false}`, []string{"false"}},
		{"absent", `{}`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapFS("settings.json", tt.json)

			entities, err := parseEntities(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if tt.want == nil {
				if len(entities) != 0 {
					t.Fatalf("Parse() entities = %+v, want empty (no enableAllProjectMcpServers present)", entities)
				}
				return
			}

			if len(entities) != 1 {
				t.Fatalf("Parse() entities len = %d, want 1: %+v", len(entities), entities)
			}
			mcp, ok := entities[0].(ir.MCPApproval)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPApproval", entities[0])
			}
			if mcp.Setting != "enableAllProjectMcpServers" {
				t.Errorf("Setting = %q, want %q", mcp.Setting, "enableAllProjectMcpServers")
			}
			if mcp.Value != tt.want[0] {
				t.Errorf("Value = %q, want %q", mcp.Value, tt.want[0])
			}
			if mcp.Location.Key != "enableAllProjectMcpServers" {
				t.Errorf("Location.Key = %q, want %q", mcp.Location.Key, "enableAllProjectMcpServers")
			}
		})
	}
}

func TestParse_MCPApprovalEnabledList(t *testing.T) {
	t.Run("two entries", func(t *testing.T) {
		fsys := mapFS("settings.json", `{"enabledMcpjsonServers": ["memory", "github"]}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 2 {
			t.Fatalf("Parse() entities len = %d, want 2: %+v", len(entities), entities)
		}

		wantValues := []string{"memory", "github"}
		for i, e := range entities {
			mcp, ok := e.(ir.MCPApproval)
			if !ok {
				t.Fatalf("entities[%d] type = %T, want ir.MCPApproval", i, e)
			}
			if mcp.Setting != "enabledMcpjsonServers" {
				t.Errorf("entities[%d].Setting = %q, want %q", i, mcp.Setting, "enabledMcpjsonServers")
			}
			if mcp.Value != wantValues[i] {
				t.Errorf("entities[%d].Value = %q, want %q", i, mcp.Value, wantValues[i])
			}
			wantKey := fmt.Sprintf("enabledMcpjsonServers[%d]", i)
			if mcp.Location.Key != wantKey {
				t.Errorf("entities[%d].Location.Key = %q, want %q", i, mcp.Location.Key, wantKey)
			}
		}
	})

	t.Run("empty list", func(t *testing.T) {
		fsys := mapFS("settings.json", `{"enabledMcpjsonServers": []}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 0 {
			t.Fatalf("Parse() entities = %+v, want empty", entities)
		}
	})

	t.Run("absent", func(t *testing.T) {
		fsys := mapFS("settings.json", `{}`)

		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}
		if len(entities) != 0 {
			t.Fatalf("Parse() entities = %+v, want empty", entities)
		}
	})
}

func TestParse_MissingFile(t *testing.T) {
	entities, err := parseEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want empty", entities)
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	fsys := mapFS("settings.json", `not json`)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse() panicked: %v", r)
		}
	}()

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil (malformed source recovers via Warning, not a fatal error)", err)
	}
	if entities != nil {
		t.Fatalf("Parse() entities = %v, want nil (malformed file contributes no entities)", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("Parse() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	if warnings[0].File != ".claude/settings.json" {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, ".claude/settings.json")
	}
	if warnings[0].Err == nil {
		t.Errorf("warnings[0].Err = nil, want non-nil")
	}
}

// A malformed .claude/settings.json alongside a valid settings.local.json
// warns for the malformed file while the sibling's entities still return.
func TestParse_MalformedSettingsWarnsSiblingSurvives(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json":       &fstest.MapFile{Data: []byte(`not json`)},
		".claude/settings.local.json": &fstest.MapFile{Data: []byte(`{"apiKeyHelper": "get-key.sh"}`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("Parse() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	if warnings[0].File != ".claude/settings.json" {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, ".claude/settings.json")
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() entities len = %d, want 1 (settings.local.json survives): %+v", len(entities), entities)
	}
	ch, ok := entities[0].(ir.CredentialHelper)
	if !ok {
		t.Fatalf("entities[0] type = %T, want ir.CredentialHelper", entities[0])
	}
	if ch.Location.File != ".claude/settings.local.json" {
		t.Errorf("entities[0].Location.File = %q, want %q", ch.Location.File, ".claude/settings.local.json")
	}
}

// The unreadable file and the surviving sibling are both settings files, so
// the skip has to be per file rather than per source.
func TestParse_UnreadableSettingsWarnsSiblingSurvives(t *testing.T) {
	fsys := failingReadFileFS{
		m: fstest.MapFS{
			".claude/settings.json":       &fstest.MapFile{Data: []byte(`{"apiKeyHelper": "get-key.sh"}`)},
			".claude/settings.local.json": &fstest.MapFile{Data: []byte(`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"notify.sh"}]}]}}`)},
		},
		failPath: ".claude/settings.json",
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil (an unreadable settings file must warn, never abort)", err)
	}

	var foundWarning bool
	for _, w := range warnings {
		if w.File == ".claude/settings.json" {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("Parse() warnings = %+v, want one naming .claude/settings.json", warnings)
	}

	var hooks []ir.Hook
	for _, e := range entities {
		if h, ok := e.(ir.Hook); ok {
			hooks = append(hooks, h)
		}
	}
	if len(hooks) != 1 || hooks[0].Command != "notify.sh" {
		t.Fatalf("Parse() Hooks = %+v, want exactly [notify.sh] (the sibling settings.local.json hook must survive)", hooks)
	}
}

// The same hook event in both files yields two distinct Location.File values.
func TestParse_SameHookEventBothFilesYieldsDistinctProvenance(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{
			"hooks": {"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "base.sh"}]}]}
		}`)},
		".claude/settings.local.json": &fstest.MapFile{Data: []byte(`{
			"hooks": {"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "local.sh"}]}]}
		}`)},
	}

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 2 {
		t.Fatalf("Parse() entities len = %d, want 2: %+v", len(entities), entities)
	}

	files := map[string]bool{}
	for _, e := range entities {
		hook, ok := e.(ir.Hook)
		if !ok {
			t.Fatalf("entity type = %T, want ir.Hook", e)
		}
		files[hook.Location.File] = true
	}
	if !files[".claude/settings.json"] || !files[".claude/settings.local.json"] {
		t.Fatalf("Location.File set = %v, want both settings.json and settings.local.json represented", files)
	}
}

// Repeated Parse calls over one input yield identical ordered Location.Key
// sequences.
func TestParse_Determinism(t *testing.T) {
	fsys := mapFS("settings.json", `{
		"hooks": {
			"Stop": [{"matcher": "", "hooks": [{"type": "command", "command": "s.sh"}]}],
			"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "p.sh"}]}],
			"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "a.sh"}]}],
			"PostToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "o.sh"}]}]
		},
		"env": {"ZETA": "z", "ALPHA": "a", "MU": "m", "BETA": "b"}
	}`)

	var first []string
	for i := 0; i < 20; i++ {
		entities, err := parseEntities(fsys)
		if err != nil {
			t.Fatalf("Parse() error = %v, want nil", err)
		}

		var keys []string
		for _, e := range entities {
			keys = append(keys, ir.LocationOf(e).Key)
		}

		if first == nil {
			first = keys
			continue
		}
		if len(keys) != len(first) {
			t.Fatalf("run %d: keys len = %d, want %d", i, len(keys), len(first))
		}
		for j := range keys {
			if keys[j] != first[j] {
				t.Fatalf("run %d: keys[%d] = %q, want %q (non-deterministic order)", i, j, keys[j], first[j])
			}
		}
	}
}
