package claude

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

const cleanLocalSettings = `{"apiKeyHelper": "get-key.sh"}`

func localCredentialHelper() ir.Entity {
	return ir.CredentialHelper{
		Variant:  "apiKeyHelper",
		Command:  "get-key.sh",
		Location: ir.Location{File: ".claude/settings.local.json", Key: "apiKeyHelper"},
	}
}

// The colliding file is refused whole and named, while the sibling settings
// file still reports.
func TestParse_SettingsKeysDifferingOnlyInCaseDropTheFile(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{
			"the hooks block",
			`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch ./m"}]}]},"Hooks":null}`,
			`.claude/settings.json: key "Hooks" differs only in case from "hooks"`,
		},
		{
			"a lone hooks key in another case",
			`{"HOOKS":{"SessionStart":[{"hooks":[{"type":"command","command":"a"}]}]}}`,
			`.claude/settings.json: key "HOOKS" differs only in case from "hooks"`,
		},
		{
			"an escaped hooks key",
			`{"\u0048ooks":{"SessionStart":[{"hooks":[{"type":"command","command":"a"}]}]}}`,
			`.claude/settings.json: key "Hooks" differs only in case from "hooks"`,
		},
		{
			"a hook command",
			`{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"a","Command":"b"}]}]}}`,
			`.claude/settings.json: hooks.SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`,
		},
		{
			"the env map",
			`{"env":{"A":"1"},"Env":null}`,
			`.claude/settings.json: key "Env" differs only in case from "env"`,
		},
		{
			"a credential helper",
			`{"apiKeyHelper":"a.sh","ApiKeyHelper":"b.sh"}`,
			`.claude/settings.json: key "ApiKeyHelper" differs only in case from "apiKeyHelper"`,
		},
		{
			"the default mode",
			`{"permissions":{"defaultMode":"plan","DefaultMode":"default"}}`,
			`.claude/settings.json: permissions: key "DefaultMode" differs only in case from "defaultMode"`,
		},
		{
			"the allow list",
			`{"permissions":{"allow":["Bash(curl:*)"],"Allow":null}}`,
			`.claude/settings.json: permissions: key "Allow" differs only in case from "allow"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				".claude/settings.json":       &fstest.MapFile{Data: []byte(tc.body)},
				".claude/settings.local.json": &fstest.MapFile{Data: []byte(cleanLocalSettings)},
			}

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if want := []string{tc.want}; !reflect.DeepEqual(warningTexts(warnings), want) {
				t.Errorf("warnings = %q, want %q", warningTexts(warnings), want)
			}
			if want := []ir.Entity{localCredentialHelper()}; !reflect.DeepEqual(entities, want) {
				t.Errorf("entities = %+v, want %+v", entities, want)
			}
		})
	}
}

// Keys that match a field exactly, or no field, decode without a warning.
func TestParse_SettingsKeepKeysTheAgentReadsApart(t *testing.T) {
	hook := func(event, command string) ir.Entity {
		return ir.Hook{
			Event:    event,
			Command:  command,
			Location: ir.Location{File: settingsFile, Key: "hooks." + event + "[0].hooks[0]"},
		}
	}
	for _, tc := range []struct {
		name, body string
		want       []ir.Entity
	}{
		{
			"env names",
			`{"env":{"PATH":"a","path":"b"}}`,
			[]ir.Entity{
				ir.EnvVar{Name: "PATH", Value: "a", Location: ir.Location{File: settingsFile, Key: "env.PATH"}},
				ir.EnvVar{Name: "path", Value: "b", Location: ir.Location{File: settingsFile, Key: "env.path"}},
			},
		},
		{
			"hook event names",
			`{"hooks":{"SessionStart":[{"hooks":[{"command":"a"}]}],"sessionStart":[{"hooks":[{"command":"b"}]}]}}`,
			[]ir.Entity{hook("SessionStart", "a"), hook("sessionStart", "b")},
		},
		{
			"an exact duplicate key",
			`{"hooks":{"SessionStart":[{"hooks":[{"command":"a"}]}]},"hooks":{"SessionStart":[{"hooks":[{"command":"b"}]}]}}`,
			[]ir.Entity{hook("SessionStart", "b")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(mapFS("settings.json", tc.body))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			wantNoWarnings(t, warnings)
			if !reflect.DeepEqual(entities, tc.want) {
				t.Errorf("entities = %+v, want %+v", entities, tc.want)
			}
		})
	}
}

func serverKeys(t *testing.T, entities []ir.Entity) []string {
	t.Helper()
	keys := make([]string, 0, len(entities))
	for _, e := range entities {
		srv, ok := e.(ir.MCPServer)
		if !ok {
			t.Fatalf("entity type = %T, want ir.MCPServer", e)
		}
		keys = append(keys, srv.Location.Key)
	}
	return keys
}

// A mismatched top-level key refuses .claude.json whole, and one inside a
// project block refuses that project alone.
func TestParseGlobal_ClaudeJSONKeysDifferingOnlyInCase(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		wantWarnings []string
		wantServers  []string
	}{
		{
			"the top level",
			`{"mcpServers":{"a":{"command":"x"}},"MCPServers":null}`,
			[]string{`.claude.json: key "MCPServers" differs only in case from "mcpServers"`},
			[]string{},
		},
		{
			"one project",
			`{"projects":{"/a":{"mcpServers":{"a":{"command":"x"}},"McpServers":null},"/b":{"mcpServers":{"b":{"command":"y"}}}}}`,
			[]string{`.claude.json: projects./a: key "McpServers" differs only in case from "mcpServers"`},
			[]string{"projects./b.mcpServers.b"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{".claude.json": &fstest.MapFile{Data: []byte(tc.body)}}

			entities, warnings, err := New().ParseGlobal(fsys)
			if err != nil {
				t.Fatalf("ParseGlobal() error = %v, want nil", err)
			}
			if got := warningTexts(warnings); !reflect.DeepEqual(got, tc.wantWarnings) {
				t.Errorf("warnings = %q, want %q", got, tc.wantWarnings)
			}
			if got := serverKeys(t, entities); !reflect.DeepEqual(got, tc.wantServers) {
				t.Errorf("servers = %q, want %q", got, tc.wantServers)
			}
		})
	}
}

const keycasePluginManifest = "plugins/p/.claude-plugin/plugin.json"

func pluginTree(manifest, file, body string) fstest.MapFS {
	return fstest.MapFS{
		keycasePluginManifest: &fstest.MapFile{Data: []byte(manifest)},
		file:                  &fstest.MapFile{Data: []byte(body)},
	}
}

// A colliding plugin document is refused and named, while the plugin itself
// still reports.
func TestParse_PluginKeysDifferingOnlyInCase(t *testing.T) {
	const hookBody = `{"hooks":[{"command":"a"}]}`
	for _, tc := range []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{
			"the manifest",
			pluginTree(`{"name":"q","hooks":"./h.json","Hooks":null}`, "plugins/p/h.json", `{"SessionStart":[`+hookBody+`]}`),
			keycasePluginManifest + `: key "Hooks" differs only in case from "hooks"`,
		},
		{
			"the mcp wrapper",
			pluginTree(`{"name":"p"}`, "plugins/p/.mcp.json", `{"mcpServers":{"a":{"command":"x"}},"McpServers":null}`),
			`plugins/p/.mcp.json: key "McpServers" differs only in case from "mcpServers"`,
		},
		{
			"a lone commands key",
			pluginTree(`{"name":"p","Commands":[]}`, "plugins/p/README.md", `x`),
			keycasePluginManifest + `: key "Commands" differs only in case from "commands"`,
		},
		{
			"a lone mcp wrapper key",
			pluginTree(`{"name":"p"}`, "plugins/p/.mcp.json", `{"MCPServers":{"a":{"command":"x"}}}`),
			`plugins/p/.mcp.json: key "MCPServers" differs only in case from "mcpServers"`,
		},
		{
			"a lone hooks wrapper key",
			pluginTree(`{"name":"p"}`, "plugins/p/hooks/hooks.json", `{"Hooks":{"SessionStart":[`+hookBody+`]}}`),
			`plugins/p/hooks/hooks.json: key "Hooks" differs only in case from "hooks"`,
		},
		{
			"the hooks wrapper",
			pluginTree(`{"name":"p"}`, "plugins/p/hooks/hooks.json", `{"hooks":{"SessionStart":[`+hookBody+`]},"Hooks":null}`),
			`plugins/p/hooks/hooks.json: key "Hooks" differs only in case from "hooks"`,
		},
		{
			"a hook command under the wrapper",
			pluginTree(`{"name":"p"}`, "plugins/p/hooks/hooks.json", `{"hooks":{"SessionStart":[{"hooks":[{"command":"a","Command":"b"}]}]}}`),
			`plugins/p/hooks/hooks.json: hooks.SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`,
		},
		{
			"a hook command in a bare map",
			pluginTree(`{"name":"p"}`, "plugins/p/hooks/hooks.json", `{"SessionStart":[{"hooks":[{"command":"a","Command":"b"}]}]}`),
			`plugins/p/hooks/hooks.json: SessionStart[0].hooks[0]: key "Command" differs only in case from "command"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entities, warnings := pluginEntities(tc.fsys)

			if want := []string{tc.want}; !reflect.DeepEqual(warningTexts(warnings), want) {
				t.Errorf("warnings = %q, want %q", warningTexts(warnings), want)
			}
			want := []ir.Entity{ir.Plugin{Name: "p", Location: ir.Location{File: keycasePluginManifest, Key: "name"}}}
			if !reflect.DeepEqual(entities, want) {
				t.Errorf("entities = %+v, want only the presence entity %+v", entities, want)
			}
		})
	}
}

// The same wrapper without the colliding key reports its hook, so the
// refusal above is what removes it.
func TestParse_PluginHooksWrapperWithoutACollisionReportsTheHook(t *testing.T) {
	fsys := pluginTree(`{"name":"p"}`, "plugins/p/hooks/hooks.json", `{"hooks":{"SessionStart":[{"hooks":[{"command":"a"}]}]}}`)

	entities, warnings := pluginEntities(fsys)

	wantNoWarnings(t, warnings)
	if len(entities) != 2 {
		t.Fatalf("entities = %+v, want the presence entity and the hook", entities)
	}
	if hook, ok := entities[1].(ir.Hook); !ok || hook.Command != "a" {
		t.Errorf("entities[1] = %+v, want the hook running a", entities[1])
	}
}

// The colliding server is dropped and its sibling still reports.
func TestParse_PluginLSPEntryKeysDifferingOnlyInCase(t *testing.T) {
	fsys := pluginTree(`{"name":"p"}`, "plugins/p/.lsp.json", `{"go":{"command":"gopls","Command":"x"},"ts":{"command":"tsls"}}`)

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if want := []string{`plugins/p/.lsp.json: lspServers.go: key "Command" differs only in case from "command"`}; !reflect.DeepEqual(warningTexts(warnings), want) {
		t.Errorf("warnings = %q, want %q", warningTexts(warnings), want)
	}
	servers := lspServers(t, entities)
	if len(servers) != 1 || servers[0].Name != "ts" {
		t.Errorf("lspServers = %+v, want only ts", servers)
	}
}

// A mismatched key in the launch file's top level refuses the file, and one
// inside a configuration refuses that configuration alone.
func TestParse_LaunchKeysDifferingOnlyInCase(t *testing.T) {
	for _, tc := range []struct {
		name, body   string
		wantWarnings []string
		wantServers  []ir.PreviewServer
	}{
		{
			"the configurations list",
			`{"configurations":[{"runtimeExecutable":"npm"}],"Configurations":null}`,
			[]string{`.claude/launch.json: key "Configurations" differs only in case from "configurations"`},
			nil,
		},
		{
			"one configuration",
			`{"configurations":[{"runtimeExecutable":"npm","RuntimeExecutable":"yarn"},{"runtimeExecutable":"pnpm"}]}`,
			[]string{`.claude/launch.json: configurations[0]: key "RuntimeExecutable" differs only in case from "runtimeExecutable"`},
			[]ir.PreviewServer{{Command: "pnpm", Location: launchLocation("1")}},
		},
		{
			"env names are map keys",
			`{"configurations":[{"runtimeExecutable":"npm","env":{"PORT":"1","port":"2"}}]}`,
			nil,
			[]ir.PreviewServer{{Command: "npm", Env: map[string]string{"PORT": "1", "port": "2"}, Location: launchLocation("0")}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tc.body))

			if got := warningTexts(warnings); !reflect.DeepEqual(got, tc.wantWarnings) {
				t.Errorf("warnings = %q, want %q", got, tc.wantWarnings)
			}
			var got []ir.PreviewServer
			for _, e := range entities {
				got = append(got, e.(ir.PreviewServer))
			}
			if !reflect.DeepEqual(got, tc.wantServers) {
				t.Errorf("preview servers = %+v, want %+v", got, tc.wantServers)
			}
		})
	}
}
