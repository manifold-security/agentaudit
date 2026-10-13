package codex

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func hooksFS(body string) fstest.MapFS {
	return fstest.MapFS{hooksFileName: &fstest.MapFile{Data: []byte(body)}}
}

// A handler Codex skips declares nothing it runs. Events are walked in name
// order, whatever order the file spells them in.
func TestParseEmitsEachHandlerHooksJSONRuns(t *testing.T) {
	entities, warnings, err := New().Parse(hooksFS(`{
  "description": "release checks",
  "hooks": {
    "Stop": [{"hooks": [{"type": "agent", "prompt": "summarise"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [
      {"type": "command", "command": "./gate.sh", "commandWindows": "gate.cmd", "timeout": 30},
      {"type": "prompt", "prompt": "Is this safe?"}
    ]}],
    "PostToolUse": [{"hooks": [
      {"type": "mcp_tool", "server": "release-index", "tool": "record", "command": "ignored.sh"}
    ]}]
  }
}`))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{
		ir.Hook{Event: "PostToolUse", MCPServer: "release-index", MCPTool: "record", Location: ir.Location{File: hooksFileName, Key: "hooks.PostToolUse[0].hooks[0]"}},
		ir.Hook{Event: "PreToolUse", Matcher: "Bash", Command: "./gate.sh", Location: ir.Location{File: hooksFileName, Key: "hooks.PreToolUse[0].hooks[0]"}},
		ir.Hook{Event: "PreToolUse", Matcher: "Bash", Command: "gate.cmd", Location: ir.Location{File: hooksFileName, Key: "hooks.PreToolUse[0].hooks[0].commandWindows"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The inline form nests handlers under the same event and group indices as
// hooks.json, and either spelling of the Windows command is read.
func TestParseEmitsEachHandlerAnInlineHooksTableRuns(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[[hooks.SessionStart]]\nmatcher = \"startup\"\n\n" +
			"[[hooks.SessionStart.hooks]]\ntype = \"command\"\ncommand = \"./warm.sh\"\ncommand_windows = \"warm.cmd\"\n\n" +
			"[[hooks.SessionStart.hooks]]\ntype = \"mcp_tool\"\nserver = \"audit\"\ntool = \"log\"\n\n" +
			"[[hooks.SessionStart.hooks]]\ntype = \"command\"\ncommand = \"./index.sh\"\ncommandWindows = \"index.cmd\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{
		ir.Hook{Event: "SessionStart", Matcher: "startup", Command: "./warm.sh", Location: ir.Location{File: configFileName, Key: "hooks.SessionStart[0].hooks[0]"}},
		ir.Hook{Event: "SessionStart", Matcher: "startup", Command: "warm.cmd", Location: ir.Location{File: configFileName, Key: "hooks.SessionStart[0].hooks[0].command_windows"}},
		ir.Hook{Event: "SessionStart", Matcher: "startup", MCPServer: "audit", MCPTool: "log", Location: ir.Location{File: configFileName, Key: "hooks.SessionStart[0].hooks[1]"}},
		ir.Hook{Event: "SessionStart", Matcher: "startup", Command: "./index.sh", Location: ir.Location{File: configFileName, Key: "hooks.SessionStart[0].hooks[2]"}},
		ir.Hook{Event: "SessionStart", Matcher: "startup", Command: "index.cmd", Location: ir.Location{File: configFileName, Key: "hooks.SessionStart[0].hooks[2].commandWindows"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The managed-directory settings share the inline hooks table with the
// events but declare no hook, so they are read past without a warning while
// an event beside them still reaches the report. The docs place them in
// TOML only, so in hooks.json the same key is read as an event.
func TestParseReadsPastTheManagedDirectorySettings(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[hooks]\nmanaged_dir = \"/opt/hooks\"\nwindows_managed_dir = 'C:\\hooks'\n\n" +
			"[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"./gate.sh\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{
		ir.Hook{Event: "PreToolUse", Command: "./gate.sh", Location: ir.Location{File: configFileName, Key: "hooks.PreToolUse[0].hooks[0]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}

	_, warnings, _ = New().Parse(hooksFS(`{"hooks": {"managed_dir": "/opt/hooks"}}`))
	if len(warnings) != 1 || warnings[0].Err.Error() != "hooks.managed_dir: expected an array of matcher groups, found a string" {
		t.Fatalf("hooks.json warnings = %+v, want the key read as an event", warnings)
	}
}

// A settings key is read past only in its documented string form. Spelled as
// an array of tables it is named in a warning, never dropped in silence.
func TestParseNamesAManagedDirectorySettingThatIsNotAString(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[[hooks.managed_dir]]\n[[hooks.managed_dir.hooks]]\ntype = \"command\"\ncommand = \"./sneaky.sh\"\n",
	))
	if err != nil || len(entities) != 0 {
		t.Fatalf("Parse() = (%+v, %v), want no entities and no error", entities, err)
	}
	if len(warnings) != 1 || warnings[0].File != configFileName || warnings[0].Err.Error() != "hooks.managed_dir: expected a string, found an array" {
		t.Fatalf("warnings = %+v, want exactly one naming the setting", warnings)
	}
}

// Each field an mcp_tool handler needs is named on its own, and an empty
// name is told apart from an absent one.
func TestParseNamesEachMissingMCPToolField(t *testing.T) {
	tests := []struct {
		name    string
		handler string
		want    []string
	}{
		{"both absent", `{"type": "mcp_tool"}`, []string{
			"hooks.Stop[0].hooks[0].server: expected a non-empty string, found none",
			"hooks.Stop[0].hooks[0].tool: expected a non-empty string, found none",
		}},
		{"server empty", `{"type": "mcp_tool", "server": "", "tool": "log"}`, []string{
			"hooks.Stop[0].hooks[0].server: expected a non-empty string, found an empty string",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(hooksFS(`{"hooks": {"Stop": [{"hooks": [` + tt.handler + `]}]}}`))
			if err != nil || len(entities) != 0 {
				t.Fatalf("Parse() = (%+v, %v), want no entities and no error", entities, err)
			}
			var got []string
			for _, w := range warnings {
				got = append(got, w.Err.Error())
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("warnings = %q, want %q", got, tt.want)
			}
		})
	}
}

// An event outside Codex's documented set is carried verbatim rather than
// refused.
func TestParseCarriesAnUnlistedEventVerbatim(t *testing.T) {
	entities, warnings, err := New().Parse(hooksFS(`{"hooks": {"BeforeDeploy": [{"hooks": [{"type": "command", "command": "./ship.sh"}]}]}}`))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{
		ir.Hook{Event: "BeforeDeploy", Command: "./ship.sh", Location: ir.Location{File: hooksFileName, Key: "hooks.BeforeDeploy[0].hooks[0]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A malformed value is named in a warning and skipped alone: the well-formed
// values beside it, in its own handler, its own array or another event, still
// reach the report.
func TestParseSkipsAMalformedHookValueAlone(t *testing.T) {
	const okHandler = `{"type": "command", "command": "./ok.sh"}`
	const okGroup = `{"hooks": [` + okHandler + `]}`
	okAt := func(event, key string) ir.Entity {
		return ir.Hook{Event: event, Command: "./ok.sh", Location: ir.Location{File: hooksFileName, Key: key}}
	}
	stop := okAt("Stop", "hooks.Stop[0].hooks[0]")
	tests := []struct {
		name    string
		entry   string
		wantKey string
		wantErr string
		want    []ir.Entity
	}{
		{"event not an array", `{"hooks": []}`, "hooks.PreToolUse", "expected an array of matcher groups, found an object", nil},
		{"group not an object", `["./gate.sh", ` + okGroup + `]`, "hooks.PreToolUse[0]", "expected a matcher group, found a string", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[1].hooks[0]")}},
		{"handlers not an array", `[{"hooks": "./gate.sh"}, ` + okGroup + `]`, "hooks.PreToolUse[0].hooks", "expected an array of handlers, found a string", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[1].hooks[0]")}},
		{"handler not an object", `[{"hooks": [null, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0]", "expected a handler, found nothing", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"type missing", `[{"hooks": [{"command": "./gate.sh"}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].type", "expected one of command, mcp_tool, prompt or agent, found nothing", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"type unrecognised", `[{"hooks": [{"type": "webhook", "command": "./gate.sh"}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].type", `expected one of command, mcp_tool, prompt or agent, found "webhook"`, []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"command not a string", `[{"hooks": [{"type": "command", "command": ["./gate.sh"]}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].command", "expected a string, found an array", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"windows command not a string", `[{"hooks": [{"type": "command", "command": "./ok.sh", "commandWindows": 42}]}]`, "hooks.PreToolUse[0].hooks[0].commandWindows", "expected a string, found a value of another type", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[0]")}},
		{"command missing", `[{"hooks": [{"type": "command", "timeout": 5}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0]", "expected a command string, found none", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"server missing", `[{"hooks": [{"type": "mcp_tool", "tool": "log"}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].server", "expected a non-empty string, found none", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"tool missing", `[{"hooks": [{"type": "mcp_tool", "server": "audit"}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].tool", "expected a non-empty string, found none", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
		{"server not a string", `[{"hooks": [{"type": "mcp_tool", "server": 7, "tool": "log"}, ` + okHandler + `]}]`, "hooks.PreToolUse[0].hooks[0].server", "expected a string, found a value of another type", []ir.Entity{okAt("PreToolUse", "hooks.PreToolUse[0].hooks[1]")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(hooksFS(`{"hooks": {"PreToolUse": ` + tt.entry + `, "Stop": [` + okGroup + `]}}`))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil: a malformed value degrades", err)
			}
			if len(warnings) != 1 || warnings[0].File != hooksFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, hooksFileName)
			}
			if want := tt.wantKey + ": " + tt.wantErr; warnings[0].Err.Error() != want {
				t.Errorf("warning = %q, want %q", warnings[0].Err, want)
			}
			want := append(tt.want, stop)
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("Parse() entities = %+v, want the well-formed values %+v", entities, want)
			}
		})
	}
}

// A malformed matcher is named in a warning, and the handlers under it are
// still reported, with no matcher.
func TestParseReportsHandlersUnderAMalformedMatcher(t *testing.T) {
	entities, warnings, err := New().Parse(hooksFS(`{"hooks": {"PreToolUse": [{"matcher": ["Bash"], "hooks": [{"type": "command", "command": "./gate.sh"}]}]}}`))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0].Err.Error(), "hooks.PreToolUse[0].matcher: ") {
		t.Fatalf("warnings = %+v, want exactly one naming the matcher", warnings)
	}
	want := []ir.Entity{
		ir.Hook{Event: "PreToolUse", Command: "./gate.sh", Location: ir.Location{File: hooksFileName, Key: "hooks.PreToolUse[0].hooks[0]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// Each document's warning is worded in its own syntax: JSON has objects where
// TOML has tables.
func TestParseNamesAMisshapenHooksValueInItsFilesVocabulary(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		file string
		want string
	}{
		{"json document", hooksFS(`["./gate.sh"]`), hooksFileName, "expected an object, found an array"},
		{"json hooks key", hooksFS(`{"hooks": ["./gate.sh"]}`), hooksFileName, "hooks: expected an object, found an array"},
		{"toml hooks key", configFS("hooks = [\"./gate.sh\"]\n"), configFileName, "hooks: expected a table, found an array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(tt.fsys)
			if err != nil || len(entities) != 0 {
				t.Fatalf("Parse() = (%+v, %v), want no entities and no error", entities, err)
			}
			if len(warnings) != 1 || warnings[0].File != tt.file || warnings[0].Err.Error() != tt.want {
				t.Fatalf("warnings = %+v, want exactly one on %q reading %q", warnings, tt.file, tt.want)
			}
		})
	}
}

// A fault in either file leaves the other file's entities in the report, and
// the fault is still named.
func TestParseReadsEachHooksSurfaceIndependently(t *testing.T) {
	const goodHooks = `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./ok.sh"}]}]}}`
	const goodConfig = "sandbox_mode = \"danger-full-access\"\n"
	tests := []struct {
		name     string
		fsys     fstest.MapFS
		badFile  string
		wantKind string
	}{
		{
			name: "malformed hooks.json",
			fsys: fstest.MapFS{
				hooksFileName:  &fstest.MapFile{Data: []byte(`{"hooks": `)},
				configFileName: &fstest.MapFile{Data: []byte(goodConfig)},
			},
			badFile:  hooksFileName,
			wantKind: ir.KindSandbox,
		},
		{
			name: "malformed config.toml",
			fsys: fstest.MapFS{
				hooksFileName:  &fstest.MapFile{Data: []byte(goodHooks)},
				configFileName: &fstest.MapFile{Data: []byte("sandbox_mode = \n")},
			},
			badFile:  configFileName,
			wantKind: ir.KindHook,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(tt.fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(warnings) != 1 || warnings[0].File != tt.badFile {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.badFile)
			}
			if len(entities) != 1 || entities[0].Kind() != tt.wantKind {
				t.Fatalf("Parse() entities = %+v, want the other file's %s", entities, tt.wantKind)
			}
		})
	}
}

func TestParseRefusesAFIFOHooksFileWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		hooksFileName: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "./ok.sh"}]}]}}`)},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := New().Parse(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 {
			t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != hooksFileName || !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Fatalf("warnings = %+v, want one refusal naming %q", got.warnings, hooksFileName)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Parse never returned; it opened the pipe instead of reading its type bits")
	}
}
