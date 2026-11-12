package cursor

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func warningLines(warnings []adapter.Warning) []string {
	lines := make([]string, 0, len(warnings))
	for _, w := range warnings {
		lines = append(lines, w.File+": "+w.Err.Error())
	}
	return lines
}

// The colliding entry is dropped and the next entry of its event reports.
func TestHookEntitiesDropAnEntryWhoseKeysDifferOnlyInCase(t *testing.T) {
	fsys := hooksMapFS(`{"hooks":{"beforeShellExecution":[{"command":"a","Command":"b"},{"command":"c"}]}}`)

	entities, warnings, err := hookEntities(fsys, hooksFileName)
	if err != nil {
		t.Fatalf("hookEntities() error = %v, want nil", err)
	}
	want := []string{`.cursor/hooks.json: hooks.beforeShellExecution[0]: key "Command" differs only in case from "command"`}
	if got := warningLines(warnings); !reflect.DeepEqual(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	if len(entities) != 1 || entities[0].(ir.Hook).Command != "c" {
		t.Errorf("entities = %+v, want only the entry running c", entities)
	}
}

// The warning names the terminal by its position in the list.
func TestEnvironmentEntitiesDropATerminalWhoseKeysDifferOnlyInCase(t *testing.T) {
	fsys := environmentMapFS(`{"terminals":[{"name":"a","command":"x","Command":"y"},{"name":"b","command":"z"}]}`)

	entities, warnings, err := environmentEntities(fsys)
	if err != nil {
		t.Fatalf("environmentEntities() error = %v, want nil", err)
	}
	want := []string{`.cursor/environment.json: terminals[0]: key "Command" differs only in case from "command"`}
	if got := warningLines(warnings); !reflect.DeepEqual(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	if len(entities) != 1 || entities[0].(ir.Provisioner).Command != "z" {
		t.Errorf("entities = %+v, want only the terminal running z", entities)
	}
}

// The shared mcpServers decode applies to Cursor's mcp.json as well.
func TestMCPEntitiesDropAServerWhoseKeysDifferOnlyInCase(t *testing.T) {
	fsys := fstest.MapFS{mcpFileName: &fstest.MapFile{Data: []byte(`{"mcpServers":{"a":{"command":"x","Command":"y"},"b":{"command":"z"}}}`)}}

	entities, warnings, err := mcpEntities(fsys, mcpFileName)
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	want := []string{`.cursor/mcp.json: mcpServers.a: key "Command" differs only in case from "command"`}
	if got := warningLines(warnings); !reflect.DeepEqual(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	if len(entities) != 1 || entities[0].(ir.MCPServer).Command != "z" {
		t.Errorf("entities = %+v, want only the server running z", entities)
	}
}

// A lone key that matches a field only ignoring case refuses its entry.
func TestHookEntitiesDropAnEntryWithAFieldKeyInAnotherCase(t *testing.T) {
	fsys := hooksMapFS(`{"hooks":{"stop":[{"command":"a","Type":"prompt"},{"command":"c"}]}}`)

	entities, warnings, err := hookEntities(fsys, hooksFileName)
	if err != nil {
		t.Fatalf("hookEntities() error = %v, want nil", err)
	}
	want := []string{`.cursor/hooks.json: hooks.stop[0]: key "Type" differs only in case from "type"`}
	if got := warningLines(warnings); !reflect.DeepEqual(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	if len(entities) != 1 || entities[0].(ir.Hook).Command != "c" {
		t.Errorf("entities = %+v, want only the entry running c", entities)
	}
}
