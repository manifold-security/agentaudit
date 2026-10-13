package claude

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func lspServers(t *testing.T, entities []ir.Entity) []ir.LSPServer {
	t.Helper()
	var got []ir.LSPServer
	for _, e := range entities {
		if l, ok := e.(ir.LSPServer); ok {
			got = append(got, l)
		}
	}
	return got
}

// A plugin root's default .lsp.json is read with no wrapper.
func TestLSPEntities_DefaultBareMap(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"go":{"command":"gopls","args":["serve"]}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	got := lspServers(t, entities)
	want := []ir.LSPServer{{
		Name: "go", Command: "gopls", Args: []string{"serve"},
		Location: ir.Location{File: "plugins/vendor/.lsp.json", Key: "lspServers.go"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lspServers = %+v, want %+v", got, want)
	}
}

// A plugin root of "." — the shape -r gives a plugin scanned as its own
// project — reads its default .lsp.json.
func TestLSPEntities_RootDotDefaultSurfaces(t *testing.T) {
	fsys := fstest.MapFS{
		".claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		".lsp.json":                  &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" || got[0].Location.File != ".lsp.json" {
		t.Fatalf("lspServers = %+v, want one go entry from .lsp.json", got)
	}
}

func TestLSPEntities_ManifestInlineAndDefaultAreAdditive(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{
			Data: []byte(`{"name":"vendor","lspServers":{"ts":{"command":"typescript-language-server","args":["--stdio"]}}}`),
		},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"go":{"command":"gopls"}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	got := lspServers(t, entities)
	if len(got) != 2 {
		t.Fatalf("lspServers = %+v, want 2 (default + manifest, both surface)", got)
	}
	names := map[string]bool{}
	for _, l := range got {
		names[l.Name] = true
	}
	for _, want := range []string{"go", "ts"} {
		if !names[want] {
			t.Errorf("lspServers = %+v, want an entry named %q", got, want)
		}
	}
}

// A manifest lspServers string path is resolved through pluginDocs.
func TestLSPEntities_ManifestStringPath(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{
			Data: []byte(`{"name":"vendor","lspServers":"./lsp-config.json"}`),
		},
		"plugins/vendor/lsp-config.json": &fstest.MapFile{
			Data: []byte(`{"go":{"command":"gopls"}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" || got[0].Location.File != "plugins/vendor/lsp-config.json" {
		t.Fatalf("lspServers = %+v, want one go entry from lsp-config.json", got)
	}
}

func TestLSPEntities_ManifestArrayOfPaths(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{
			Data: []byte(`{"name":"vendor","lspServers":["./a.json","./b.json"]}`),
		},
		"plugins/vendor/a.json": &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
		"plugins/vendor/b.json": &fstest.MapFile{Data: []byte(`{"ts":{"command":"tsserver"}}`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	got := lspServers(t, entities)
	if len(got) != 2 {
		t.Fatalf("lspServers = %+v, want 2 (one per array element)", got)
	}
}

func TestLSPEntities_ManifestPathEscapingRootWarns(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{
			Data: []byte(`{"name":"vendor","lspServers":"../outside.json"}`),
		},
		"outside.json": &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(lspServers(t, entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none (the path escapes the root)", lspServers(t, entities))
	}
	if len(warnings) != 1 || !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warnings = %+v, want exactly one errors.Is(_, adapter.ErrUnreadable)", warnings)
	}
}

func TestLSPEntities_ExpandsPluginRootLeavesPluginDataLiteral(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"go":{` +
				`"command":"${CLAUDE_PLUGIN_ROOT}/lsp/server.sh",` +
				`"args":["--root","$CLAUDE_PLUGIN_ROOT/data","--state","${CLAUDE_PLUGIN_DATA}/state.json"]` +
				`}}`),
		},
	}

	entities, _, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	got := lspServers(t, entities)
	if len(got) != 1 {
		t.Fatalf("lspServers = %+v, want 1", got)
	}
	if got[0].Command != "plugins/vendor/lsp/server.sh" {
		t.Errorf("Command = %q, want the substituted plugin root", got[0].Command)
	}
	wantArgs := []string{"--root", "plugins/vendor/data", "--state", "${CLAUDE_PLUGIN_DATA}/state.json"}
	if !reflect.DeepEqual(got[0].Args, wantArgs) {
		t.Errorf("Args = %v, want %v", got[0].Args, wantArgs)
	}
}

func TestLSPEntities_MissingOrEmptyCommandWarnsAndSkipsEntry(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"missing command", `{"go":{}}`},
		{"empty command", `{"go":{"command":""}}`},
		{"non-string command", `{"go":{"command":5}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
				"plugins/vendor/.lsp.json":                  &fstest.MapFile{Data: []byte(tt.data)},
			}

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(lspServers(t, entities)) != 0 {
				t.Fatalf("lspServers = %+v, want none", lspServers(t, entities))
			}

			var found bool
			for _, w := range warnings {
				if w.File == "plugins/vendor/.lsp.json" {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings = %+v, want one naming plugins/vendor/.lsp.json", warnings)
			}
		})
	}
}

func TestLSPEntities_BadCommandSiblingSurvives(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"bad":{"command":""},"go":{"command":"gopls"}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" {
		t.Fatalf("lspServers = %+v, want only the go sibling", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly 1", warnings)
	}
}

// Wrong-typed args take the same shape as a wrong-typed headersHelper.
func TestLSPEntities_WrongTypedArgsKeepsServerWithNilArgs(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"go":{"command":"gopls","args":"serve"}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" || got[0].Args != nil {
		t.Fatalf("lspServers = %+v, want the server surfaced with nil Args", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly 1", warnings)
	}
}

func TestLSPEntities_NonObjectEntryWarnsSiblingSurvives(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"bad":["not","an","object"],"go":{"command":"gopls"}}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" {
		t.Fatalf("lspServers = %+v, want only the go sibling", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly 1", warnings)
	}
}

func TestLSPEntities_TopLevelArrayWarnsNamingShape(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json":                  &fstest.MapFile{Data: []byte(`[1,2,3]`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(lspServers(t, entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none", lspServers(t, entities))
	}
	if len(warnings) != 1 || warnings[0].Err == nil {
		t.Fatalf("warnings = %+v, want exactly 1", warnings)
	}
	wantMsg := "expected an object of server entries, found an array"
	if warnings[0].Err.Error() != wantMsg {
		t.Errorf("warnings[0].Err = %v, want %q", warnings[0].Err, wantMsg)
	}
}

func TestLSPEntities_NullDocumentIsSilent(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json":                  &fstest.MapFile{Data: []byte(`null`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if len(lspServers(t, entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none", lspServers(t, entities))
	}
}

// A manifest lspServers of the wrong shape reuses pluginDocs' own message.
func TestLSPEntities_ManifestWrongTypeFormWarning(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{
			Data: []byte(`{"name":"vendor","lspServers":42}`),
		},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(lspServers(t, entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none", lspServers(t, entities))
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly 1", warnings)
	}
	wantMsg := "lspServers: not parsed, expected a string, array or object"
	if warnings[0].Err == nil || warnings[0].Err.Error() != wantMsg {
		t.Errorf("warnings[0].Err = %v, want %q", warnings[0].Err, wantMsg)
	}
}

// The companion arm shows a present default DOES yield an entity, so the
// silence is not because nothing was ever read.
func TestLSPEntities_AbsentDefaultIsSilentPresentDefaultYieldsOne(t *testing.T) {
	absent := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
	}
	entities, warnings, err := New().Parse(absent)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	if len(lspServers(t, entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none", lspServers(t, entities))
	}

	present := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json":                  &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
	}
	entities, _, err = New().Parse(present)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(lspServers(t, entities)) != 1 {
		t.Fatalf("lspServers = %+v, want exactly 1", lspServers(t, entities))
	}
}

type blockingPathFS struct {
	m    fstest.MapFS
	path string
}

func (f blockingPathFS) Open(name string) (fs.File, error) {
	if name == f.path {
		select {}
	}
	return f.m.Open(name)
}

func (f blockingPathFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func TestLSPEntities_FIFODefaultLocationWarnsNoHang(t *testing.T) {
	const piped = "plugins/vendor/.lsp.json"
	fsys := blockingPathFS{
		m: fstest.MapFS{
			"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
			piped: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"go":{"command":"gopls"}}`)},
		},
		path: piped,
	}

	got := bounded(t, parseAll, fsys)
	if len(lspServers(t, got.entities)) != 0 {
		t.Fatalf("lspServers = %+v, want none", lspServers(t, got.entities))
	}
	var found bool
	for _, w := range got.warnings {
		if w.File == "plugins/vendor/.lsp.json" && errors.Is(w.Err, adapter.ErrUnreadable) {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %+v, want one naming plugins/vendor/.lsp.json as errors.Is(_, adapter.ErrUnreadable)", got.warnings)
	}
}

func TestLSPEntities_SkillsDirPluginRootSurfaces(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/skills/foo/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"foo"}`)},
		".claude/skills/foo/.lsp.json":                  &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	got := lspServers(t, entities)
	if len(got) != 1 || got[0].Name != "go" {
		t.Fatalf("lspServers = %+v, want one go entry", got)
	}
	if got[0].Location.File != ".claude/skills/foo/.lsp.json" {
		t.Errorf("Location.File = %q, want the skills-dir plugin's own .lsp.json", got[0].Location.File)
	}
}

// Entries are sorted by name, regardless of source document order.
func TestLSPEntities_SortedByName(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/vendor/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"vendor"}`)},
		"plugins/vendor/.lsp.json": &fstest.MapFile{
			Data: []byte(`{"z":{"command":"z-bin"},"a":{"command":"a-bin"},"m":{"command":"m-bin"}}`),
		},
	}

	entities, _, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	got := lspServers(t, entities)
	wantOrder := []string{"a", "m", "z"}
	if len(got) != len(wantOrder) {
		t.Fatalf("lspServers = %+v, want %d entries", got, len(wantOrder))
	}
	for i, name := range wantOrder {
		if got[i].Name != name {
			t.Errorf("lspServers[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
}
