package cursor

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const shipToolRoot = "plugins/ship-tool"

// componentsFrom returns what the plugins in fsys contribute.
func componentsFrom(t *testing.T, fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	t.Helper()

	entities, warnings, err := pluginEntities(fsys)
	if err != nil {
		t.Fatalf("pluginEntities() error = %v, want nil", err)
	}
	return entities, warnings
}

// The hooks and MCP servers a plugin ships surface from the plugin's own
// tree, each located at the file that declared it.
func TestPluginEntitiesSurfaceTheComponentsAPluginShips(t *testing.T) {
	fsys := fstest.MapFS{
		shipToolManifest:                   manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"afterFileEdit":[{"command":"./sync.sh","matcher":"*.env"}]}}`),
		shipToolRoot + "/mcp.json":         manifest(`{"mcpServers":{"index":{"command":"./bin/index"}}}`),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.MCPServer{
			Name:      "index",
			Transport: ir.TransportStdio,
			Command:   "./bin/index",
			Location:  ir.Location{File: shipToolRoot + "/mcp.json", Key: "mcpServers.index"},
		},
		ir.Hook{
			Event:    "afterFileEdit",
			Matcher:  "*.env",
			Command:  "./sync.sh",
			Location: ir.Location{File: shipToolRoot + "/hooks/hooks.json", Key: "hooks.afterFileEdit[0].command"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A plugin's declaration and the project's own are separate sources, so a
// reader following either lands on the file that carries it.
func TestParseKeepsThePluginFilesApartFromTheProjectOnes(t *testing.T) {
	fsys := fstest.MapFS{
		shipToolManifest:                   manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"sessionStart":[{"command":"./plugin.sh"}]}}`),
		shipToolRoot + "/mcp.json":         manifest(`{"mcpServers":{"plugin-index":{"command":"./bin/index"}}}`),
		hooksFileName:                      manifest(`{"version":1,"hooks":{"sessionStart":[{"command":"./project.sh"}]}}`),
		mcpFileName:                        manifest(`{"mcpServers":{"project-index":{"command":"./bin/project"}}}`),
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	fileByCommand := map[string]string{}
	for _, e := range entities {
		switch v := e.(type) {
		case ir.Hook:
			fileByCommand[v.Command] = v.Location.File
		case ir.MCPServer:
			fileByCommand[v.Command] = v.Location.File
		}
	}

	want := map[string]string{
		"./plugin.sh":   shipToolRoot + "/hooks/hooks.json",
		"./project.sh":  hooksFileName,
		"./bin/index":   shipToolRoot + "/mcp.json",
		"./bin/project": mcpFileName,
	}
	if !reflect.DeepEqual(fileByCommand, want) {
		t.Fatalf("Parse() located commands at %+v, want %+v", fileByCommand, want)
	}
}

// A plugin-root spelling Cursor resolves reaches the report resolved against
// the plugin's path, and a value naming one of the standard's own names
// reaches it exactly as the config wrote it.
func TestPluginMCPResolvesOnlyTheSpellingsCursorSubstitutes(t *testing.T) {
	tests := []struct {
		name string
		root string
		raw  string
		want ir.MCPServer
	}{
		{
			name: "cursor spelling in a nested root's command",
			root: shipToolRoot,
			raw:  `{"command":"${CURSOR_PLUGIN_ROOT}/bin/index"}`,
			want: ir.MCPServer{Command: shipToolRoot + "/bin/index"},
		},
		{
			name: "claude spelling in a nested root's command",
			root: shipToolRoot,
			raw:  `{"command":"${CLAUDE_PLUGIN_ROOT}/bin/index"}`,
			want: ir.MCPServer{Command: shipToolRoot + "/bin/index"},
		},
		{
			name: "a bare reference resolves to the root itself",
			root: shipToolRoot,
			raw:  `{"command":"run","env":{"HOME_DIR":"${CURSOR_PLUGIN_ROOT}"}}`,
			want: ir.MCPServer{Command: "run", Env: map[string]string{"HOME_DIR": shipToolRoot}},
		},
		{
			name: "a repository-root plugin collapses the separator",
			root: ".",
			raw:  `{"command":"${CURSOR_PLUGIN_ROOT}/bin/index"}`,
			want: ir.MCPServer{Command: "bin/index"},
		},
		{
			name: "a cursor spelling in an argument",
			root: shipToolRoot,
			raw:  `{"command":"run","args":["--data","${CURSOR_PLUGIN_ROOT}/data"]}`,
			want: ir.MCPServer{Command: "run", Args: []string{"--data", shipToolRoot + "/data"}},
		},
		{
			name: "the standard's names stay verbatim",
			root: shipToolRoot,
			raw:  `{"command":"${PLUGIN_ROOT}/bin/index","args":["--data","${PLUGIN_DATA}"]}`,
			want: ir.MCPServer{Command: "${PLUGIN_ROOT}/bin/index", Args: []string{"--data", "${PLUGIN_DATA}"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcpFile := path.Join(tt.root, pluginMCPFile)
			fsys := fstest.MapFS{
				path.Join(tt.root, pluginManifestDir, pluginManifestFile): manifest(`{"name":"ship-tool"}`),
				mcpFile: manifest(`{"mcpServers":{"index":` + tt.raw + `}}`),
			}

			got, warnings := componentsFrom(t, fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}

			want := tt.want
			want.Name = "index"
			want.Transport = ir.TransportStdio
			want.Location = ir.Location{File: mcpFile, Key: "mcpServers.index"}
			if !reflect.DeepEqual(got, []ir.Entity{want}) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
			}
		})
	}
}

// A plugin's hooks document surfaces its hook with no version key present.
// Cursor documents that key as required for a project's own hooks file, yet
// its plugin template ships one without it, so requiring the key here would
// report a clean tree over a live hook.
func TestPluginHooksSurfaceWithoutAVersionKey(t *testing.T) {
	fsys := fstest.MapFS{
		shipToolManifest:                   manifest(`{"name":"ship-tool"}`),
		shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"workspaceOpen":[{"command":"./boot.sh"}]}}`),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{ir.Hook{
		Event:    "workspaceOpen",
		Command:  "./boot.sh",
		Location: ir.Location{File: shipToolRoot + "/hooks/hooks.json", Key: "hooks.workspaceOpen[0].command"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
}

// A manifest naming no component location leaves every default location
// read, and says nothing of its own. Each entity in want below comes from a
// different one of the locations pluginComponentEntities reads, so a read
// newly gated on the manifest loses one of them. The plugin root's own
// SKILL.md is the location left out: a skills root suppresses it, so no one
// tree exercises both.
func TestPluginComponentsReadEveryDefaultLocationAManifestLeaves(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"

	fsys := fstest.MapFS{
		shipToolManifest:                   manifest(`{"version":"1.4.2"}`),
		shipToolRoot + "/mcp.json":         manifest(`{"mcpServers":{"index":{"command":"./bin/index"}}}`),
		shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"sessionStart":[{"command":"./boot.sh"}]}}`),
		skillDir + "/SKILL.md":             named("release"),
		skillDir + "/scripts/deploy.sh":    {Data: []byte("#!/bin/sh\n")},
		shipToolRoot + "/agents/ship.md":   named("shipper"),
	}

	got, warnings := componentsFrom(t, fsys)

	want := []ir.Entity{
		ir.MCPServer{
			Name:      "index",
			Command:   "./bin/index",
			Transport: ir.TransportStdio,
			Location:  ir.Location{File: shipToolRoot + "/mcp.json", Key: "mcpServers.index"},
		},
		ir.Hook{
			Event:    "sessionStart",
			Command:  "./boot.sh",
			Location: ir.Location{File: shipToolRoot + "/hooks/hooks.json", Key: "hooks.sessionStart[0].command"},
		},
		ir.Skill{
			Name:     "release",
			Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:      skillDir + "/scripts/deploy.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: skillDir + "/scripts/deploy.sh"},
		},
		ir.Subagent{
			Name:     "shipper",
			Location: ir.Location{File: shipToolRoot + "/agents/ship.md", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
}

// A component file that degrades names its own path, and the components
// beside it still surface. The document and the server map fail through
// separate decodes, so each has to reach the warn channel from the plugin's
// path.
func TestPluginComponentDegradationNamesThePluginsFile(t *testing.T) {
	const mcpFile = shipToolRoot + "/mcp.json"

	tests := []struct {
		name string
		body string
	}{
		{name: "the document does not decode", body: `{"`},
		{name: "the document is not an object", body: `[1,2,3]`},
		{name: "the server map is not an object", body: `{"mcpServers":[1,2,3]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				shipToolManifest: manifest(inlineHook),
				mcpFile:          manifest(tt.body),
			}

			entities, warnings, err := pluginEntities(fsys)
			if err != nil {
				t.Fatalf("pluginEntities() error = %v, want nil: a malformed source degrades", err)
			}

			want := []ir.Entity{inlineHookAt(shipToolManifest)}
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("pluginEntities() = %+v, want %+v", entities, want)
			}
			if len(warnings) != 1 || warnings[0].File != mcpFile {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, mcpFile)
			}
		})
	}
}

// A manifest field naming a component's location replaces the default
// folder: the declared location is read, and the default beside it is left
// alone.
func TestPluginManifestPathReplacesTheDefaultComponentLocation(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		files map[string]*fstest.MapFile
		want  ir.Entity
	}{
		{
			name: "skills",
			body: `{"name":"ship-tool","skills":"./release-skills/"}`,
			files: map[string]*fstest.MapFile{
				shipToolRoot + "/release-skills/release/SKILL.md": named("release"),
				shipToolRoot + "/skills/decoy/SKILL.md":           named("decoy"),
			},
			want: ir.Skill{
				Name:     "release",
				Location: ir.Location{File: shipToolRoot + "/release-skills/release/SKILL.md", Key: "name"},
			},
		},
		{
			name: "agents",
			body: `{"name":"ship-tool","agents":"./crew/"}`,
			files: map[string]*fstest.MapFile{
				shipToolRoot + "/crew/ship.md":    named("shipper"),
				shipToolRoot + "/agents/decoy.md": named("decoy"),
			},
			want: ir.Subagent{
				Name:     "shipper",
				Location: ir.Location{File: shipToolRoot + "/crew/ship.md", Key: "name"},
			},
		},
		{
			name: "hooks",
			body: `{"name":"ship-tool","hooks":"./config/hooks.json"}`,
			files: map[string]*fstest.MapFile{
				shipToolRoot + "/config/hooks.json": manifest(`{"hooks":{"sessionStart":[{"command":"./boot.sh"}]}}`),
				shipToolRoot + "/hooks/hooks.json":  manifest(`{"hooks":{"sessionStart":[{"command":"./decoy.sh"}]}}`),
			},
			want: ir.Hook{
				Event:    "sessionStart",
				Command:  "./boot.sh",
				Location: ir.Location{File: shipToolRoot + "/config/hooks.json", Key: "hooks.sessionStart[0].command"},
			},
		},
		{
			name: "mcpServers",
			body: `{"name":"ship-tool","mcpServers":"./servers.json"}`,
			files: map[string]*fstest.MapFile{
				shipToolRoot + "/servers.json": manifest(`{"mcpServers":{"index":{"command":"./bin/index"}}}`),
				shipToolRoot + "/mcp.json":     manifest(`{"mcpServers":{"decoy":{"command":"./bin/decoy"}}}`),
			},
			want: ir.MCPServer{
				Name:      "index",
				Transport: ir.TransportStdio,
				Command:   "./bin/index",
				Location:  ir.Location{File: shipToolRoot + "/servers.json", Key: "mcpServers.index"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{shipToolManifest: manifest(tt.body)}
			for p, f := range tt.files {
				fsys[p] = f
			}

			got, warnings := componentsFrom(t, fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if !reflect.DeepEqual(got, []ir.Entity{tt.want}) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A component the manifest declares inline surfaces from the manifest that
// carries it, located at the key that declared it, and the default location
// beside it is left alone. The plugin-root spellings resolve in an inline
// server exactly as they do in a server read from a file.
func TestPluginManifestInlineComponentsSurfaceFromTheManifest(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		decoy map[string]*fstest.MapFile
		want  ir.Entity
	}{
		{
			name: "hooks",
			body: `{"name":"ship-tool","hooks":{"afterFileEdit":[{"command":"./sync.sh","matcher":"*.env"}]}}`,
			decoy: map[string]*fstest.MapFile{
				shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"sessionStart":[{"command":"./decoy.sh"}]}}`),
			},
			want: ir.Hook{
				Event:    "afterFileEdit",
				Matcher:  "*.env",
				Command:  "./sync.sh",
				Location: ir.Location{File: shipToolManifest, Key: "hooks.afterFileEdit[0].command"},
			},
		},
		{
			name: "mcpServers",
			body: `{"name":"ship-tool","mcpServers":{"index":{"command":"${CURSOR_PLUGIN_ROOT}/bin/index"}}}`,
			decoy: map[string]*fstest.MapFile{
				shipToolRoot + "/mcp.json": manifest(`{"mcpServers":{"decoy":{"command":"./bin/decoy"}}}`),
			},
			want: ir.MCPServer{
				Name:      "index",
				Transport: ir.TransportStdio,
				Command:   shipToolRoot + "/bin/index",
				Location:  ir.Location{File: shipToolManifest, Key: "mcpServers.index"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{shipToolManifest: manifest(tt.body)}
			for p, f := range tt.decoy {
				fsys[p] = f
			}

			got, warnings := componentsFrom(t, fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if !reflect.DeepEqual(got, []ir.Entity{tt.want}) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A manifest naming a skills location leaves the plugin root's own SKILL.md
// unread, whether or not that location holds anything: the single-skill form
// is what a plugin declaring no skills location falls back to.
func TestPluginManifestSkillsFieldLeavesTheRootSkillUnread(t *testing.T) {
	const declaredSkill = shipToolRoot + "/release-skills/release/SKILL.md"

	tests := []struct {
		name        string
		body        string
		files       map[string]*fstest.MapFile
		want        []ir.Entity
		wantWarning string
	}{
		{
			name:        "declared, and the location holds nothing",
			body:        `{"name":"ship-tool","skills":"./release-skills/"}`,
			wantWarning: shipToolRoot + "/release-skills",
		},
		{
			name:  "declared, and the location holds a skill",
			body:  `{"name":"ship-tool","skills":"./release-skills/"}`,
			files: map[string]*fstest.MapFile{declaredSkill: named("release")},
			want: []ir.Entity{ir.Skill{
				Name:     "release",
				Location: ir.Location{File: declaredSkill, Key: "name"},
			}},
		},
		{
			name: "undeclared",
			body: `{"name":"ship-tool"}`,
			want: []ir.Entity{ir.Skill{
				Name:     "ship-tool",
				Location: ir.Location{File: shipToolRoot + "/SKILL.md", Key: "name"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				shipToolManifest:           manifest(tt.body),
				shipToolRoot + "/SKILL.md": named("ship-tool"),
			}
			for p, f := range tt.files {
				fsys[p] = f
			}

			got, warnings := componentsFrom(t, fsys)
			if tt.wantWarning == "" && len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if tt.wantWarning != "" && (len(warnings) != 1 || warnings[0].File != tt.wantWarning) {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.wantWarning)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pluginEntities() components = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A declared location this scanner refuses to resolve degrades, and nothing
// loads for that component.
func TestPluginManifestUnresolvableComponentPathDegrades(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		planted string
		wantErr string
		refused bool
	}{
		{
			refused: true,
			name:    "a parent of the plugin root",
			body:    `{"name":"ship-tool","skills":"../outside/"}`,
			planted: "plugins/outside/rogue/SKILL.md",
			wantErr: `skills: path "../outside/" escapes the plugin root`,
		},
		{
			refused: true,
			name:    "a sibling the plugin root's name prefixes",
			body:    `{"name":"ship-tool","skills":"../ship-tool-evil/"}`,
			planted: "plugins/ship-tool-evil/rogue/SKILL.md",
			wantErr: `skills: path "../ship-tool-evil/" escapes the plugin root`,
		},
		{
			refused: true,
			name:    "an absolute path",
			body:    `{"name":"ship-tool","skills":"/etc/cursor/"}`,
			planted: shipToolRoot + "/etc/cursor/rogue/SKILL.md",
			wantErr: `skills: path "/etc/cursor/" escapes the plugin root`,
		},
		{
			name:    "no path at all",
			body:    `{"name":"ship-tool","skills":""}`,
			planted: shipToolRoot + "/SKILL.md",
			wantErr: "skills: expected a non-empty path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				shipToolManifest:                        manifest(tt.body),
				tt.planted:                              named("rogue"),
				shipToolRoot + "/skills/decoy/SKILL.md": named("decoy"),
			}

			got, warnings := componentsFrom(t, fsys)
			if len(got) != 0 {
				t.Fatalf("pluginEntities() components = %+v, want none", got)
			}
			if len(warnings) != 1 || warnings[0].File != shipToolManifest {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, shipToolManifest)
			}
			if err := warnings[0].Err.Error(); err != tt.wantErr {
				t.Errorf("warning = %q, want %q", err, tt.wantErr)
			}
			if tt.refused && !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable): a path the plugin loads and this scanner does not is a blind spot", warnings[0].Err)
			}
		})
	}
}

// A component field this scanner cannot read as a location degrades, and the
// default location stays unread: the manifest specified the component, so
// where it loads from is what went unresolved.
func TestPluginManifestWrongTypedComponentFieldDegrades(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		decoy   string
		wantErr string
	}{
		{
			name:    "a skills object",
			body:    `{"name":"ship-tool","skills":{"release":"./release/"}}`,
			decoy:   shipToolRoot + "/skills/decoy/SKILL.md",
			wantErr: "skills: expected a path string, found an object",
		},
		{
			name:    "an agents number",
			body:    `{"name":"ship-tool","agents":7}`,
			decoy:   shipToolRoot + "/agents/decoy.md",
			wantErr: "agents: expected a path string, found a non-object value",
		},
		{
			name:    "a hooks array",
			body:    `{"name":"ship-tool","hooks":[{"command":"./decoy.sh"}]}`,
			decoy:   shipToolRoot + "/hooks/hooks.json",
			wantErr: "hooks: expected a path string or an inline object, found an array",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				shipToolManifest: manifest(tt.body),
				tt.decoy:         named("decoy"),
			}
			if path.Ext(tt.decoy) == ".json" {
				fsys[tt.decoy] = manifest(`{"hooks":{"sessionStart":[{"command":"./decoy.sh"}]}}`)
			}

			got, warnings := componentsFrom(t, fsys)
			if len(got) != 0 {
				t.Fatalf("pluginEntities() components = %+v, want none", got)
			}
			if len(warnings) != 1 || warnings[0].File != shipToolManifest {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, shipToolManifest)
			}
			if err := warnings[0].Err.Error(); err != tt.wantErr {
				t.Errorf("warning = %q, want %q", err, tt.wantErr)
			}
		})
	}
}

type emptyPathFS struct {
	m fstest.MapFS
}

func (f emptyPathFS) Open(name string) (fs.File, error) {
	if name == "" {
		return nil, fs.ErrPermission
	}
	return f.m.Open(name)
}

func (f emptyPathFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f emptyPathFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func (f emptyPathFS) Lstat(name string) (fs.FileInfo, error) {
	if name == "" {
		return nil, fs.ErrPermission
	}
	return f.m.Lstat(name)
}

// A component whose location the manifest left unresolved is not read at
// all: every warning names the manifest that carried the field, and none
// names a location this scanner never resolved.
func TestPluginManifestUnresolvedComponentsAreNeverRead(t *testing.T) {
	fsys := emptyPathFS{m: fstest.MapFS{
		shipToolManifest: manifest(`{"name":"ship-tool","skills":7,"agents":7,"hooks":7,"mcpServers":7}`),
	}}

	got, warnings := componentsFrom(t, fsys)
	if len(got) != 0 {
		t.Fatalf("pluginEntities() components = %+v, want none", got)
	}
	if len(warnings) != 4 {
		t.Fatalf("warnings = %+v, want one per unresolved component field", warnings)
	}
	for _, w := range warnings {
		if w.File != shipToolManifest {
			t.Errorf("warning %v names %q, want the manifest %q", w.Err, w.File, shipToolManifest)
		}
	}
}

// A manifest this scanner cannot decode leaves its components read where a
// manifest naming no location leaves them: the descriptor is what went
// unread, not the component files beside it.
func TestPluginComponentsSurviveAManifestThatDoesNotDecode(t *testing.T) {
	const skillDir = shipToolRoot + "/skills/release"

	fsys := fstest.MapFS{
		shipToolManifest:                   manifest(`{"`),
		shipToolRoot + "/mcp.json":         manifest(`{"mcpServers":{"index":{"command":"./bin/index"}}}`),
		shipToolRoot + "/hooks/hooks.json": manifest(`{"hooks":{"sessionStart":[{"command":"./boot.sh"}]}}`),
		skillDir + "/SKILL.md":             named("release"),
		shipToolRoot + "/agents/ship.md":   named("shipper"),
	}

	got, warnings := componentsFrom(t, fsys)

	want := []ir.Entity{
		ir.MCPServer{
			Name:      "index",
			Transport: ir.TransportStdio,
			Command:   "./bin/index",
			Location:  ir.Location{File: shipToolRoot + "/mcp.json", Key: "mcpServers.index"},
		},
		ir.Hook{
			Event:    "sessionStart",
			Command:  "./boot.sh",
			Location: ir.Location{File: shipToolRoot + "/hooks/hooks.json", Key: "hooks.sessionStart[0].command"},
		},
		ir.Skill{
			Name:     "release",
			Location: ir.Location{File: skillDir + "/SKILL.md", Key: "name"},
		},
		ir.Subagent{
			Name:     "shipper",
			Location: ir.Location{File: shipToolRoot + "/agents/ship.md", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() components = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != shipToolManifest {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, shipToolManifest)
	}
}

// A declared component location that holds nothing names itself on the warn
// channel and leaves the default it replaced unread, while an absent default
// location stays silent.
func TestPluginManifestDeclaredButAbsentComponentDegrades(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		decoy    string
		wantFile string
	}{
		{
			name:     "declared skills",
			body:     `{"name":"ship-tool","skills":"./nope/"}`,
			decoy:    shipToolRoot + "/skills/decoy/SKILL.md",
			wantFile: shipToolRoot + "/nope",
		},
		{
			name:     "declared agents",
			body:     `{"name":"ship-tool","agents":"./nope/"}`,
			decoy:    shipToolRoot + "/agents/decoy.md",
			wantFile: shipToolRoot + "/nope",
		},
		{
			name:     "declared hooks",
			body:     `{"name":"ship-tool","hooks":"./nope.json"}`,
			decoy:    shipToolRoot + "/hooks/hooks.json",
			wantFile: shipToolRoot + "/nope.json",
		},
		{
			name:     "declared mcpServers",
			body:     `{"name":"ship-tool","mcpServers":"./nope.json"}`,
			decoy:    shipToolRoot + "/mcp.json",
			wantFile: shipToolRoot + "/nope.json",
		},
		{name: "default skills", body: `{"name":"ship-tool"}`},
		{name: "default agents", body: `{"name":"ship-tool"}`},
		{name: "default hooks", body: `{"name":"ship-tool"}`},
		{name: "default mcpServers", body: `{"name":"ship-tool"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{shipToolManifest: manifest(tt.body)}
			switch {
			case tt.decoy == "":
			case path.Ext(tt.decoy) == ".json":
				fsys[tt.decoy] = manifest(`{"hooks":{"sessionStart":[{"command":"./decoy.sh"}]},"mcpServers":{"decoy":{"command":"./decoy"}}}`)
			default:
				fsys[tt.decoy] = named("decoy")
			}

			got, warnings := componentsFrom(t, fsys)
			if len(got) != 0 {
				t.Fatalf("pluginEntities() components = %+v, want none", got)
			}
			if tt.wantFile == "" {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %+v, want none: an absent default location is silent", warnings)
				}
				return
			}
			if len(warnings) != 1 || warnings[0].File != tt.wantFile {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.wantFile)
			}
			if !errors.Is(warnings[0].Err, fs.ErrNotExist) {
				t.Errorf("warnings[0].Err = %v, want errors.Is(_, fs.ErrNotExist)", warnings[0].Err)
			}
			if !strings.Contains(warnings[0].Err.Error(), tt.wantFile) {
				t.Errorf("warning = %q, want it to name %q", warnings[0].Err, tt.wantFile)
			}
		})
	}
}
