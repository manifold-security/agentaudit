package cursor

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const agentPluginRoot = "plugins/release-kit"

func agentManifest(schema string) *fstest.MapFile {
	return manifest(`{"$schema":"` + schema + `","name":"release-kit","version":"2.0.1"}`)
}

func agentScript() *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("#!/bin/sh\necho ship\n")}
}

// The want below is exact, so the hooks file and the agents directory the
// fixture plants beside the skills contribute nothing. A Cursor-format
// plugin does surface both, which
// TestPluginEntitiesSurfaceTheComponentsAPluginShips and
// TestPluginAgentsSurfaceFromEveryAcceptedMarkdownSpelling cover.
func TestAgentPluginSurfacesItsSkillsAndMCPServersAlone(t *testing.T) {
	fsys := fstest.MapFS{
		agentPluginRoot + "/plugin.json":                  agentManifest("https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"),
		agentPluginRoot + "/mcp.json":                     manifest(`{"mcpServers":{"index":{"command":"${CURSOR_PLUGIN_ROOT}/bin/index"}}}`),
		agentPluginRoot + "/skills/greet/SKILL.md":        named("greet"),
		agentPluginRoot + "/skills/greet/scripts/ship.sh": agentScript(),
		agentPluginRoot + "/hooks/hooks.json":             manifest(`{"hooks":{"afterFileEdit":[{"command":"./scripts/sync.sh"}]}}`),
		agentPluginRoot + "/agents/reviewer.md":           named("reviewer"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.MCPServer{
			Name:      "index",
			Transport: ir.TransportStdio,
			Command:   agentPluginRoot + "/bin/index",
			Location:  ir.Location{File: agentPluginRoot + "/mcp.json", Key: "mcpServers.index"},
		},
		ir.Skill{
			Name:     "greet",
			Location: ir.Location{File: agentPluginRoot + "/skills/greet/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:      agentPluginRoot + "/skills/greet/scripts/ship.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: agentPluginRoot + "/skills/greet/scripts/ship.sh"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
}

// A plugin declaring its one skill beside its manifest reaches the same
// reader the Cursor format uses, so the scripts that skill bundles are read
// from the plugin root too.
func TestAgentPluginSingleSkillFormSurfacesTheScriptsItBundles(t *testing.T) {
	fsys := fstest.MapFS{
		agentPluginRoot + "/plugin.json":     agentManifest("https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"),
		agentPluginRoot + "/SKILL.md":        named("release-kit"),
		agentPluginRoot + "/scripts/ship.sh": agentScript(),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "release-kit",
			Location: ir.Location{File: agentPluginRoot + "/SKILL.md", Key: "name"},
		},
		ir.BundledPayload{
			Path:      agentPluginRoot + "/scripts/ship.sh",
			Extension: ".sh",
			Origin:    "skill",
			Location:  ir.Location{File: agentPluginRoot + "/scripts/ship.sh"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
}

// A document making no claim to the standard mints nothing and, where the
// scanner could read it, says nothing. The skills root below every row is
// what makes the components stay unread observable; the last row is the arm
// that fails when the claim stops being read at all.
func TestAgentPluginReadsOnlyAManifestNamingTheStandard(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []ir.Entity
		// wantWarning is set where the row's document leaves the scanner
		// unable to say whose file it read.
		wantWarning bool
	}{
		{
			name: "no schema at all",
			body: `{"name":"release-kit","version":"2.0.1"}`,
		},
		{
			name: "another tool's schema",
			body: `{"$schema":"https://example.test/schemas/plugin.schema.json","name":"release-kit"}`,
		},
		{
			name: "the standard's identifier inside another URL",
			body: `{"$schema":"https://example.test/r?to=https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"release-kit"}`,
		},
		{
			name: "a schema that is not a string",
			body: `{"$schema":["https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"],"name":"release-kit"}`,
		},
		{
			name:        "a document that does not parse",
			body:        `{"`,
			wantWarning: true,
		},
		{
			name: "a document that is not an object",
			body: `["release-kit"]`,
		},
		{
			name: "a later specification version",
			body: `{"$schema":"https://agent-plugins.org/schemas/1.1.0/plugin.schema.json","name":"release-kit","version":"2.0.1"}`,
			want: []ir.Entity{
				ir.Skill{
					Name:     "greet",
					Location: ir.Location{File: "skills/greet/SKILL.md", Key: "name"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := componentsFrom(t, fstest.MapFS{
				"plugin.json":           manifest(tt.body),
				"skills/greet/SKILL.md": named("greet"),
			})

			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pluginEntities() = %+v, want %+v", got, tt.want)
			}
			if !tt.wantWarning {
				if len(warnings) != 0 {
					t.Fatalf("warnings = %+v, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 || warnings[0].File != "plugin.json" {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, "plugin.json")
			}
		})
	}
}

// A manifest the scanner refuses to read is an attacker-chosen blind spot
// whoever authored it, so the refusal names the path rather than passing for
// a file some other tool left there.
func TestAgentPluginManifestRefusalNamesItsOwnPath(t *testing.T) {
	fsys := fstest.MapFS{
		"plugin.json":           {Mode: fs.ModeSymlink, Data: []byte("../elsewhere/plugin.json")},
		"skills/greet/SKILL.md": named("greet"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(got) != 0 {
		t.Fatalf("pluginEntities() = %+v, want none", got)
	}
	if len(warnings) != 1 || warnings[0].File != "plugin.json" {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, "plugin.json")
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// Location alone tells the two plugin formats apart, which is how Cursor
// identifies them: a manifest in a .cursor-plugin directory is the Cursor
// format's whatever its document claims, and the standard's sits at a plugin
// root, the scan root and below it alike. Every manifest below carries the
// same document, so where each plugin root lands is what separates them.
func TestAgentPluginManifestsSurfaceByLocation(t *testing.T) {
	const cursorRoot = "plugins/ship-tool"
	const cursorManifest = cursorRoot + "/.cursor-plugin/plugin.json"

	schema := "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	fsys := fstest.MapFS{
		"plugin.json":                    agentManifest(schema),
		"SKILL.md":                       named("root-kit"),
		agentPluginRoot + "/plugin.json": agentManifest(schema),
		agentPluginRoot + "/SKILL.md":    named("release-kit"),
		cursorManifest:                   agentManifest(schema),
		cursorRoot + "/SKILL.md":         named("ship-tool"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	var files []string
	for _, e := range got {
		files = append(files, ir.LocationOf(e).File)
	}
	want := []string{cursorRoot + "/SKILL.md", "SKILL.md", agentPluginRoot + "/SKILL.md"}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("plugin root files = %q, want %q", files, want)
	}
}

// A FIFO at the Agent Plugins root manifest is refused without being
// opened.
func TestAgentPluginManifestRefusesAFIFOWithoutOpeningIt(t *testing.T) {
	const piped = agentPluginRoot + "/plugin.json"
	const healthy = "plugins/ship-tool/.cursor-plugin/plugin.json"
	schema := "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"

	fsys := blockingPathFS{
		m: fstest.MapFS{
			piped:   {Mode: fs.ModeNamedPipe, Data: []byte(`{"$schema":"` + schema + `","name":"release-kit"}`)},
			healthy: manifest(inlineHook),
		},
		path: piped,
	}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
		err      error
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, err := pluginEntities(fsys)
		done <- result{entities, warnings, err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("pluginEntities() error = %v, want nil", got.err)
		}
		want := []ir.Entity{inlineHookAt(healthy)}
		if !reflect.DeepEqual(got.entities, want) {
			t.Fatalf("pluginEntities() = %+v, want %+v", got.entities, want)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != piped {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, piped)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pluginEntities never returned; it opened the pipe instead of reading its type bits")
	}
}

// Manifests are ordered by their own path rather than by the order the walk
// reached them, so one tree renders the same rows twice running. The pair
// below is what makes the two orders differ: a hyphen sorts ahead of a path
// separator, so the walk yields a before a-x and the sort reverses them.
func TestAgentPluginManifestsAreOrderedByPath(t *testing.T) {
	schema := "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
	fsys := fstest.MapFS{
		"plugins/a/plugin.json":   manifest(`{"$schema":"` + schema + `","name":"a"}`),
		"plugins/a/SKILL.md":      named("a"),
		"plugins/a-x/plugin.json": manifest(`{"$schema":"` + schema + `","name":"a-x"}`),
		"plugins/a-x/SKILL.md":    named("a-x"),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{
		ir.Skill{
			Name:     "a-x",
			Location: ir.Location{File: "plugins/a-x/SKILL.md", Key: "name"},
		},
		ir.Skill{
			Name:     "a",
			Location: ir.Location{File: "plugins/a/SKILL.md", Key: "name"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
}
