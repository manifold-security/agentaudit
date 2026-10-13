package cursor

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/discovery"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func manifest(body string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(body)}
}

// inlineHook is a document a manifest contributes an entity of its own from,
// which is what makes the manifest's own path observable in the result.
const inlineHook = `{"hooks":{"sessionStart":[{"command":"./boot.sh"}]}}`

func inlineHookAt(file string) ir.Hook {
	return ir.Hook{
		Event:    "sessionStart",
		Command:  "./boot.sh",
		Location: ir.Location{File: file, Key: "hooks.sessionStart[0].command"},
	}
}

// A manifest is read wherever in the tree it sits, and what it declares
// carries the manifest's own path so a reader lands on the declaration.
func TestPluginEntitiesReadAManifestWhereverItSits(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
		want []ir.Entity
	}{
		{
			name: "at the repository root",
			fsys: fstest.MapFS{
				".cursor-plugin/plugin.json": manifest(inlineHook),
			},
			want: []ir.Entity{inlineHookAt(".cursor-plugin/plugin.json")},
		},
		{
			name: "vendored below a directory a reviewer skims",
			fsys: fstest.MapFS{
				"node_modules/shipper/.cursor-plugin/plugin.json": manifest(inlineHook),
			},
			want: []ir.Entity{inlineHookAt("node_modules/shipper/.cursor-plugin/plugin.json")},
		},
		{
			name: "ordered by manifest path rather than by walk order",
			fsys: fstest.MapFS{
				"plugins/a/.cursor-plugin/plugin.json":   manifest(inlineHook),
				"plugins/a-x/.cursor-plugin/plugin.json": manifest(inlineHook),
			},
			want: []ir.Entity{
				inlineHookAt("plugins/a-x/.cursor-plugin/plugin.json"),
				inlineHookAt("plugins/a/.cursor-plugin/plugin.json"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := componentsFrom(t, tt.fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("pluginEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A marketplace index declares no plugin of its own, so the directory
// holding one is not a plugin root: the component locations beside it belong
// to whoever published the index. The manifest below is what proves the same
// walk does reach a plugin root's components.
func TestPluginEntitiesLeaveTheNeighboursOfAMarketplaceIndexUnread(t *testing.T) {
	fsys := fstest.MapFS{
		".cursor-plugin/marketplace.json":              manifest(`{"name":"example-marketplace","owner":{"name":"example-owner"},"plugins":[{"name":"ship-tool"}]}`),
		"hooks/hooks.json":                             manifest(`{"hooks":{"sessionStart":[{"command":"./index.sh"}]}}`),
		"plugins/ship-tool/.cursor-plugin/plugin.json": manifest(inlineHook),
	}

	got, warnings := componentsFrom(t, fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	want := []ir.Entity{inlineHookAt("plugins/ship-tool/.cursor-plugin/plugin.json")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
}

// One malformed manifest leaves the tree's other plugins read.
func TestPluginEntitiesKeepSiblingManifestsWhenOneIsMalformed(t *testing.T) {
	const broken = "plugins/broken/.cursor-plugin/plugin.json"
	const healthy = "plugins/ship-tool/.cursor-plugin/plugin.json"

	fsys := fstest.MapFS{
		broken:  manifest(`{"`),
		healthy: manifest(inlineHook),
	}

	got, warnings := componentsFrom(t, fsys)

	want := []ir.Entity{inlineHookAt(healthy)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != broken {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, broken)
	}
}

type readDirFaultFS struct {
	m   fstest.MapFS
	dir string
}

func (f readDirFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readDirFaultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.dir {
		return nil, fs.ErrPermission
	}
	return f.m.ReadDir(name)
}

// A directory the walk cannot list names itself in a Warning, and the
// manifests found elsewhere are still read.
func TestPluginEntitiesKeepManifestsFoundBesideAnUnlistableDirectory(t *testing.T) {
	const unlistable = "vendor"
	const healthy = "plugins/ship-tool/.cursor-plugin/plugin.json"

	fsys := readDirFaultFS{
		m: fstest.MapFS{
			healthy: manifest(inlineHook),
			"vendor/hidden/.cursor-plugin/plugin.json": manifest(inlineHook),
		},
		dir: unlistable,
	}

	got, warnings := componentsFrom(t, fsys)

	want := []ir.Entity{inlineHookAt(healthy)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pluginEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != unlistable {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, unlistable)
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

// This parser walks to its subject rather than reading one known path, so the
// entry it reaches is whichever the tree put there. Type bits settle it, and
// the manifest beside it is still read.
func TestPluginEntitiesRefuseAFIFOManifestWithoutOpeningIt(t *testing.T) {
	const piped = "plugins/piped/.cursor-plugin/plugin.json"
	const healthy = "plugins/ship-tool/.cursor-plugin/plugin.json"

	fsys := blockingPathFS{
		m: fstest.MapFS{
			piped:   &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(inlineHook)},
			healthy: manifest(inlineHook),
		},
		path: piped,
	}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := pluginEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
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

// A signature can still match manifest paths and stop qualifying for
// discovery's plugin-root derivation.
func TestPluginManifestsAgreeWithDiscovery(t *testing.T) {
	fsys := fstest.MapFS{
		".cursor-plugin/plugin.json":                   manifest(`{"name":"root-plugin"}`),
		"plugins/ship-tool/.cursor-plugin/plugin.json": manifest(`{"name":"ship-tool"}`),
		".cursor-plugin/marketplace.json":              manifest(`{"name":"example-marketplace"}`),
		"unrelated/dir/plugin.json":                    manifest(`{"name":"decoy"}`),
		"evil.cursor-plugin/plugin.json":               manifest(`{"name":"decoy"}`),
	}

	manifests, _, err := pluginManifests(fsys)
	if err != nil {
		t.Fatalf("pluginManifests() error = %v, want nil", err)
	}
	if len(manifests.cursor) == 0 {
		t.Fatal("pluginManifests() found nothing; a comparison of two empty lists proves nothing")
	}

	want := make([]string, 0, len(manifests.cursor))
	for _, m := range manifests.cursor {
		want = append(want, path.Dir(path.Dir(m)))
	}

	result, _, err := discovery.Discover(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Discover() error = %v, want nil", err)
	}
	if !slices.Equal(want, result.PluginRoots) {
		t.Fatalf("pluginManifests() roots = %v, discovery.Discover() PluginRoots = %v — diverged", want, result.PluginRoots)
	}
}
