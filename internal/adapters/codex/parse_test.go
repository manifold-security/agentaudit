package codex

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestParseLeavesATreeWithoutTheConfigFileSilent(t *testing.T) {
	entities, warnings, err := New().Parse(fstest.MapFS{"README.md": &fstest.MapFile{Data: []byte("# hi\n")}})
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("Parse() = (%+v, %+v), want neither", entities, warnings)
	}
}

// A document the decoder cannot read degrades to a Warning naming the file,
// so a source that stopped contributing is still named.
func TestParseDegradesAMalformedDocument(t *testing.T) {
	entities, warnings, err := New().Parse(configFS("sandbox_mode = \n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil: a malformed source degrades", err)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != configFileName {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, configFileName)
	}
}

type blockingOpenFS struct {
	m fstest.MapFS
}

func (f blockingOpenFS) Open(string) (fs.File, error) { select {} }

func (f blockingOpenFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f blockingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func TestParseRefusesAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		configFileName: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte("sandbox_mode = \"danger-full-access\"\n")},
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
		if len(got.warnings) != 1 || !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Fatalf("warnings = %+v, want one refusal naming the entry", got.warnings)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Parse never returned; it opened the pipe instead of reading its type bits")
	}
}

// Every surface the file declares reaches one Parse, so a document mixing
// them reports each rather than stopping at the first.
func TestParseReadsEverySurfaceOneDocumentDeclares(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"approval_policy = \"never\"\n" +
			"default_permissions = \":workspace\"\n\n" +
			"[sandbox_workspace_write]\nwritable_roots = [\"/\"]\nnetwork_access = true\n\n" +
			"[permissions.p.filesystem]\n\"~/src\" = \"write\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	byKey := map[string]string{}
	for _, e := range entities {
		byKey[ir.LocationOf(e).Key] = e.Kind()
	}
	want := map[string]string{
		"sandbox_workspace_write.writable_roots[0]": ir.KindSandbox,
		"sandbox_workspace_write.network_access":    ir.KindNetworkPolicy,
		"approval_policy":                           ir.KindPermissionMode,
		"default_permissions":                       ir.KindPermissionMode,
		"permissions.p.filesystem.~/src":            ir.KindSandbox,
	}
	for key, kind := range want {
		if byKey[key] != kind {
			t.Errorf("entity at %q = %q, want %q", key, byKey[key], kind)
		}
	}
	if len(byKey) != len(want) {
		t.Fatalf("Parse() keys = %+v, want exactly %+v", byKey, want)
	}
}
