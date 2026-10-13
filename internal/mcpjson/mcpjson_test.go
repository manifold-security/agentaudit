package mcpjson

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

const testFile = ".mcp.json"

func stdioResolver(Entry) (ir.Transport, string) { return ir.TransportStdio, "" }

func docFS(data string) fstest.MapFS {
	return fstest.MapFS{testFile: &fstest.MapFile{Data: []byte(data)}}
}

// EntitiesFromFile and ServersFromFile yield the same servers and warnings
// for this case.
func TestServersFromFileParityWithEntitiesFromFile(t *testing.T) {
	fsys := docFS(`{"mcpServers":{"build":{"command":"npx"}}}`)

	servers, serverWarnings, err := ServersFromFile(fsys, testFile, "mcpServers")
	if err != nil || len(serverWarnings) != 0 {
		t.Fatalf("ServersFromFile() = (%v, %+v), want no failure", err, serverWarnings)
	}
	if len(servers) != 1 || servers["build"].Command != "npx" {
		t.Fatalf("ServersFromFile() = %+v, want one build entry", servers)
	}

	entities, entityWarnings, err := EntitiesFromFile(fsys, testFile, "mcpServers", stdioResolver)
	if err != nil || len(entityWarnings) != 0 {
		t.Fatalf("EntitiesFromFile() = (%v, %+v), want no failure", err, entityWarnings)
	}
	want := Entities(servers, testFile, "mcpServers", stdioResolver)
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("EntitiesFromFile() = %+v, want %+v built from ServersFromFile's own servers", entities, want)
	}
}

// A wrong-typed headersHelper must not fail the entry's own decode.
func TestServersFromRawDecodesAnObjectValuedHeadersHelper(t *testing.T) {
	servers, warnings := ServersFromRaw([]byte(`{"docs":{"command":"npx","headersHelper":{"nested":"x"}}}`), testFile, "mcpServers")
	if len(warnings) != 0 {
		t.Fatalf("ServersFromRaw() warnings = %+v, want none", warnings)
	}
	entry, ok := servers["docs"]
	if !ok {
		t.Fatalf("ServersFromRaw() = %+v, want a docs entry", servers)
	}
	if _, ok := entry.HeadersHelper.(map[string]any); !ok {
		t.Fatalf("HeadersHelper = %#v (%T), want a decoded map", entry.HeadersHelper, entry.HeadersHelper)
	}
}

func TestEntitiesFromFileLeavesAnAbsentDocumentSilent(t *testing.T) {
	entities, warnings, err := EntitiesFromFile(fstest.MapFS{}, testFile, "mcpServers", stdioResolver)
	if err != nil {
		t.Fatalf("EntitiesFromFile() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("EntitiesFromFile() = (%+v, %+v), want neither", entities, warnings)
	}
}

func TestEntitiesFromFileLocatesServersUnderTheCallersKey(t *testing.T) {
	entities, warnings, err := EntitiesFromFile(docFS(`{"mcpServers":{"build":{"command":"npx"}}}`), testFile, "mcpServers", stdioResolver)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("EntitiesFromFile() = (%v, %+v), want no failure", err, warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("EntitiesFromFile() = %+v, want one entity", entities)
	}
	got := entities[0].(ir.MCPServer)
	if got.Location != (ir.Location{File: testFile, Key: "mcpServers.build"}) {
		t.Errorf("Location = %+v, want the caller's file and key prefix", got.Location)
	}
}

// A trial decode into the document's Go struct would name that struct to a
// config author who never wrote Go.
func TestEntitiesFromFileDegradesAWrongShapedDocumentWithoutNamingAGoType(t *testing.T) {
	entities, warnings, err := EntitiesFromFile(docFS(`[1,2,3]`), testFile, "mcpServers", stdioResolver)
	if err != nil {
		t.Fatalf("EntitiesFromFile() error = %v, want nil: a malformed source degrades", err)
	}
	if len(entities) != 0 {
		t.Fatalf("EntitiesFromFile() entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != testFile {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, testFile)
	}
	if got, want := warnings[0].Err.Error(), "expected an object, found an array"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}
	for _, leak := range []string{"struct", "json.RawMessage", "map[string]"} {
		if strings.Contains(warnings[0].Err.Error(), leak) {
			t.Errorf("warning = %q, must not leak a Go type name", warnings[0].Err)
		}
	}
}

// blockingOpenFS hangs on open alone, so it reddens only if EntitiesFromFile
// reaches fs.ReadFile instead of fsguard.ReadResolvedRegular.
type blockingOpenFS struct {
	m fstest.MapFS
}

func (f blockingOpenFS) Open(string) (fs.File, error) { select {} }

func (f blockingOpenFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f blockingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func TestEntitiesFromFileRefusesAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		testFile: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"mcpServers":{"s":{"command":"npx"}}}`)},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := EntitiesFromFile(fsys, testFile, "mcpServers", stdioResolver)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 {
			t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != testFile {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, testFile)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("EntitiesFromFile never returned; it opened the pipe instead of reading its type bits")
	}
}
