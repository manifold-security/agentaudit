package tomlconf

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
)

const testFile = ".codex/config.toml"

func docFS(data string) fstest.MapFS {
	return fstest.MapFS{testFile: &fstest.MapFile{Data: []byte(data)}}
}

func TestDocumentLeavesAnAbsentFileSilent(t *testing.T) {
	doc, warnings := Document(fstest.MapFS{}, testFile)
	if len(doc) != 0 || len(warnings) != 0 {
		t.Fatalf("Document() = (%+v, %+v), want neither", doc, warnings)
	}
}

func TestDocumentKeysATableByItsHeaderPath(t *testing.T) {
	doc, warnings := Document(docFS("sandbox_mode = \"workspace-write\"\n\n[sandbox_workspace_write]\nnetwork_access = true\n"), testFile)
	if len(warnings) != 0 {
		t.Fatalf("Document() warnings = %+v, want none", warnings)
	}

	if got := doc["sandbox_mode"]; got != "workspace-write" {
		t.Errorf("doc[%q] = %#v, want %q", "sandbox_mode", got, "workspace-write")
	}
	table, ok := doc["sandbox_workspace_write"].(map[string]any)
	if !ok {
		t.Fatalf("doc[%q] = %#v, want a table", "sandbox_workspace_write", doc["sandbox_workspace_write"])
	}
	if got := table["network_access"]; got != true {
		t.Errorf("table[%q] = %#v, want true", "network_access", got)
	}
}

// A syntax fault is reported in the document's own terms, so the message
// reaching a config author carries no Go vocabulary.
func TestDocumentDegradesAMalformedDocumentWithoutNamingAGoType(t *testing.T) {
	doc, warnings := Document(docFS("sandbox_mode = \n"), testFile)
	if len(doc) != 0 {
		t.Fatalf("Document() = %+v, want nothing from a document that did not decode", doc)
	}
	if len(warnings) != 1 || warnings[0].File != testFile {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, testFile)
	}
	for _, leak := range []string{"map[string]", "interface {}", "struct"} {
		if strings.Contains(warnings[0].Err.Error(), leak) {
			t.Errorf("warning = %q, must not leak a Go type name", warnings[0].Err)
		}
	}
}

// blockingOpenFS hangs on open alone, so it reddens only if Document reaches
// fs.ReadFile instead of fsguard.ReadResolvedRegular.
type blockingOpenFS struct {
	m fstest.MapFS
}

func (f blockingOpenFS) Open(string) (fs.File, error) { select {} }

func (f blockingOpenFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f blockingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func TestDocumentRefusesAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		testFile: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte("sandbox_mode = \"danger-full-access\"\n")},
	}}

	type result struct {
		doc      map[string]any
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		doc, warnings := Document(fsys, testFile)
		done <- result{doc, warnings}
	}()

	select {
	case got := <-done:
		if len(got.doc) != 0 {
			t.Fatalf("doc = %+v, want nothing: the entry is refused, never read", got.doc)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != testFile {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, testFile)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Document never returned; it opened the pipe instead of reading its type bits")
	}
}

func TestFormOfClassifiesADecodedValueByItsShape(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  Form
	}{
		{"an absent key", nil, FormAbsent},
		{"a string", "workspace-write", FormString},
		{"a boolean", true, FormBool},
		{"an array", []any{"/etc"}, FormArray},
		{"a table", map[string]any{"granular": true}, FormTable},
		{"an integer", int64(3), FormOther},
		{"a moment", time.Now(), FormOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormOf(tt.value); got != tt.want {
				t.Errorf("FormOf(%#v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// Every Form reads as the noun a warning completes, and no two share one.
func TestFormNameNamesEachFormDistinctly(t *testing.T) {
	forms := []Form{FormAbsent, FormString, FormBool, FormArray, FormTable, FormOther}
	seen := map[string]Form{}
	for _, f := range forms {
		name := FormName(f)
		if name == "" {
			t.Errorf("FormName(%v) = %q, want a noun a warning can complete", f, name)
		}
		if prior, dup := seen[name]; dup {
			t.Errorf("FormName(%v) = %q, already used by %v", f, name, prior)
		}
		seen[name] = f
	}
	if got := FormName(FormString); got != "a string" {
		t.Errorf("FormName(FormString) = %q, want %q", got, "a string")
	}
}
