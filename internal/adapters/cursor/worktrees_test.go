package cursor

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

func worktreesMapFS(data string) fstest.MapFS {
	return fstest.MapFS{worktreesFileName: &fstest.MapFile{Data: []byte(data)}}
}

func onlyProvisioners(t *testing.T, fsys fs.FS) []ir.Provisioner {
	t.Helper()
	entities, warnings, err := worktreeEntities(fsys)
	return provisionersFrom(t, entities, warnings, err)
}

func provisionersFrom(t *testing.T, entities []ir.Entity, warnings []adapter.Warning, err error) []ir.Provisioner {
	t.Helper()
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	provisioners := make([]ir.Provisioner, 0, len(entities))
	for _, e := range entities {
		p, ok := e.(ir.Provisioner)
		if !ok {
			t.Fatalf("entity %+v is %T, want ir.Provisioner", e, e)
		}
		provisioners = append(provisioners, p)
	}
	return provisioners
}

func TestWorktreeEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings, err := worktreeEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("worktreeEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("worktreeEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

func TestWorktreeEntitiesDeclaringNoSetupAreSilent(t *testing.T) {
	entities, warnings, err := worktreeEntities(worktreesMapFS(`{"somethingElse":["npm ci"]}`))
	if err != nil {
		t.Fatalf("worktreeEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("worktreeEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// An interpolation belongs to the shell that will run the command, so storing
// it expanded would attribute to the config a string it never contained.
func TestWorktreeEntitiesLocateCommandsInTheCursorFileUnexpanded(t *testing.T) {
	got := onlyProvisioners(t, worktreesMapFS(`{"setup-worktree-unix":["npm ci","./init.sh $ROOT_WORKTREE_PATH"]}`))
	want := []ir.Provisioner{
		{
			Phase:    "setup-worktree-unix",
			Command:  "npm ci",
			Location: ir.Location{File: ".cursor/worktrees.json", Key: "setup-worktree-unix[0]"},
		},
		{
			Phase:    "setup-worktree-unix",
			Command:  "./init.sh $ROOT_WORKTREE_PATH",
			Location: ir.Location{File: ".cursor/worktrees.json", Key: "setup-worktree-unix[1]"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worktreeEntities() = %+v, want %+v", got, want)
	}
}

// A script path is one command, so its key carries no element index.
func TestWorktreeEntitiesLocateAScriptPathAtItsBareKey(t *testing.T) {
	got := onlyProvisioners(t, worktreesMapFS(`{"setup-worktree":"bootstrap.sh"}`))
	want := []ir.Provisioner{{
		Phase:    "setup-worktree",
		Command:  "bootstrap.sh",
		Location: ir.Location{File: ".cursor/worktrees.json", Key: "setup-worktree"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worktreeEntities() = %+v, want %+v", got, want)
	}
}

// The provenance key carries its own phase, so a reader following a finding
// lands on the declaration that produced it.
func TestWorktreeEntitiesReadEveryDocumentedSetupKey(t *testing.T) {
	const document = `{"setup-worktree":"generic.sh","setup-worktree-windows":["win.ps1"],"setup-worktree-unix":["unix.sh"]}`

	assertKeysMatchDocument(t, "setupKeys", setupKeys, document)

	got := onlyProvisioners(t, worktreesMapFS(document))

	var keys []string
	for _, p := range got {
		keys = append(keys, p.Location.Key)
	}
	want := []string{
		"setup-worktree-unix[0]",
		"setup-worktree-windows[0]",
		"setup-worktree",
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for _, p := range got {
		if !strings.HasPrefix(p.Location.Key, p.Phase) {
			t.Errorf("provisioner at %q carries phase %q", p.Location.Key, p.Phase)
		}
	}
}

func TestWorktreeEntitiesDegradeMalformedSourcesToWarnings(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantMsg string
	}{
		{"invalid json", `{not json`, ""},
		{"empty document", ``, "unexpected end of JSON input"},
		{"array document", `[1,2,3]`, "expected an object, found an array"},
		{"object setup key", `{"setup-worktree-unix":{"run":"x"}}`, "setup-worktree-unix: expected an array of commands or a script path, found an object"},
		{"number setup key", `{"setup-worktree":5}`, "setup-worktree: expected an array of commands or a script path, found a non-object value"},
		{"object command", `{"setup-worktree-unix":[{"command":"x"}]}`, "setup-worktree-unix[0]: expected a shell command string, found an object"},
		{"number command", `{"setup-worktree-windows":[7]}`, "setup-worktree-windows[0]: expected a shell command string, found a non-object value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := worktreeEntities(worktreesMapFS(tt.data))
			if err != nil {
				t.Fatalf("worktreeEntities() error = %v, want nil: a malformed source degrades", err)
			}
			if len(entities) != 0 {
				t.Fatalf("worktreeEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != worktreesFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, worktreesFileName)
			}
			if tt.wantMsg != "" && warnings[0].Err.Error() != tt.wantMsg {
				t.Errorf("warning = %q, want %q", warnings[0].Err, tt.wantMsg)
			}
		})
	}
}

// A faulty key and a faulty element both degrade at their own level.
func TestWorktreeEntitiesKeepSiblingsOfAMalformedKeyAndElement(t *testing.T) {
	entities, warnings, err := worktreeEntities(worktreesMapFS(`{"setup-worktree-unix":[7,"survivor"],"setup-worktree-windows":{"run":"x"},"setup-worktree":"generic.sh"}`))
	if err != nil {
		t.Fatalf("worktreeEntities() error = %v, want nil", err)
	}

	var commands []string
	for _, e := range entities {
		commands = append(commands, e.(ir.Provisioner).Command)
	}
	if !reflect.DeepEqual(commands, []string{"survivor", "generic.sh"}) {
		t.Fatalf("commands = %v, want the well-formed siblings alone", commands)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v, want one per faulty location", warnings)
	}
	for i, want := range []string{"setup-worktree-unix[0]:", "setup-worktree-windows:"} {
		if !strings.HasPrefix(warnings[i].Err.Error(), want) {
			t.Errorf("warnings[%d] = %q, want it to name %q", i, warnings[i].Err, want)
		}
	}
}

func TestWorktreeEntitiesRefuseAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		worktreesFileName: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"setup-worktree-unix":["npm ci"]}`)},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := worktreeEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 {
			t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != worktreesFileName {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, worktreesFileName)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("worktreeEntities never returned; it opened the pipe instead of reading its type bits")
	}
}

func TestParseSurfacesTheCursorWorktreeSetup(t *testing.T) {
	entities, warnings, err := New().Parse(worktreesMapFS(`{"setup-worktree-unix":["./boot.sh"]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() = %+v, want one entity", entities)
	}
	p, ok := entities[0].(ir.Provisioner)
	if !ok {
		t.Fatalf("entity %+v is %T, want ir.Provisioner", entities[0], entities[0])
	}
	if p.Location.File != worktreesFileName {
		t.Errorf("Location.File = %q, want %q", p.Location.File, worktreesFileName)
	}
}
