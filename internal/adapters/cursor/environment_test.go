package cursor

import (
	"encoding/json"
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

func environmentMapFS(data string) fstest.MapFS {
	return fstest.MapFS{environmentFileName: &fstest.MapFile{Data: []byte(data)}}
}

func onlyEnvironmentProvisioners(t *testing.T, fsys fs.FS) []ir.Provisioner {
	t.Helper()
	entities, warnings, err := environmentEntities(fsys)
	return provisionersFrom(t, entities, warnings, err)
}

// assertKeysMatchDocument cross-checks a production key list against a
// hand-written document in both directions, so a key added to either side
// fails by name instead of going silently unread. The document is written out
// by hand, independently of the list, so the two can disagree.
func assertKeysMatchDocument(t *testing.T, list string, keys []string, document string) {
	t.Helper()

	var declared map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &declared); err != nil {
		t.Fatalf("document: %v", err)
	}
	for _, key := range keys {
		if _, ok := declared[key]; !ok {
			t.Errorf("%s declares %q with no row in this document", list, key)
		}
	}
	for key := range declared {
		var known bool
		for _, k := range keys {
			known = known || k == key
		}
		if !known {
			t.Errorf("this document carries %q, which %s no longer declares", key, list)
		}
	}
}

func TestEnvironmentEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings, err := environmentEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("environmentEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("environmentEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// The keys below shape the environment rather than declaring anything that
// runs in it, so reading one would report a capability the file never gave.
func TestEnvironmentEntitiesDeclaringNoExecutionAreSilent(t *testing.T) {
	const document = `{"name":"agent-env","user":"ubuntu","image":"node:22","snapshot":"snap-1","ports":[3000]}`

	entities, warnings, err := environmentEntities(environmentMapFS(document))
	if err != nil {
		t.Fatalf("environmentEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("environmentEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// A description must leave no trace on the entity its entry produces.
func TestEnvironmentEntitiesLocateEveryCommandPhaseUnexpanded(t *testing.T) {
	const document = `{
		"install": "npm ci && ./setup.sh $HOME",
		"start": "npm run dev",
		"terminals": [
			{"name": "watcher", "command": "npm run watch", "description": "displayed to the agent"},
			{"command": "./tail.sh"}
		]
	}`

	got := onlyEnvironmentProvisioners(t, environmentMapFS(document))
	want := []ir.Provisioner{
		{
			Phase:    "install",
			Command:  "npm ci && ./setup.sh $HOME",
			Location: ir.Location{File: ".cursor/environment.json", Key: "install"},
		},
		{
			Phase:    "start",
			Command:  "npm run dev",
			Location: ir.Location{File: ".cursor/environment.json", Key: "start"},
		},
		{
			Phase:    "terminals",
			Name:     "watcher",
			Command:  "npm run watch",
			Location: ir.Location{File: ".cursor/environment.json", Key: "terminals[0].command"},
		},
		{
			Phase:    "terminals",
			Command:  "./tail.sh",
			Location: ir.Location{File: ".cursor/environment.json", Key: "terminals[1].command"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environmentEntities() = %+v, want %+v", got, want)
	}
}

// terminals accepts one entry in place of the array, and an entry reached
// that way resolves to the same phase as an element of the array.
func TestEnvironmentEntitiesReadASingleTerminalEntry(t *testing.T) {
	got := onlyEnvironmentProvisioners(t, environmentMapFS(`{"terminals":{"name":"solo","command":"./serve.sh"}}`))
	want := []ir.Provisioner{{
		Phase:    "terminals",
		Name:     "solo",
		Command:  "./serve.sh",
		Location: ir.Location{File: ".cursor/environment.json", Key: "terminals." + commandField},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("environmentEntities() = %+v, want %+v", got, want)
	}
}

// A build names its Dockerfile either by path or by carrying the file
// itself, and the phase is what tells a reader which key declared the value.
func TestEnvironmentEntitiesLocateEitherBuildForm(t *testing.T) {
	tests := []struct {
		name      string
		document  string
		wantPhase string
		wantValue string
	}{
		{"path", `{"build":{"dockerfile":"docker/agent.Dockerfile"}}`, "build.dockerfile", "docker/agent.Dockerfile"},
		{"contents", `{"build":{"dockerfileContents":"FROM node:22"}}`, "build.dockerfileContents", "FROM node:22"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onlyEnvironmentProvisioners(t, environmentMapFS(tt.document))
			want := []ir.Provisioner{{
				Phase:    tt.wantPhase,
				Command:  tt.wantValue,
				Location: ir.Location{File: ".cursor/environment.json", Key: tt.wantPhase},
			}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("environmentEntities() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestEnvironmentEntitiesReadEveryDocumentedKey(t *testing.T) {
	const commands = `{"install":"npm ci","start":"npm run dev"}`
	const build = `{"dockerfile":"docker/agent.Dockerfile","dockerfileContents":"FROM node:22"}`

	assertKeysMatchDocument(t, "commandKeys", commandKeys, commands)
	assertKeysMatchDocument(t, "buildKeys", buildKeys, build)

	var keys []string
	for _, p := range onlyEnvironmentProvisioners(t, environmentMapFS(commands)) {
		keys = append(keys, p.Location.Key)
	}
	if want := []string{"install", "start"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

func TestEnvironmentEntitiesDegradeMalformedSourcesToWarnings(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantMsg string
	}{
		{"invalid json", `{not json`, ""},
		{"empty document", ``, "unexpected end of JSON input"},
		{"array document", `[1,2,3]`, "expected an object, found an array"},
		{"object command key", `{"install":{"run":"x"}}`, "install: expected a string, found an object"},
		{"number command key", `{"start":5}`, "start: expected a string, found a non-object value"},
		{"string terminals", `{"terminals":"./serve.sh"}`, "terminals: expected an array of entries or one entry, found a string"},
		{"number terminal entry", `{"terminals":[7]}`, "terminals[0]: expected an object, found a non-object value"},
		{"wrong-typed terminal field", `{"terminals":[{"command":1}]}`, "terminals[0].command: expected string, found number"},
		{"array build", `{"build":["docker/agent.Dockerfile"]}`, "build: expected an object, found an array"},
		{"object build key", `{"build":{"dockerfile":{"path":"x"}}}`, "build.dockerfile: expected a string, found an object"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := environmentEntities(environmentMapFS(tt.data))
			if err != nil {
				t.Fatalf("environmentEntities() error = %v, want nil: a malformed source degrades", err)
			}
			if len(entities) != 0 {
				t.Fatalf("environmentEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != environmentFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, environmentFileName)
			}
			if tt.wantMsg != "" && warnings[0].Err.Error() != tt.wantMsg {
				t.Errorf("warning = %q, want %q", warnings[0].Err, tt.wantMsg)
			}
		})
	}
}

func TestEnvironmentEntitiesKeepSiblingsOfAMalformedKeyAndEntry(t *testing.T) {
	const document = `{
		"install": {"run": "x"},
		"start": "survivor",
		"terminals": [7, {"command": "terminal survivor"}],
		"build": {"dockerfile": 9, "dockerfileContents": "FROM node:22"}
	}`

	entities, warnings, err := environmentEntities(environmentMapFS(document))
	if err != nil {
		t.Fatalf("environmentEntities() error = %v, want nil", err)
	}

	var commands []string
	for _, e := range entities {
		commands = append(commands, e.(ir.Provisioner).Command)
	}
	if want := []string{"survivor", "terminal survivor", "FROM node:22"}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %v, want the well-formed siblings alone", commands)
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings = %+v, want one per faulty location", warnings)
	}
	for i, want := range []string{"install:", "terminals[0]:", "build.dockerfile:"} {
		if !strings.HasPrefix(warnings[i].Err.Error(), want) {
			t.Errorf("warnings[%d] = %q, want it to name %q", i, warnings[i].Err, want)
		}
	}
}

func TestEnvironmentEntitiesRefuseAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		environmentFileName: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"install":"npm ci"}`)},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := environmentEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 {
			t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != environmentFileName {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, environmentFileName)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("environmentEntities never returned; it opened the pipe instead of reading its type bits")
	}
}

func TestParseSurfacesTheCursorEnvironment(t *testing.T) {
	entities, warnings, err := New().Parse(environmentMapFS(`{"start":"./boot.sh"}`))
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
	if p.Location.File != environmentFileName {
		t.Errorf("Location.File = %q, want %q", p.Location.File, environmentFileName)
	}
}
