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

func sandboxMapFS(data string) fstest.MapFS {
	return fstest.MapFS{sandboxFileName: &fstest.MapFile{Data: []byte(data)}}
}

func sandboxEntitiesOf(t *testing.T, fsys fs.FS) []ir.Entity {
	t.Helper()
	entities, warnings, err := sandboxEntities(fsys)
	if err != nil {
		t.Fatalf("sandboxEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("sandboxEntities() warnings = %+v, want none", warnings)
	}
	return entities
}

func TestSandboxEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings, err := sandboxEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("sandboxEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("sandboxEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// Each document below narrows what the agent may reach rather than widening
// it. networkPolicyStrict is here on the strength of a merge-rules note
// alone: no schema table describes it, so reading it would report a key
// whose shape this parser cannot state.
func TestSandboxEntitiesStaySilentOnADocumentThatGrantsNothing(t *testing.T) {
	documents := map[string]string{
		"default mode":     `{"type":"workspace_readwrite"}`,
		"read-only mode":   `{"type":"workspace_readonly"}`,
		"tmp write off":    `{"disableTmpWrite":true}`,
		"shared cache":     `{"enableSharedBuildCache":true}`,
		"egress denied":    `{"networkPolicy":{"default":"deny"}}`,
		"deny list":        `{"networkPolicy":{"deny":["*.example.com","203.0.113.0/24"]}}`,
		"strict egress":    `{"networkPolicyStrict":true}`,
		"unknown top key":  `{"somethingElse":"x"}`,
		"empty path lists": `{"additionalReadwritePaths":[],"additionalReadonlyPaths":[]}`,
	}

	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			entities, warnings, err := sandboxEntities(sandboxMapFS(document))
			if err != nil {
				t.Fatalf("sandboxEntities() error = %v, want nil", err)
			}
			if len(entities) != 0 || len(warnings) != 0 {
				t.Fatalf("sandboxEntities() = (%+v, %+v), want neither", entities, warnings)
			}
		})
	}
}

// The mode reaches the entity exactly as the file spells it, and a
// restriction the same document declares rides along unreported.
func TestSandboxEntitiesLocateTheDisablingMode(t *testing.T) {
	got := sandboxEntitiesOf(t, sandboxMapFS(`{"type":"insecure_none","disableTmpWrite":true}`))
	want := []ir.Entity{ir.Sandbox{
		Mode:     "insecure_none",
		Location: ir.Location{File: ".cursor/sandbox.json", Key: "type"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sandboxEntities() = %+v, want %+v", got, want)
	}
}

// The access a key grants travels on every entity that key produces, so two
// keys' paths stay distinguishable once they share a kind.
func TestSandboxEntitiesFanOutOneEntityPerGrantedPath(t *testing.T) {
	const document = `{
		"additionalReadwritePaths": ["~/.aws", "/opt/tools"],
		"additionalReadonlyPaths": ["~/.ssh"]
	}`

	got := sandboxEntitiesOf(t, sandboxMapFS(document))
	want := []ir.Entity{
		ir.Sandbox{
			Path:     "~/.aws",
			Access:   accessReadwrite,
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "additionalReadwritePaths[0]"},
		},
		ir.Sandbox{
			Path:     "/opt/tools",
			Access:   accessReadwrite,
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "additionalReadwritePaths[1]"},
		},
		ir.Sandbox{
			Path:     "~/.ssh",
			Access:   accessReadonly,
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "additionalReadonlyPaths[0]"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sandboxEntities() = %+v, want %+v", got, want)
	}
}

// The allow list fans out beside the fallback action, and a deny list in the
// same object contributes nothing.
func TestSandboxEntitiesFanOutTheEgressPolicy(t *testing.T) {
	const document = `{
		"networkPolicy": {
			"default": "allow",
			"allow": ["registry.example.com", "*.example.net", "203.0.113.0/24"],
			"deny": ["blocked.example.org"]
		}
	}`

	got := sandboxEntitiesOf(t, sandboxMapFS(document))
	want := []ir.Entity{
		ir.NetworkPolicy{
			Default:  "allow",
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "networkPolicy.default"},
		},
		ir.NetworkPolicy{
			Pattern:  "registry.example.com",
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "networkPolicy.allow[0]"},
		},
		ir.NetworkPolicy{
			Pattern:  "*.example.net",
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "networkPolicy.allow[1]"},
		},
		ir.NetworkPolicy{
			Pattern:  "203.0.113.0/24",
			Location: ir.Location{File: ".cursor/sandbox.json", Key: "networkPolicy.allow[2]"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sandboxEntities() = %+v, want %+v", got, want)
	}
}

func TestSandboxEntitiesReadEveryDocumentedPathKey(t *testing.T) {
	const document = `{"additionalReadwritePaths":["/a"],"additionalReadonlyPaths":["/b"]}`

	var keys []string
	for _, g := range pathGrants {
		keys = append(keys, g.key)
	}
	assertKeysMatchDocument(t, "pathGrants", keys, document)

	var accesses []string
	for _, e := range sandboxEntitiesOf(t, sandboxMapFS(document)) {
		accesses = append(accesses, e.(ir.Sandbox).Access)
	}
	if want := []string{accessReadwrite, accessReadonly}; !reflect.DeepEqual(accesses, want) {
		t.Fatalf("accesses = %v, want %v", accesses, want)
	}
}

func TestSandboxEntitiesDegradeMalformedSourcesToWarnings(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantMsg string
	}{
		{"invalid json", `{not json`, ""},
		{"empty document", ``, "unexpected end of JSON input"},
		{"array document", `[1,2,3]`, "expected an object, found an array"},
		{"object mode", `{"type":{"name":"insecure_none"}}`, "type: expected a string, found an object"},
		{"string path list", `{"additionalReadwritePaths":"~/.aws"}`, "additionalReadwritePaths: expected an array of paths, found a string"},
		{"object path entry", `{"additionalReadonlyPaths":[{"path":"~/.ssh"}]}`, "additionalReadonlyPaths[0]: expected a path string, found an object"},
		{"array network policy", `{"networkPolicy":["*.example.com"]}`, "networkPolicy: expected an object, found an array"},
		{"array egress default", `{"networkPolicy":{"default":["allow"]}}`, "networkPolicy.default: expected a string, found an array"},
		{"object allow list", `{"networkPolicy":{"allow":{"host":"x"}}}`, "networkPolicy.allow: expected an array of patterns, found an object"},
		{"number allow entry", `{"networkPolicy":{"allow":[7]}}`, "networkPolicy.allow[0]: expected a pattern string, found a non-object value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := sandboxEntities(sandboxMapFS(tt.data))
			if err != nil {
				t.Fatalf("sandboxEntities() error = %v, want nil: a malformed source degrades", err)
			}
			if len(entities) != 0 {
				t.Fatalf("sandboxEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != sandboxFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, sandboxFileName)
			}
			if tt.wantMsg != "" && warnings[0].Err.Error() != tt.wantMsg {
				t.Errorf("warning = %q, want %q", warnings[0].Err, tt.wantMsg)
			}
		})
	}
}

func TestSandboxEntitiesKeepSiblingsOfAMalformedKeyAndEntry(t *testing.T) {
	const document = `{
		"type": 5,
		"additionalReadwritePaths": [7, "/opt/survivor"],
		"additionalReadonlyPaths": "~/.ssh",
		"networkPolicy": {"default": "allow", "allow": [{"host": "x"}, "survivor.example.com"]}
	}`

	entities, warnings, err := sandboxEntities(sandboxMapFS(document))
	if err != nil {
		t.Fatalf("sandboxEntities() error = %v, want nil", err)
	}

	var values []string
	for _, e := range entities {
		switch v := e.(type) {
		case ir.Sandbox:
			values = append(values, v.Path)
		case ir.NetworkPolicy:
			values = append(values, v.Default+v.Pattern)
		default:
			t.Fatalf("entity %+v is %T, want a sandbox grant", e, e)
		}
	}
	if want := []string{"/opt/survivor", "allow", "survivor.example.com"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %v, want the well-formed siblings alone", values)
	}
	if len(warnings) != 4 {
		t.Fatalf("warnings = %+v, want one per faulty location", warnings)
	}
	for i, want := range []string{
		"type:",
		"additionalReadwritePaths[0]:",
		"additionalReadonlyPaths:",
		"networkPolicy.allow[0]:",
	} {
		if !strings.HasPrefix(warnings[i].Err.Error(), want) {
			t.Errorf("warnings[%d] = %q, want it to name %q", i, warnings[i].Err, want)
		}
	}
}

func TestSandboxEntitiesRefuseAFIFOWithoutOpeningIt(t *testing.T) {
	fsys := blockingOpenFS{m: fstest.MapFS{
		sandboxFileName: &fstest.MapFile{Mode: fs.ModeNamedPipe, Data: []byte(`{"type":"insecure_none"}`)},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := sandboxEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 {
			t.Fatalf("entities = %+v, want none: the entry is refused, never read", got.entities)
		}
		if len(got.warnings) != 1 || got.warnings[0].File != sandboxFileName {
			t.Fatalf("warnings = %+v, want exactly one naming %q", got.warnings, sandboxFileName)
		}
		if !errors.Is(got.warnings[0].Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", got.warnings[0].Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sandboxEntities never returned; it opened the pipe instead of reading its type bits")
	}
}

func TestParseSurfacesTheCursorSandbox(t *testing.T) {
	entities, warnings, err := New().Parse(sandboxMapFS(`{"type":"insecure_none"}`))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() = %+v, want one entity", entities)
	}
	s, ok := entities[0].(ir.Sandbox)
	if !ok {
		t.Fatalf("entity %+v is %T, want ir.Sandbox", entities[0], entities[0])
	}
	if s.Location.File != sandboxFileName {
		t.Errorf("Location.File = %q, want %q", s.Location.File, sandboxFileName)
	}
}
