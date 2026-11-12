package claude

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const launchPath = ".claude/launch.json"

func launchFS(body string) fstest.MapFS {
	return fstest.MapFS{launchPath: &fstest.MapFile{Data: []byte(body)}}
}

func launchLocation(i string) ir.Location {
	return ir.Location{File: launchPath, Key: "configurations[" + i + "]"}
}

func wantNoWarnings(t *testing.T, warnings []adapter.Warning) {
	t.Helper()
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
}

func TestPreviewServerEntitiesMapsARuntimeExecutable(t *testing.T) {
	tests := []struct {
		name string
		body string
		want ir.PreviewServer
	}{
		{
			name: "every mapped field",
			body: `{"configurations":[{"name":"web","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"apps/web","env":{"NODE_ENV":"development"},"url":"http://localhost:3000"}]}`,
			want: ir.PreviewServer{
				Name: "web", Command: "npm", Args: []string{"run", "dev"},
				Cwd: "apps/web", Env: map[string]string{"NODE_ENV": "development"},
				URL: "http://localhost:3000", Location: launchLocation("0"),
			},
		},
		{
			name: "an executable with no arguments",
			body: `{"configurations":[{"runtimeExecutable":"yarn"}]}`,
			want: ir.PreviewServer{Command: "yarn", Location: launchLocation("0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tt.body))
			wantNoWarnings(t, warnings)
			if want := []ir.Entity{tt.want}; !reflect.DeepEqual(entities, want) {
				t.Fatalf("entities = %+v, want %+v", entities, want)
			}
		})
	}
}

func TestPreviewServerEntitiesRunsAProgramWithNode(t *testing.T) {
	tests := []struct {
		name string
		body string
		want ir.PreviewServer
	}{
		{
			name: "a program with arguments",
			body: `{"configurations":[{"name":"api","program":"server.js","args":["--port","4000"]}]}`,
			want: ir.PreviewServer{Name: "api", Command: "node", Args: []string{"server.js", "--port", "4000"}, Location: launchLocation("0")},
		},
		{
			name: "a program alone",
			body: `{"configurations":[{"name":"api","program":"server.js"}]}`,
			want: ir.PreviewServer{Name: "api", Command: "node", Args: []string{"server.js"}, Location: launchLocation("0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tt.body))
			wantNoWarnings(t, warnings)
			if want := []ir.Entity{tt.want}; !reflect.DeepEqual(entities, want) {
				t.Fatalf("entities = %+v, want %+v", entities, want)
			}
		})
	}
}

func TestPreviewServerEntitiesKeepsAnAttachOnlyEntryCommandless(t *testing.T) {
	entities, warnings := previewServerEntities(launchFS(`{"configurations":[{"name":"attached","url":"http://localhost:4000"}]}`))
	wantNoWarnings(t, warnings)
	want := []ir.Entity{ir.PreviewServer{Name: "attached", URL: "http://localhost:4000", Location: launchLocation("0")}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities = %+v, want %+v", entities, want)
	}

	entities, _ = previewServerEntities(launchFS(`{"configurations":[{"name":"attached","url":"http://localhost:4000","runtimeExecutable":"npm"}]}`))
	if len(entities) != 1 {
		t.Fatalf("entities = %+v, want the one entry", entities)
	}
	got, ok := entities[0].(ir.PreviewServer)
	if !ok || got.Command != "npm" {
		t.Fatalf("entities = %+v, want the same entry running npm once it declares an executable", entities)
	}
}

// A runtime executable and a program in one entry are two things the entry
// could run, so the one that does not become the command still reaches the
// entity.
func TestPreviewServerEntitiesKeepsAProgramBesideARuntimeExecutable(t *testing.T) {
	tests := []struct {
		name string
		body string
		want ir.PreviewServer
	}{
		{
			name: "both declared",
			body: `{"configurations":[{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"program":"server.js","args":["--port","4000"]}]}`,
			want: ir.PreviewServer{
				Command: "npm", Args: []string{"run", "dev"},
				Program: "server.js", ProgramArgs: []string{"--port", "4000"},
				Location: launchLocation("0"),
			},
		},
		{
			name: "arguments with no program beside an executable",
			body: `{"configurations":[{"runtimeExecutable":"npm","args":["--port","4000"]}]}`,
			want: ir.PreviewServer{Command: "npm", ProgramArgs: []string{"--port", "4000"}, Location: launchLocation("0")},
		},
		{
			name: "runtime arguments with no executable beside a program",
			body: `{"configurations":[{"runtimeArgs":["--inspect"],"program":"server.js"}]}`,
			want: ir.PreviewServer{Args: []string{"--inspect"}, Program: "server.js", Location: launchLocation("0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tt.body))
			wantNoWarnings(t, warnings)
			if want := []ir.Entity{tt.want}; !reflect.DeepEqual(entities, want) {
				t.Fatalf("entities = %+v, want %+v", entities, want)
			}
		})
	}
}

// Arguments with nothing to run are still a capability to report: Desktop may
// supply a default runtime the file never names.
func TestPreviewServerEntitiesKeepsArgumentsWithNoCommand(t *testing.T) {
	tests := []struct {
		name string
		body string
		want ir.PreviewServer
	}{
		{
			name: "runtime arguments",
			body: `{"configurations":[{"name":"web","runtimeArgs":["run","dev"]}]}`,
			want: ir.PreviewServer{Name: "web", Args: []string{"run", "dev"}, Location: launchLocation("0")},
		},
		{
			name: "program arguments",
			body: `{"configurations":[{"name":"web","args":["--port","4000"]}]}`,
			want: ir.PreviewServer{Name: "web", Args: []string{"--port", "4000"}, Location: launchLocation("0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tt.body))
			wantNoWarnings(t, warnings)
			if want := []ir.Entity{tt.want}; !reflect.DeepEqual(entities, want) {
				t.Fatalf("entities = %+v, want %+v", entities, want)
			}
		})
	}
}

func TestPreviewServerEntitiesWarnsPerMalformedEntry(t *testing.T) {
	entities, warnings := previewServerEntities(launchFS(
		`{"configurations":[{"name":"web","runtimeExecutable":"npm"}, 7, {"name":"x","runtimeArgs":"dev"}, {"name":"api","program":"server.js"}]}`))

	want := []ir.Entity{
		ir.PreviewServer{Name: "web", Command: "npm", Location: launchLocation("0")},
		ir.PreviewServer{Name: "api", Command: "node", Args: []string{"server.js"}, Location: launchLocation("3")},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities = %+v, want the entries at [0] and [3]", entities)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v, want one each for [1] and [2]", warnings)
	}
	for i, w := range warnings {
		if w.File != launchPath {
			t.Errorf("warnings[%d].File = %q, want %q", i, w.File, launchPath)
		}
		if errors.Is(w.Err, adapter.ErrUnreadable) {
			t.Errorf("warnings[%d].Err = %v, want an unparsed entry, not an unreadable file", i, w.Err)
		}
	}
	if got, want := warnings[0].Err.Error(), "configurations[1]: expected an object, found a non-object value"; got != want {
		t.Errorf("warnings[0] = %q, want %q", got, want)
	}
	if got := warnings[1].Err.Error(); !strings.HasPrefix(got, "configurations[2]: ") || !strings.Contains(got, "runtimeArgs") {
		t.Errorf("warnings[1] = %q, want it to name configurations[2] and runtimeArgs", got)
	}
}

func TestPreviewServerEntitiesWarnsOnAFileItCannotDecode(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"a comment before the object", "// dev servers\n{\"configurations\":[{\"runtimeExecutable\":\"npm\"}]}", "invalid character '/' looking for beginning of value"},
		{"a truncated document", `{"configurations":[`, "unexpected end of JSON input"},
		{"a top-level array", `[]`, "expected an object, found an array"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := previewServerEntities(launchFS(tt.body))
			if len(entities) != 0 {
				t.Fatalf("entities = %+v, want none from a file that did not decode", entities)
			}
			if len(warnings) != 1 || warnings[0].File != launchPath {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, launchPath)
			}
			if errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Errorf("warning = %v, want an unparsed file, not an unreadable one", warnings[0].Err)
			}
			if got := warnings[0].Err.Error(); got != tt.wantErr {
				t.Errorf("warning = %q, want %q", got, tt.wantErr)
			}
		})
	}
}

func TestPreviewServerEntitiesWarnsWhenConfigurationsIsNotAnArray(t *testing.T) {
	entities, warnings := previewServerEntities(launchFS(`{"configurations":{"name":"web","runtimeExecutable":"npm"}}`))
	if len(entities) != 0 {
		t.Fatalf("entities = %+v, want none", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	if got, want := warnings[0].Err.Error(), "configurations: expected an array of configurations, found an object"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}

	for _, body := range []string{`{}`, `{"configurations":null}`, `{"configurations":[]}`} {
		entities, warnings := previewServerEntities(launchFS(body))
		if len(entities) != 0 || len(warnings) != 0 {
			t.Errorf("previewServerEntities(%s) = (%+v, %+v), want silence for a file with no configuration to read", body, entities, warnings)
		}
	}
}

func TestPreviewServerEntitiesIgnoresTheTypeOfPortAndAutoVerify(t *testing.T) {
	entities, warnings := previewServerEntities(launchFS(
		`{"autoVerify":"sometimes","configurations":[{"name":"web","runtimeExecutable":"npm","port":"3000","autoPort":"yes"}]}`))
	wantNoWarnings(t, warnings)
	want := []ir.Entity{ir.PreviewServer{Name: "web", Command: "npm", Location: launchLocation("0")}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities = %+v, want %+v", entities, want)
	}
}

func TestPreviewServerEntitiesSkipsANestedLaunchFile(t *testing.T) {
	nested := fstest.MapFS{"app/.claude/launch.json": &fstest.MapFile{Data: []byte(`{"configurations":[{"runtimeExecutable":"npm"}]}`)}}
	entities, warnings := previewServerEntities(nested)
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("previewServerEntities() = (%+v, %+v), want nothing from a file below the root", entities, warnings)
	}

	entities, _ = previewServerEntities(launchFS(`{"configurations":[{"runtimeExecutable":"npm"}]}`))
	if len(entities) != 1 {
		t.Fatalf("entities = %+v, want the same body read at the root", entities)
	}
}

func TestPreviewServerEntitiesRefusesADanglingLink(t *testing.T) {
	entities, warnings := previewServerEntities(fstest.MapFS{launchPath: symlink("../missing.json")})
	if len(entities) != 0 {
		t.Fatalf("entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != launchPath || !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warnings = %+v, want one unreadable warning naming %q", warnings, launchPath)
	}

	entities, warnings = previewServerEntities(fstest.MapFS{".claude/unrelated.txt": &fstest.MapFile{Data: []byte("x")}})
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("previewServerEntities() = (%+v, %+v), want silence when the file is absent", entities, warnings)
	}
}
