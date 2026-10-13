package cursor

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func cliGlobalMapFS(data string) fstest.MapFS {
	return fstest.MapFS{cliGlobalFileName: &fstest.MapFile{Data: []byte(data)}}
}

func parseGlobalOf(t *testing.T, fsys fstest.MapFS) []ir.Entity {
	t.Helper()
	entities, warnings, err := New().ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %+v, want none", warnings)
	}
	return entities
}

func TestParseGlobalSurfacesPermissionsFromCLIConfig(t *testing.T) {
	got := parseGlobalOf(t, cliGlobalMapFS(`{"permissions":{"allow":["Shell(npm ci)"]}}`))
	if len(got) != 1 {
		t.Fatalf("ParseGlobal() = %+v, want one entity", got)
	}
	p, ok := got[0].(ir.ToolPermission)
	if !ok {
		t.Fatalf("entity %+v is %T, want ir.ToolPermission", got[0], got[0])
	}
	if p.Location.File != cliGlobalFileName {
		t.Errorf("Location.File = %q, want %q", p.Location.File, cliGlobalFileName)
	}
}

// The home CLI configuration withholds an allow entry its deny list repeats,
// and leaves one the deny list does not.
func TestParseGlobalWithholdsAnAllowEntryItsDenyListRepeats(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     []string
	}{
		{
			name:     "repeated entry is withheld",
			document: `{"permissions":{"allow":["Shell(npm ci)","Shell(rm)"],"deny":["Shell(rm)"]}}`,
			want:     []string{"Shell|npm ci"},
		},
		{
			name:     "unrepeated entry stands",
			document: `{"permissions":{"allow":["Shell(npm ci)"],"deny":["Shell(rm)"]}}`,
			want:     []string{"Shell|npm ci"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, e := range parseGlobalOf(t, cliGlobalMapFS(tt.document)) {
				p, ok := e.(ir.ToolPermission)
				if !ok {
					t.Fatalf("entity = %+v, want an ir.ToolPermission", e)
				}
				got = append(got, p.Tool+"|"+p.Argument)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("permissions = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGlobalMalformedDocumentWarnsNamingTheGlobalFile(t *testing.T) {
	entities, warnings, err := New().ParseGlobal(cliGlobalMapFS(`["not an object"]`))
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("ParseGlobal() entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != cliGlobalFileName {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, cliGlobalFileName)
	}
}

// A wrong-typed permissions key warns naming the global file, not the
// project one: the two files share entitiesFromPermissions, so a hardcoded
// file name there would misattribute this warning silently.
func TestParseGlobalPermissionsWrongFormWarnsNamingTheGlobalFile(t *testing.T) {
	entities, warnings, err := New().ParseGlobal(cliGlobalMapFS(`{"permissions":["Shell(ls)"]}`))
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != cliGlobalFileName {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, cliGlobalFileName)
	}
}

func TestParseGlobalAbsentFileIsSilent(t *testing.T) {
	entities, warnings, err := New().ParseGlobal(fstest.MapFS{})
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("ParseGlobal() = (%+v, %+v), want neither", entities, warnings)
	}
}

// Both the project CLI file and the global one can sit in one fixture; each
// method must attribute nothing to the other's file.
func TestParseAndParseGlobalStayApartOnTheSameTree(t *testing.T) {
	fsys := fstest.MapFS{
		cliFileName:       &fstest.MapFile{Data: []byte(`{"permissions":{"allow":["Shell(project)"]}}`)},
		cliGlobalFileName: &fstest.MapFile{Data: []byte(`{"permissions":{"allow":["Shell(global)"]}}`)},
	}

	a := New()
	parsed, parseWarnings, err := a.Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(parseWarnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", parseWarnings)
	}
	for _, e := range parsed {
		p, ok := e.(ir.ToolPermission)
		if ok && p.Location.File == cliGlobalFileName {
			t.Fatalf("Parse() attributed an entity to %q, want it to read only %q", cliGlobalFileName, cliFileName)
		}
	}

	global, globalWarnings, err := a.ParseGlobal(fsys)
	if err != nil {
		t.Fatalf("ParseGlobal() error = %v, want nil", err)
	}
	if len(globalWarnings) != 0 {
		t.Fatalf("ParseGlobal() warnings = %+v, want none", globalWarnings)
	}
	for _, e := range global {
		p, ok := e.(ir.ToolPermission)
		if ok && p.Location.File == cliFileName {
			t.Fatalf("ParseGlobal() attributed an entity to %q, want it to read only %q", cliFileName, cliGlobalFileName)
		}
	}

	if len(parsed) != 1 || parsed[0].(ir.ToolPermission).Argument != "project" {
		t.Fatalf("Parse() = %+v, want the project-file grant alone", parsed)
	}
	if len(global) != 1 || global[0].(ir.ToolPermission).Argument != "global" {
		t.Fatalf("ParseGlobal() = %+v, want the global-file grant alone", global)
	}
}

// The malformed arm gives the "no warning names them" check a warning to
// inspect; approvalMode and sandbox.mode are wrong-typed in it, so a
// producer over either would warn where no warning is wanted.
func TestParseGlobalUnreadKeysStayOut(t *testing.T) {
	unreadKeys := []string{"authInfo", "Cache", "approvalMode", "sandbox"}

	tests := []struct {
		name         string
		document     string
		wantEntities int
		wantWarnings int
	}{
		{
			name: "the read key is well formed",
			document: `{
				"authInfo": {"token": "placeholder-not-a-credential"},
				"privacyCache": {"x": 1},
				"serverConfigCache": {"y": 2},
				"permissions": {"allow": ["Shell(npm ci)"]},
				"approvalMode": "unrestricted",
				"sandbox": {"mode": "disabled", "networkAccess": "allow_all"}
			}`,
			wantEntities: 1,
			wantWarnings: 0,
		},
		{
			name: "the read key is malformed",
			document: `{
				"authInfo": {"token": "placeholder-not-a-credential"},
				"privacyCache": {"x": 1},
				"serverConfigCache": {"y": 2},
				"permissions": ["Shell(npm ci)"],
				"approvalMode": 5,
				"sandbox": {"mode": 5, "networkAccess": "allow_all"}
			}`,
			wantEntities: 0,
			wantWarnings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().ParseGlobal(cliGlobalMapFS(tt.document))
			if err != nil {
				t.Fatalf("ParseGlobal() error = %v, want nil", err)
			}
			if len(warnings) != tt.wantWarnings {
				t.Fatalf("warnings = %+v, want %d", warnings, tt.wantWarnings)
			}
			if len(entities) != tt.wantEntities {
				t.Fatalf("entities = %+v, want %d read-key entities", entities, tt.wantEntities)
			}
			for _, e := range entities {
				v := reflect.ValueOf(e)
				loc := v.FieldByName("Location").Interface().(ir.Location)
				for _, key := range unreadKeys {
					if strings.Contains(loc.Key, key) {
						t.Fatalf("entity %+v names the unread key %q", e, key)
					}
				}
			}
			for _, w := range warnings {
				if strings.Contains(w.Err.Error(), "placeholder-not-a-credential") {
					t.Fatalf("warning %+v leaks an unread key's value", w)
				}
				for _, key := range unreadKeys {
					if strings.Contains(w.Err.Error(), key) {
						t.Fatalf("warning %+v names the unread key %q", w, key)
					}
				}
			}
		})
	}
}

func TestGlobalConfigDeclaresEveryCursorHomeEntry(t *testing.T) {
	cfg := New().GlobalConfig()
	if cfg.Base != adapter.BaseHome {
		t.Fatalf("GlobalConfig().Base = %q, want %q", cfg.Base, adapter.BaseHome)
	}
	want := map[string]bool{
		".cursor/mcp.json":         true,
		".cursor/hooks.json":       true,
		".cursor/hooks":            true,
		".cursor/sandbox.json":     true,
		".cursor/skills":           true,
		".cursor/agents":           true,
		".cursor/plugins/local":    true,
		".cursor/cli-config.json":  true,
		".cursor/permissions.json": true,
	}
	got := map[string]bool{}
	for _, e := range cfg.Entries {
		got[e] = true
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GlobalConfig().Entries = %v, want exactly %v", cfg.Entries, want)
	}
}
