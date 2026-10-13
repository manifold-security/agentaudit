package cursor

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func cliMapFS(data string) fstest.MapFS {
	return fstest.MapFS{cliFileName: &fstest.MapFile{Data: []byte(data)}}
}

func cliEntitiesOf(t *testing.T, fsys fstest.MapFS) []ir.Entity {
	t.Helper()
	entities, warnings, err := cliEntities(fsys)
	if err != nil {
		t.Fatalf("cliEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("cliEntities() warnings = %+v, want none", warnings)
	}
	return entities
}

func TestCLIEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings, err := cliEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("cliEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("cliEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// Reading a deny entry would report a restriction as a capability.
func TestCLIEntitiesStaySilentOnADocumentThatGrantsNothing(t *testing.T) {
	documents := map[string]string{
		"deny list alone":   `{"permissions":{"deny":["Shell(rm)","Read(.env*)"]}}`,
		"empty allow list":  `{"permissions":{"allow":[]}}`,
		"empty permissions": `{"permissions":{}}`,
		"no permissions":    `{"model":"composer-1"}`,
		"empty document":    `{}`,
	}

	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			entities, warnings, err := cliEntities(cliMapFS(document))
			if err != nil {
				t.Fatalf("cliEntities() error = %v, want nil", err)
			}
			if len(entities) != 0 || len(warnings) != 0 {
				t.Fatalf("cliEntities() = (%+v, %+v), want neither", entities, warnings)
			}
		})
	}
}

// Every allow entry becomes a grant of its own, decomposed into the tool it
// names and the argument scoping it.
func TestCLIEntitiesFanOutOneEntityPerAllowedPermission(t *testing.T) {
	const document = `{
		"permissions": {
			"allow": ["Shell(npm run build)", "Read(src/**/*.ts)", "Mcp(github:create_issue)"],
			"deny": ["Shell(rm)"]
		}
	}`

	got := cliEntitiesOf(t, cliMapFS(document))
	want := []ir.Entity{
		ir.ToolPermission{
			Tool:     "Shell",
			Argument: "npm run build",
			Location: ir.Location{File: ".cursor/cli.json", Key: "permissions.allow[0]"},
		},
		ir.ToolPermission{
			Tool:     "Read",
			Argument: "src/**/*.ts",
			Location: ir.Location{File: ".cursor/cli.json", Key: "permissions.allow[1]"},
		},
		ir.ToolPermission{
			Tool:     "Mcp",
			Argument: "github:create_issue",
			Location: ir.Location{File: ".cursor/cli.json", Key: "permissions.allow[2]"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cliEntities() = %+v, want %+v", got, want)
	}
}

// The argument reaches the entity exactly as the file spells it: a wildcard
// expanded here would report a grant the file never wrote, and one folded
// away would hide how wide the entry is.
func TestCLIEntitiesCarryTheArgumentVerbatim(t *testing.T) {
	const document = `{"permissions":{"allow":["WebFetch(*)","Shell(curl:*)","Write(**/*.key)","Shell(sh -c (id))"]}}`

	var arguments []string
	for _, e := range cliEntitiesOf(t, cliMapFS(document)) {
		arguments = append(arguments, e.(ir.ToolPermission).Argument)
	}
	want := []string{"*", "curl:*", "**/*.key", "sh -c (id)"}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %q, want %q", arguments, want)
	}
}

// An entry in no shape the decomposition recognises surfaces whole rather
// than being dropped.
func TestCLIEntitiesSurfaceAnUndecomposableEntryWhole(t *testing.T) {
	const document = `{"permissions":{"allow":["Shell","Shell(rm","Write(**/*.key) # keys",")","(rm -rf /)","()"]}}`

	got := cliEntitiesOf(t, cliMapFS(document))
	var tools, arguments []string
	for _, e := range got {
		p := e.(ir.ToolPermission)
		tools = append(tools, p.Tool)
		arguments = append(arguments, p.Argument)
	}
	wantTools := []string{"Shell", "Shell(rm", "Write(**/*.key) # keys", ")", "(rm -rf /)", "()"}
	if !reflect.DeepEqual(tools, wantTools) {
		t.Fatalf("tools = %q, want %q", tools, wantTools)
	}
	if want := []string{"", "", "", "", "", ""}; !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %q, want %q", arguments, want)
	}
}

func TestCLIEntitiesDegradeMalformedSourcesToWarnings(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantMsg string
	}{
		{"invalid json", `{not json`, ""},
		{"empty document", ``, "unexpected end of JSON input"},
		{"array document", `["Shell(ls)"]`, "expected an object, found an array"},
		{"array permissions", `{"permissions":["Shell(ls)"]}`, "permissions: expected an object, found an array"},
		{"string permissions", `{"permissions":"all"}`, "permissions: expected an object, found a string"},
		{"object allow list", `{"permissions":{"allow":{"Shell":"ls"}}}`, "permissions.allow: expected an array of permissions, found an object"},
		{"string allow list", `{"permissions":{"allow":"Shell(ls)"}}`, "permissions.allow: expected an array of permissions, found a string"},
		{"object allow entry", `{"permissions":{"allow":[{"tool":"Shell"}]}}`, "permissions.allow[0]: expected a permission string, found an object"},
		{"number allow entry", `{"permissions":{"allow":[7]}}`, "permissions.allow[0]: expected a permission string, found a non-object value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := cliEntities(cliMapFS(tt.data))
			if err != nil {
				t.Fatalf("cliEntities() error = %v, want nil: a malformed source degrades", err)
			}
			if len(entities) != 0 {
				t.Fatalf("cliEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != cliFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, cliFileName)
			}
			if tt.wantMsg != "" && warnings[0].Err.Error() != tt.wantMsg {
				t.Errorf("warning = %q, want %q", warnings[0].Err, tt.wantMsg)
			}
		})
	}
}

// A faulty entry must not take the grants beside it with it, or one typo
// silences a permission list the reader is told nothing about.
func TestCLIEntitiesKeepSiblingsOfAMalformedEntry(t *testing.T) {
	const document = `{"permissions":{"allow":[{"tool":"Shell"}, "Shell(npm ci)", 7, "Read(*)"]}}`

	entities, warnings, err := cliEntities(cliMapFS(document))
	if err != nil {
		t.Fatalf("cliEntities() error = %v, want nil", err)
	}

	var values []string
	for _, e := range entities {
		p := e.(ir.ToolPermission)
		values = append(values, p.Tool+"|"+p.Argument)
	}
	if want := []string{"Shell|npm ci", "Read|*"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %q, want the well-formed siblings alone", values)
	}
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v, want one per faulty entry", warnings)
	}
	for i, want := range []string{"permissions.allow[0]:", "permissions.allow[2]:"} {
		if !strings.HasPrefix(warnings[i].Err.Error(), want) {
			t.Errorf("warnings[%d] = %q, want it to name %q", i, warnings[i].Err, want)
		}
	}
}

func TestParseSurfacesTheCursorCLIPermissions(t *testing.T) {
	entities, warnings, err := New().Parse(cliMapFS(`{"permissions":{"allow":["Shell(npm ci)"]}}`))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() = %+v, want one entity", entities)
	}
	p, ok := entities[0].(ir.ToolPermission)
	if !ok {
		t.Fatalf("entity %+v is %T, want ir.ToolPermission", entities[0], entities[0])
	}
	if p.Location.File != cliFileName {
		t.Errorf("Location.File = %q, want %q", p.Location.File, cliFileName)
	}
}

// A deny entry withholds the allow entry that decomposes to the same tool
// and argument, and the allow entries beside it keep their own indexed keys.
func TestCLIEntitiesWithholdAnAllowEntryADenyEntryRepeats(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     []string
	}{
		{
			name:     "repeated entry is withheld",
			document: `{"permissions":{"allow":["Shell(git *)","Shell(git push *)"],"deny":["Shell(git push *)"]}}`,
			want:     []string{"permissions.allow[0]|Shell|git *"},
		},
		{
			name:     "narrower deny leaves the wider allow",
			document: `{"permissions":{"allow":["Shell(git *)"],"deny":["Shell(git push *)"]}}`,
			want:     []string{"permissions.allow[0]|Shell|git *"},
		},
		{
			name:     "a deny extending the allow argument leaves it standing",
			document: `{"permissions":{"allow":["Shell(git push)"],"deny":["Shell(git push --force)"]}}`,
			want:     []string{"permissions.allow[0]|Shell|git push"},
		},
		{
			name:     "an allow extending the deny argument still stands",
			document: `{"permissions":{"allow":["Shell(git push --force)"],"deny":["Shell(git push)"]}}`,
			want:     []string{"permissions.allow[0]|Shell|git push --force"},
		},
		{
			name:     "same argument under another tool is left",
			document: `{"permissions":{"allow":["Read(.env*)"],"deny":["Write(.env*)"]}}`,
			want:     []string{"permissions.allow[0]|Read|.env*"},
		},
		{
			name:     "a withheld entry does not renumber its siblings",
			document: `{"permissions":{"allow":["Shell(rm)","Read(*)","Mcp(x:y)"],"deny":["Read(*)"]}}`,
			want:     []string{"permissions.allow[0]|Shell|rm", "permissions.allow[2]|Mcp|x:y"},
		},
		{
			name:     "an empty argument list matches the tool spelled bare",
			document: `{"permissions":{"allow":["Shell"],"deny":["Shell()"]}}`,
			want:     nil,
		},
		{
			name:     "every allow entry repeated leaves nothing",
			document: `{"permissions":{"allow":["Shell(rm)","Read(.env*)"],"deny":["Read(.env*)","Shell(rm)"]}}`,
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, e := range cliEntitiesOf(t, cliMapFS(tt.document)) {
				p := e.(ir.ToolPermission)
				got = append(got, p.Location.Key+"|"+p.Tool+"|"+p.Argument)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("permissions = %q, want %q", got, tt.want)
			}
		})
	}
}

// A deny list the reader cannot decompose warns rather than withholding in
// silence, and the entries beside a faulty one still withhold.
func TestCLIEntitiesWarnOnAMalformedDenyList(t *testing.T) {
	tests := []struct {
		name     string
		document string
		wantMsgs []string
		want     []string
	}{
		{
			name:     "object deny list",
			document: `{"permissions":{"allow":["Shell(rm)"],"deny":{"Shell":"rm"}}}`,
			wantMsgs: []string{"permissions.deny: expected an array of permissions, found an object"},
			want:     []string{"Shell|rm"},
		},
		{
			name:     "string deny list",
			document: `{"permissions":{"allow":["Shell(rm)"],"deny":"Shell(rm)"}}`,
			wantMsgs: []string{"permissions.deny: expected an array of permissions, found a string"},
			want:     []string{"Shell|rm"},
		},
		{
			name:     "one faulty deny entry leaves its siblings denying",
			document: `{"permissions":{"allow":["Shell(rm)","Read(*)"],"deny":[7,"Shell(rm)"]}}`,
			wantMsgs: []string{"permissions.deny[0]: expected a permission string, found a non-object value"},
			want:     []string{"Read|*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := cliEntities(cliMapFS(tt.document))
			if err != nil {
				t.Fatalf("cliEntities() error = %v, want nil", err)
			}

			var got []string
			for _, e := range entities {
				p := e.(ir.ToolPermission)
				got = append(got, p.Tool+"|"+p.Argument)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("permissions = %q, want %q", got, tt.want)
			}

			var msgs []string
			for _, w := range warnings {
				if w.File != cliFileName {
					t.Errorf("warning %v names %q, want %q", w.Err, w.File, cliFileName)
				}
				msgs = append(msgs, w.Err.Error())
			}
			if !reflect.DeepEqual(msgs, tt.wantMsgs) {
				t.Fatalf("warnings = %q, want %q", msgs, tt.wantMsgs)
			}
		})
	}
}
