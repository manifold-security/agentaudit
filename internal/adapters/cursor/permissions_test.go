package cursor

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func permissionsMapFS(data string) fstest.MapFS {
	return fstest.MapFS{permissionsFileName: &fstest.MapFile{Data: []byte(data)}}
}

func permissionEntitiesOf(t *testing.T, fsys fstest.MapFS) []ir.Entity {
	t.Helper()
	entities, warnings := permissionEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("permissionEntities() warnings = %+v, want none", warnings)
	}
	return entities
}

// An allowlist entry arrives in the permission-string vocabulary the CLI
// configuration already uses, so one reader reads both files.
func TestPermissionEntitiesRewriteBothAllowlistsIntoPermissionStrings(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     []string
	}{
		{
			name:     "terminal commands",
			document: `{"terminalAllowlist":["git","npm run build"]}`,
			want:     []string{"Shell|git|terminalAllowlist[0]", "Shell|npm run build|terminalAllowlist[1]"},
		},
		{
			name:     "mcp server and tool",
			document: `{"mcpAllowlist":["github:create_issue"]}`,
			want:     []string{"Mcp|github:create_issue|mcpAllowlist[0]"},
		},
		{
			name:     "an entry naming no tool is carried whole",
			document: `{"mcpAllowlist":["github"]}`,
			want:     []string{"Mcp|github|mcpAllowlist[0]"},
		},
		{
			name:     "both lists",
			document: `{"terminalAllowlist":["git"],"mcpAllowlist":["s:t"]}`,
			want:     []string{"Shell|git|terminalAllowlist[0]", "Mcp|s:t|mcpAllowlist[0]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, e := range permissionEntitiesOf(t, permissionsMapFS(tt.document)) {
				p, ok := e.(ir.ToolPermission)
				if !ok {
					t.Fatalf("entity %+v is %T, want ir.ToolPermission", e, e)
				}
				if p.Location.File != permissionsFileName {
					t.Errorf("Location.File = %q, want %q", p.Location.File, permissionsFileName)
				}
				got = append(got, p.Tool+"|"+p.Argument+"|"+p.Location.Key)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("permissions = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPermissionEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings := permissionEntities(fstest.MapFS{})
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("permissionEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

func TestPermissionEntitiesStaySilentOnADocumentThatAllowsNothing(t *testing.T) {
	documents := map[string]string{
		"empty lists":    `{"terminalAllowlist":[],"mcpAllowlist":[]}`,
		"unread key":     `{"version":1}`,
		"empty document": `{}`,
	}

	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			entities, warnings := permissionEntities(permissionsMapFS(document))
			if len(entities) != 0 || len(warnings) != 0 {
				t.Fatalf("permissionEntities() = (%+v, %+v), want neither", entities, warnings)
			}
		})
	}
}

// A wrong-typed key takes only itself down, and a wrong-typed element only
// its own index.
func TestPermissionEntitiesDegradePerKeyAndPerElement(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		want        []string
		wantWarning string
	}{
		{
			name:        "one key is not an array",
			document:    `{"terminalAllowlist":"git","mcpAllowlist":["s:t"]}`,
			want:        []string{"Mcp|s:t"},
			wantWarning: "terminalAllowlist:",
		},
		{
			name:        "one element is not a string",
			document:    `{"terminalAllowlist":["git",7,"npm ci"]}`,
			want:        []string{"Shell|git", "Shell|npm ci"},
			wantWarning: "terminalAllowlist[1]:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := permissionEntities(permissionsMapFS(tt.document))

			var got []string
			for _, e := range entities {
				p, ok := e.(ir.ToolPermission)
				if !ok {
					t.Fatalf("entity %+v is %T, want ir.ToolPermission", e, e)
				}
				got = append(got, p.Tool+"|"+p.Argument)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("permissions = %q, want %q", got, tt.want)
			}

			if len(warnings) != 1 || warnings[0].File != permissionsFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, permissionsFileName)
			}
			if !strings.HasPrefix(warnings[0].Err.Error(), tt.wantWarning) {
				t.Errorf("warning = %q, want it to open with %q", warnings[0].Err, tt.wantWarning)
			}
		})
	}
}

// Cursor reads this file with a JSONC parser, so a comment in it is the
// user's file being valid and this scanner's decoder being strict. The
// warning has to say which of the two failed. Cursor's parser accepts the
// line opener and the block opener alike.
func TestPermissionEntitiesBlameTheScannerWhenADecodeStopsAtACommentOpener(t *testing.T) {
	documents := map[string]string{
		"line opener":  "{\n  // the deploy box only\n  \"terminalAllowlist\": [\"git\"]\n}\n",
		"block opener": "{\n  /* the deploy box only */\n  \"terminalAllowlist\": [\"git\"]\n}\n",
	}

	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			entities, warnings := permissionEntities(permissionsMapFS(document))
			if len(entities) != 0 {
				t.Fatalf("entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != permissionsFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, permissionsFileName)
			}

			got := warnings[0].Err.Error()
			for _, want := range []string{"strict JSON", "JSONC", "nothing in the file was read"} {
				if !strings.Contains(got, want) {
					t.Errorf("warning = %q, want it to mention %q", got, want)
				}
			}
			if strings.Contains(got, "invalid character") {
				t.Errorf("warning = %q, want the decoder's own message replaced", got)
			}
		})
	}
}

// The scanner-limitation wording is opt-in per file. cli.json is one Cursor
// decodes strictly itself, so the same body there is the user's own syntax
// error and keeps the decoder's message.
func TestCLIEntitiesKeepTheDecoderMessageOnTheSameCommentedBody(t *testing.T) {
	const document = "{\n  // the deploy box only\n  \"permissions\": {\"allow\": [\"Shell(git)\"]}\n}\n"

	_, warnings, err := cliEntities(cliMapFS(document))
	if err != nil {
		t.Fatalf("cliEntities() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	got := warnings[0].Err.Error()
	if !strings.Contains(got, "invalid character") {
		t.Errorf("warning = %q, want the decoder's own message", got)
	}
	if strings.Contains(got, "JSONC") {
		t.Errorf("warning = %q, want no JSONC claim for a file Cursor decodes strictly", got)
	}
}

// The JSONC wording is keyed to a comment opener, not to a slash on its
// own. A slash no second comment byte follows is the user's own syntax
// error in permissions.json too, inside a string value as much as outside
// one, and the decoder's own message stands.
func TestPermissionEntitiesKeepTheDecoderMessageAwayFromACommentOpener(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		wantMessage string
	}{
		{
			name:        "a fault at no slash at all",
			document:    `{"terminalAllowlist": ["git",}`,
			wantMessage: "invalid character '}'",
		},
		{
			name:        "a division typo",
			document:    `{"a": 1/2}`,
			wantMessage: "invalid character '/' after object key:value pair",
		},
		{
			name:        "a slash inside an unterminated string",
			document:    `{"a":"x/`,
			wantMessage: "unexpected end of JSON input",
		},
		{
			name:        "a slash pair inside a string, then a trailing slash",
			document:    `{"a":"//not a comment"} /`,
			wantMessage: "invalid character '/' after top-level value",
		},
		{
			name:        "a slash trailing the document",
			document:    `{"a":1}/`,
			wantMessage: "invalid character '/' after top-level value",
		},
		{
			name:        "a lone slash",
			document:    `/`,
			wantMessage: "invalid character '/' looking for beginning of value",
		},
		{
			name:        "a slash a newline follows",
			document:    "/\n",
			wantMessage: "invalid character '/' looking for beginning of value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, warnings := permissionEntities(permissionsMapFS(tt.document))
			if len(warnings) != 1 {
				t.Fatalf("warnings = %+v, want exactly one", warnings)
			}
			got := warnings[0].Err.Error()
			if !strings.Contains(got, tt.wantMessage) {
				t.Errorf("warning = %q, want the decoder's own %q", got, tt.wantMessage)
			}
			if strings.Contains(got, "JSONC") {
				t.Errorf("warning = %q, want no JSONC claim for a fault away from a comment", got)
			}
		})
	}
}

// The slash pair here sits inside a JSON string value rather than opening
// a comment, and the strict decoder reads the document whole.
func TestPermissionEntitiesReadADocumentWhoseStringHoldsASlashPair(t *testing.T) {
	const document = `{"terminalAllowlist":["curl https://example.test//api"]}`

	got := permissionEntitiesOf(t, permissionsMapFS(document))
	if len(got) != 1 {
		t.Fatalf("permissionEntities() = %+v, want one entity", got)
	}
	p, ok := got[0].(ir.ToolPermission)
	if !ok {
		t.Fatalf("entity %+v is %T, want ir.ToolPermission", got[0], got[0])
	}
	if want := "curl https://example.test//api"; p.Argument != want {
		t.Errorf("Argument = %q, want %q", p.Argument, want)
	}
}

func TestPermissionEntitiesMalformedDocumentWarnsNamingTheFile(t *testing.T) {
	entities, warnings := permissionEntities(permissionsMapFS(`["not an object"]`))
	if len(entities) != 0 {
		t.Fatalf("entities = %+v, want none", entities)
	}
	if len(warnings) != 1 || warnings[0].File != permissionsFileName {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, permissionsFileName)
	}
}

func instructionsOf(t *testing.T, entities []ir.Entity) map[string]string {
	t.Helper()
	got := map[string]string{}
	for _, e := range entities {
		i, ok := e.(ir.InstructionText)
		if !ok {
			t.Fatalf("entity %+v is %T, want ir.InstructionText", e, e)
		}
		if i.Location.File != permissionsFileName {
			t.Errorf("Location.File = %q, want %q", i.Location.File, permissionsFileName)
		}
		got[i.Setting+"@"+i.Location.Key] = i.Text
	}
	return got
}

// The instruction keys hold prose rather than a tool name, so they arrive
// as text and not as a grant.
func TestPermissionEntitiesSurfaceAutoRunInstructionsAsText(t *testing.T) {
	const document = `{"autoRun":{"allow_instructions":["release scripts are routine","tag pushes are routine"],"block_instructions":["ask before touching prod"]}}`

	got := instructionsOf(t, permissionEntitiesOf(t, permissionsMapFS(document)))
	want := map[string]string{
		"allow_instructions@autoRun.allow_instructions[0]": "release scripts are routine",
		"allow_instructions@autoRun.allow_instructions[1]": "tag pushes are routine",
		"block_instructions@autoRun.block_instructions[0]": "ask before touching prod",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instructions = %+v, want %+v", got, want)
	}
}

// Cursor tries autoReview before autoRun, so a document carrying both is
// read through autoReview alone. The one-key arms are what make the
// absence in the both-keys arm attributable to the precedence.
func TestPermissionEntitiesReadAutoReviewAheadOfAutoRun(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     map[string]string
	}{
		{
			name:     "autoRun alone",
			document: `{"autoRun":{"allow_instructions":["from autoRun"]}}`,
			want:     map[string]string{"allow_instructions@autoRun.allow_instructions[0]": "from autoRun"},
		},
		{
			name:     "autoReview alone",
			document: `{"autoReview":{"allow_instructions":["from autoReview"]}}`,
			want:     map[string]string{"allow_instructions@autoReview.allow_instructions[0]": "from autoReview"},
		},
		{
			name:     "both",
			document: `{"autoRun":{"allow_instructions":["from autoRun"]},"autoReview":{"allow_instructions":["from autoReview"]}}`,
			want:     map[string]string{"allow_instructions@autoReview.allow_instructions[0]": "from autoReview"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := instructionsOf(t, permissionEntitiesOf(t, permissionsMapFS(tt.document)))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("instructions = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A top-level name is matched whatever its casing, so a spelling chosen to
// slip past a scanner still reads. The exact-case arm is what keeps the
// folded arm from passing on a reader that ignores casing entirely.
func TestPermissionEntitiesMatchATopLevelNameWhateverItsCasing(t *testing.T) {
	tests := []struct {
		name     string
		document string
		wantKeys []string
	}{
		{
			name:     "documented casing",
			document: `{"terminalAllowlist":["git"]}`,
			wantKeys: []string{"terminalAllowlist[0]"},
		},
		{
			name:     "shouted casing",
			document: `{"TERMINALALLOWLIST":["git"]}`,
			wantKeys: []string{"TERMINALALLOWLIST[0]"},
		},
		{
			name:     "four spellings all read",
			document: `{"TerminalAllowlist":["a"],"terminalallowlist":["b"],"TERMINALALLOWLIST":["c"],"terminalAllowlist":["d"]}`,
			wantKeys: []string{"TERMINALALLOWLIST[0]", "TerminalAllowlist[0]", "terminalAllowlist[0]", "terminalallowlist[0]"},
		},
	}

	// Map iteration is randomized per range, so the repeat is what turns an
	// unordered reader from a flake into a failure.
	const repeats = 32

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range repeats {
				var got []string
				for _, e := range permissionEntitiesOf(t, permissionsMapFS(tt.document)) {
					got = append(got, ir.LocationOf(e).Key)
				}
				if !reflect.DeepEqual(got, tt.wantKeys) {
					t.Fatalf("located keys = %q, want %q", got, tt.wantKeys)
				}
			}
		})
	}
}

func TestPermissionEntitiesMatchTheAutoRunBlockWhateverItsCasing(t *testing.T) {
	got := instructionsOf(t, permissionEntitiesOf(t, permissionsMapFS(`{"AutoRun":{"allow_instructions":["shouted"]}}`)))
	want := map[string]string{"allow_instructions@AutoRun.allow_instructions[0]": "shouted"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instructions = %+v, want %+v", got, want)
	}
}

// Inside the block the two instruction names are exact property access, so
// a re-cased one is a key Cursor reads nothing from and this reports
// nothing for. The exact-case arm proves the silence is the casing's doing.
func TestPermissionEntitiesReadTheInstructionNamesCaseSensitively(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     int
	}{
		{"documented casing", `{"autoRun":{"allow_instructions":["x"]}}`, 1},
		{"re-cased", `{"autoRun":{"Allow_Instructions":["x"]}}`, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := permissionEntitiesOf(t, permissionsMapFS(tt.document))
			if len(got) != tt.want {
				t.Fatalf("permissionEntities() = %+v, want %d entities", got, tt.want)
			}
		})
	}
}

func TestPermissionEntitiesDegradeTheAutoRunBlockAlone(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		wantTexts   int
		wantWarning string
	}{
		{
			name:        "the block is not an object",
			document:    `{"autoRun":"on","terminalAllowlist":["git"]}`,
			wantTexts:   0,
			wantWarning: "autoRun:",
		},
		{
			name:        "one instruction key is not an array",
			document:    `{"autoRun":{"allow_instructions":"x","block_instructions":["kept"]}}`,
			wantTexts:   1,
			wantWarning: "autoRun.allow_instructions:",
		},
		{
			name:        "one instruction element is not a string",
			document:    `{"autoRun":{"allow_instructions":["kept",7]}}`,
			wantTexts:   1,
			wantWarning: "autoRun.allow_instructions[1]:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings := permissionEntities(permissionsMapFS(tt.document))

			texts := 0
			for _, e := range entities {
				if _, ok := e.(ir.InstructionText); ok {
					texts++
				}
			}
			if texts != tt.wantTexts {
				t.Errorf("instruction entities = %d, want %d (from %+v)", texts, tt.wantTexts, entities)
			}
			if len(warnings) != 1 || warnings[0].File != permissionsFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, permissionsFileName)
			}
			if !strings.HasPrefix(warnings[0].Err.Error(), tt.wantWarning) {
				t.Errorf("warning = %q, want it to open with %q", warnings[0].Err, tt.wantWarning)
			}
		})
	}
}
