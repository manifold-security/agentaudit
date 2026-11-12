package claude

import (
	"fmt"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const (
	settingsFile      = ".claude/settings.json"
	localSettingsFile = ".claude/settings.local.json"
)

func allowPermissionAt(file string, i int, tool, argument string) ir.Entity {
	return ir.ToolPermission{
		Tool:     tool,
		Argument: argument,
		Location: ir.Location{File: file, Key: fmt.Sprintf("permissions.allow[%d]", i)},
	}
}

func allowPermission(i int, tool, argument string) ir.Entity {
	return allowPermissionAt(settingsFile, i, tool, argument)
}

// With no deny or ask entry, every string allow entry becomes one permission,
// whatever tool it names, and an entry the Tool(spec) shape does not fit stays
// whole in Tool.
func TestParse_AllowYieldsAToolPermissionPerEntry(t *testing.T) {
	fsys := mapFS("settings.json", `{"permissions": {"allow": [
		"Bash",
		"Bash(npm run test:*)",
		"Bash(git status)",
		"WebFetch(domain:example.com)",
		"mcp__github__create_issue",
		"Bash(rm",
		"(ls)"
	]}}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	want := []ir.Entity{
		allowPermission(0, "Bash", ""),
		allowPermission(1, "Bash", "npm run test:*"),
		allowPermission(2, "Bash", "git status"),
		allowPermission(3, "WebFetch", "domain:example.com"),
		allowPermission(4, "mcp__github__create_issue", ""),
		allowPermission(5, "Bash(rm", ""),
		allowPermission(6, "(ls)", ""),
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities = %+v, want %+v", entities, want)
	}
}

func TestParse_AllowEntryWithAStarArgumentIsTheBareTool(t *testing.T) {
	fsys := mapFS("settings.json", `{"permissions": {"allow": ["Bash(*)", "PowerShell(*)"]}}`)

	entities, err := parseEntities(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	want := []ir.Entity{allowPermission(0, "Bash", ""), allowPermission(1, "PowerShell", "")}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("entities = %+v, want %+v", entities, want)
	}
}

func warningTexts(warnings []adapter.Warning) []string {
	var texts []string
	for _, w := range warnings {
		texts = append(texts, w.File+": "+w.Err.Error())
	}
	return texts
}

// A non-string element costs only its own entry: siblings and the rest of the
// file still report, and each loss is named.
func TestParse_AllowDegradesPerEntry(t *testing.T) {
	fsys := mapFS("settings.json", `{
		"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.sh"}]}]},
		"permissions": {"allow": ["Bash(make)", 7, null, {"tool": "Bash"}, "Bash(npm ci)"]}
	}`)

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	want := []ir.Entity{
		ir.Hook{
			Event:    "PreToolUse",
			Matcher:  "Bash",
			Command:  "audit.sh",
			Location: ir.Location{File: settingsFile, Key: "hooks.PreToolUse[0].hooks[0]"},
		},
		allowPermission(0, "Bash", "make"),
		allowPermission(4, "Bash", "npm ci"),
	}
	if !reflect.DeepEqual(entities, want) {
		t.Errorf("entities = %+v, want %+v", entities, want)
	}

	wantWarnings := []string{
		settingsFile + ": permissions.allow[1]: expected a permission rule string, found a non-object value",
		settingsFile + ": permissions.allow[2]: expected a permission rule string, found nothing",
		settingsFile + ": permissions.allow[3]: expected a permission rule string, found an object",
	}
	if got := warningTexts(warnings); !reflect.DeepEqual(got, wantWarnings) {
		t.Errorf("warnings = %q, want %q", got, wantWarnings)
	}
}

// An allow value that is not an array costs that list alone: one warning
// names its shape and the hook beside it still reports. A null value reads as
// absent and warns nothing.
func TestParse_AllowThatIsNotAnArrayWarnsAlone(t *testing.T) {
	tests := []struct {
		name  string
		allow string
		want  []string
	}{
		{"string", `"Bash"`, []string{"permissions.allow: expected an array of permission rules, found a string"}},
		{"object", `{}`, []string{"permissions.allow: expected an array of permission rules, found an object"}},
		{"number", `1`, []string{"permissions.allow: expected an array of permission rules, found a non-object value"}},
		{"null", `null`, nil},
		{"absent", ``, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions := `{}`
			if tt.allow != "" {
				permissions = `{"allow": ` + tt.allow + `}`
			}
			fsys := mapFS("settings.json", `{
				"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.sh"}]}]},
				"permissions": `+permissions+`
			}`)

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("entities = %+v, want only the hook", entities)
			}
			if _, ok := entities[0].(ir.Hook); !ok {
				t.Fatalf("entities[0] type = %T, want ir.Hook", entities[0])
			}

			var wantWarnings []string
			for _, w := range tt.want {
				wantWarnings = append(wantWarnings, settingsFile+": "+w)
			}
			if got := warningTexts(warnings); !reflect.DeepEqual(got, wantWarnings) {
				t.Errorf("warnings = %q, want %q", got, wantWarnings)
			}
		})
	}
}

func permissionsBody(allow, deny, ask string) string {
	body := `{"permissions": {"allow": ` + allow
	if deny != "" {
		body += `, "deny": ` + deny
	}
	if ask != "" {
		body += `, "ask": ` + ask
	}
	return body + `}}`
}

// Claude Code checks deny and ask before allow.
func TestParse_AllowEntryADenyOrAskEntryCoversIsWithheld(t *testing.T) {
	tests := []struct {
		name  string
		allow string
		deny  string
		ask   string
		want  []ir.Entity
	}{
		{"deny of the bare tool", `["Bash(touch ./m)"]`, `["Bash"]`, ``, nil},
		{"deny of the tool with a star", `["Bash(touch ./m)"]`, `["Bash(*)"]`, ``, nil},
		{"ask of the bare tool", `["Bash(touch ./m)"]`, ``, `["Bash"]`, nil},
		{"deny identical to the entry", `["Bash(touch ./m)"]`, `["Bash(touch ./m)"]`, ``, nil},
		{"ask identical to the entry", `["Bash(touch ./m)"]`, ``, `["Bash(touch ./m)"]`, nil},
		{"deny of the space-star spelling of the entry's prefix", `["Bash(curl:*)"]`, `["Bash(curl *)"]`, ``, nil},
		{"ask of the colon-star spelling of the entry's prefix", `["Bash(curl *)"]`, ``, `["Bash(curl:*)"]`, nil},
		{"PowerShell entry beside a bare deny", `["PowerShell(Get-ChildItem *)"]`, `["PowerShell"]`, ``, nil},
		{"PowerShell entry beside a deny of the tool with a star", `["PowerShell(Get-ChildItem *)"]`, `["PowerShell(*)"]`, ``, nil},
		{"only the entry that an identical deny names", `["Bash(a)", "Bash(b)"]`, `["Bash(a)"]`, ``, []ir.Entity{allowPermission(1, "Bash", "b")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapFS("settings.json", permissionsBody(tt.allow, tt.deny, tt.ask))

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Errorf("entities = %+v, want %+v", entities, tt.want)
			}
			if len(warnings) != 0 {
				t.Errorf("warnings = %q, want none", warningTexts(warnings))
			}
		})
	}
}

func TestParse_AllowEntryStaysBesideADenyOrAskEntryThatDoesNotMatchIt(t *testing.T) {
	tests := []struct {
		name  string
		allow string
		deny  string
		ask   string
		want  []ir.Entity
	}{
		{"deny of the space-star spelling before more text", `["Bash(curl:* -s)"]`, `["Bash(curl * -s)"]`, ``, []ir.Entity{allowPermission(0, "Bash", "curl:* -s")}},
		{"deny of a longer prefix", `["Bash(curl:*)"]`, `["Bash(curl https:*)"]`, ``, []ir.Entity{allowPermission(0, "Bash", "curl:*")}},
		{"ask of a narrower entry", `["Bash"]`, ``, `["Bash(rm:*)"]`, []ir.Entity{allowPermission(0, "Bash", "")}},
		{"deny of another shell tool", `["Bash(make)"]`, `["PowerShell"]`, ``, []ir.Entity{allowPermission(0, "Bash", "make")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapFS("settings.json", permissionsBody(tt.allow, tt.deny, tt.ask))

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Errorf("entities = %+v, want %+v", entities, tt.want)
			}
			if len(warnings) != 0 {
				t.Errorf("warnings = %q, want none", warningTexts(warnings))
			}
		})
	}
}

// A deny or ask list that cannot be read as rule strings warns, and the strings
// beside a bad element still count.
func TestParse_MalformedDenyOrAskListWarns(t *testing.T) {
	tests := []struct {
		name string
		deny string
		ask  string
		want []ir.Entity
		warn string
	}{
		{"deny that is a string", `"Bash"`, ``, []ir.Entity{allowPermission(0, "Bash", "make")}, "permissions.deny: expected an array of permission rules, found a string"},
		{"ask with a number beside a string", ``, `["Bash", 7]`, nil, "permissions.ask[1]: expected a permission rule string, found a non-object value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := mapFS("settings.json", permissionsBody(`["Bash(make)"]`, tt.deny, tt.ask))

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Errorf("entities = %+v, want %+v", entities, tt.want)
			}
			if got, want := warningTexts(warnings), []string{settingsFile + ": " + tt.warn}; !reflect.DeepEqual(got, want) {
				t.Errorf("warnings = %q, want %q", got, want)
			}
		})
	}
}

func TestParse_DenyOrAskInOneSettingsFileWithholdsNothingInTheOther(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []ir.Entity
	}{
		{"deny in the first file", map[string]string{
			"settings.json":       `{"permissions": {"deny": ["Bash"]}}`,
			"settings.local.json": `{"permissions": {"allow": ["Bash(make)"]}}`,
		}, []ir.Entity{allowPermissionAt(localSettingsFile, 0, "Bash", "make")}},
		{"deny in the second file", map[string]string{
			"settings.json":       `{"permissions": {"allow": ["Bash(make)"]}}`,
			"settings.local.json": `{"permissions": {"deny": ["Bash"]}}`,
		}, []ir.Entity{allowPermissionAt(settingsFile, 0, "Bash", "make")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for name, data := range tt.files {
				fsys[".claude/"+name] = &fstest.MapFile{Data: []byte(data)}
			}

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Errorf("entities = %+v, want %+v", entities, tt.want)
			}
			if len(warnings) != 0 {
				t.Errorf("warnings = %q, want none", warningTexts(warnings))
			}
		})
	}
}
