package claude

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const settingsFile = ".claude/settings.json"

func allowPermission(i int, tool, argument string) ir.Entity {
	return ir.ToolPermission{
		Tool:     tool,
		Argument: argument,
		Location: ir.Location{File: settingsFile, Key: fmt.Sprintf("permissions.allow[%d]", i)},
	}
}

// Every string allow entry becomes one permission, whatever tool it names, and
// an entry the Tool(spec) shape does not fit stays whole in Tool.
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
