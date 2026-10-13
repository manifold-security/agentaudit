package codex

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func configFS(body string) fstest.MapFS {
	return fstest.MapFS{configFileName: &fstest.MapFile{Data: []byte(body)}}
}

// The declared mode reaches the entity verbatim, so a rule narrows on the
// vendor's own token rather than on a classification made here.
func TestParseCarriesTheDeclaredSandboxModeVerbatim(t *testing.T) {
	for _, mode := range []string{"read-only", "workspace-write", "danger-full-access"} {
		t.Run(mode, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS("sandbox_mode = \"" + mode + "\"\n"))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			want := []ir.Entity{ir.Sandbox{
				Mode:     mode,
				Location: ir.Location{File: configFileName, Key: "sandbox_mode"},
			}}
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
			}
		})
	}
}

// Each writable root is its own entity, so a report names every granted
// location on a line of its own.
func TestParseFansOutOneEntityPerWritableRoot(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[sandbox_workspace_write]\nwritable_roots = [\"/\", \"~/.ssh\"]\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{
		ir.Sandbox{Path: "/", Access: accessReadwrite, Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.writable_roots[0]"}},
		ir.Sandbox{Path: "~/.ssh", Access: accessReadwrite, Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.writable_roots[1]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// network_access carries the value the file spells where it grants, and
// withholding it declares no capability.
func TestParseSurfacesNetworkAccessOnlyWhereItIsGranted(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []ir.Entity
	}{
		{
			name: "granted",
			body: "[sandbox_workspace_write]\nnetwork_access = true\n",
			want: []ir.Entity{ir.NetworkPolicy{
				Default:  "true",
				Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.network_access"},
			}},
		},
		{
			name: "withheld",
			body: "[sandbox_workspace_write]\nnetwork_access = false\n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS(tt.body))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, tt.want)
			}
		})
	}
}

// A wrong-typed key degrades alone, named by what the key was meant to hold,
// and its siblings still reach the report.
func TestParseDegradesAWrongTypedSandboxKeyWithoutItsSiblings(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"sandbox_mode = 3\n\n[sandbox_workspace_write]\nwritable_roots = \"/etc\"\nnetwork_access = true\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil: a malformed key degrades", err)
	}

	var got []string
	for _, w := range warnings {
		if w.File != configFileName {
			t.Errorf("warning %+v does not name %q", w, configFileName)
		}
		got = append(got, w.Err.Error())
	}
	want := []string{
		"sandbox_mode: expected a string, found a value of another type",
		"sandbox_workspace_write.writable_roots: expected an array of paths, found a string",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %+v, want %+v", got, want)
	}

	wantEntities := []ir.Entity{ir.NetworkPolicy{
		Default:  "true",
		Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.network_access"},
	}}
	if !reflect.DeepEqual(entities, wantEntities) {
		t.Fatalf("Parse() entities = %+v, want the well-formed sibling %+v", entities, wantEntities)
	}
}

// One faulty element never takes its siblings with it.
func TestParseDegradesOneWritableRootElementAlone(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[sandbox_workspace_write]\nwritable_roots = [\"/\", 3, \"~/.aws\"]\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	if got, want := warnings[0].Err.Error(), "sandbox_workspace_write.writable_roots[1]: expected a path string, found a value of another type"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}

	want := []ir.Entity{
		ir.Sandbox{Path: "/", Access: accessReadwrite, Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.writable_roots[0]"}},
		ir.Sandbox{Path: "~/.aws", Access: accessReadwrite, Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.writable_roots[2]"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The two exclusion keys narrow the writable set rather than widening it, so
// neither reaches a finding.
func TestParseLeavesTheWritableSetExclusionsUnreported(t *testing.T) {
	const exclusions = "exclude_tmpdir_env_var = true\nexclude_slash_tmp = true\n"

	entities, warnings, err := New().Parse(configFS("[sandbox_workspace_write]\n" + exclusions))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none: an exclusion declares no capability", entities)
	}

	entities, warnings, err = New().Parse(configFS("[sandbox_workspace_write]\n" + exclusions + "network_access = true\n"))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.NetworkPolicy{
		Default:  "true",
		Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.network_access"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v: the table this reads is the same one", entities, want)
	}
}
