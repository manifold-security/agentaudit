package codex

import (
	"reflect"
	"slices"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestParseCarriesTheDefaultPermissionProfileVerbatim(t *testing.T) {
	for _, profile := range []string{":read-only", ":workspace", ":danger-full-access", "project-edit"} {
		t.Run(profile, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS("default_permissions = \"" + profile + "\"\n"))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			want := []ir.Entity{ir.PermissionMode{
				Mode:     profile,
				Source:   "default_permissions",
				Location: ir.Location{File: configFileName, Key: "default_permissions"},
			}}
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
			}
		})
	}
}

// A profile inherits its base by name, and that name carries the same grant
// the default key would, so it reaches the report under its own provenance.
func TestParseCarriesTheProfileBaseItExtends(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.release]\nextends = \":danger-full-access\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.PermissionMode{
		Mode:     ":danger-full-access",
		Source:   "extends",
		Location: ir.Location{File: configFileName, Key: "permissions.release.extends"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A root the profile withholds declares nothing.
func TestParseSurfacesAProfileWorkspaceRootOnlyWhereItIsGranted(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.workspace_roots]\n\"~/code/app\" = true\n\"~/archive\" = false\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.Sandbox{
		Path:     "~/code/app",
		Access:   "workspace_root",
		Location: ir.Location{File: configFileName, Key: "permissions.p.workspace_roots.~/code/app"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The alias naming common runtime paths is withheld.
func TestParseLeavesTheBaselineFilesystemAliasUnreported(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.filesystem]\n\":minimal\" = \"read\"\n\":root\" = \"write\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	var paths []string
	for _, e := range entities {
		if s, ok := e.(ir.Sandbox); ok {
			paths = append(paths, s.Path)
		}
	}
	if !slices.Equal(paths, []string{":root"}) {
		t.Errorf("paths = %v, want only the root alias", paths)
	}
}

// Each filesystem entry keeps the level the profile spelled.
func TestParseCarriesEachFilesystemGrantAtItsDeclaredLevel(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.filesystem]\n\"~/.aws/credentials\" = \"read\"\n\"~/src\" = \"write\"\n\"**/*.env\" = \"deny\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{
		ir.Sandbox{Path: "~/.aws/credentials", Access: "read", Location: ir.Location{File: configFileName, Key: "permissions.p.filesystem.~/.aws/credentials"}},
		ir.Sandbox{Path: "~/src", Access: "write", Location: ir.Location{File: configFileName, Key: "permissions.p.filesystem.~/src"}},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The workspace-scoped table holds grants of its own, so its entries reach
// the report under the table that scoped them.
func TestParseReadsTheWorkspaceScopedFilesystemTable(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.filesystem.\":workspace_roots\"]\n\".\" = \"write\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.Sandbox{
		Path:     ".",
		Access:   "write",
		Location: ir.Location{File: configFileName, Key: "permissions.p.filesystem.:workspace_roots.."},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A scan bound reaches no finding, and the granted sibling proves the table
// the bound sits in is read.
func TestParseLeavesTheGlobScanBoundUnreported(t *testing.T) {
	const bound = "glob_scan_max_depth = 4\n"

	entities, warnings, err := New().Parse(configFS("[permissions.p.filesystem]\n" + bound))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none: a scan bound declares no capability", entities)
	}

	entities, warnings, err = New().Parse(configFS("[permissions.p.filesystem]\n" + bound + "\"~/src\" = \"write\"\n"))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.Sandbox{
		Path:     "~/src",
		Access:   "write",
		Location: ir.Location{File: configFileName, Key: "permissions.p.filesystem.~/src"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v: the table this reads is the same one", entities, want)
	}
}

// Egress carries the key that grants it, and withholding it declares no
// capability.
func TestParseSurfacesProfileEgressOnlyWhereItIsEnabled(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []ir.Entity
	}{
		{
			name: "enabled",
			body: "[permissions.p.network]\nenabled = true\n",
			want: []ir.Entity{ir.NetworkPolicy{
				Default:  "enabled",
				Location: ir.Location{File: configFileName, Key: "permissions.p.network.enabled"},
			}},
		},
		{
			name: "withheld",
			body: "[permissions.p.network]\nenabled = false\n",
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

// Only the allowed patterns reach the report.
func TestParseSurfacesOnlyTheDomainsAProfileAllows(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.network.domains]\n\"api.example.com\" = \"allow\"\n\"tracking.example.com\" = \"deny\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{ir.NetworkPolicy{
		Pattern:  "api.example.com",
		Location: ir.Location{File: configFileName, Key: "permissions.p.network.domains.api.example.com"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// Only the sockets a profile admits reach the report, and the withheld one
// sits beside an admitted one.
func TestParseSurfacesOnlyTheUnixSocketsAProfileAdmits(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "verdict",
			body: "[permissions.p.network.unix_sockets]\n\"/run/docker.sock\" = \"allow\"\n\"/run/gpg-agent\" = \"deny\"\n",
			want: []string{"/run/docker.sock"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS(tt.body))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			var got []string
			for _, e := range entities {
				s, isSandbox := e.(ir.Sandbox)
				if !isSandbox {
					t.Fatalf("entity %+v is not an ir.Sandbox", e)
				}
				got = append(got, s.SocketPath)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse() sockets = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Two profiles and their keys reach the report in one order whatever order
// the decoder's tables hand them over in.
func TestParseOrdersProfileGrantsDeterministically(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.zeta.filesystem]\n\"~/z\" = \"write\"\n\"/etc\" = \"read\"\n" +
			"[permissions.alpha.filesystem]\n\"~/a\" = \"write\"\n\"/opt\" = \"read\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	var got []string
	for _, e := range entities {
		got = append(got, ir.LocationOf(e).Key)
	}
	want := []string{
		"permissions.alpha.filesystem./opt",
		"permissions.alpha.filesystem.~/a",
		"permissions.zeta.filesystem./etc",
		"permissions.zeta.filesystem.~/z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() keys = %+v, want %+v", got, want)
	}
}

func TestParseDegradesAWrongTypedProfileKeyWithoutItsSiblings(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"default_permissions = 3\n" +
			"[permissions.p]\nworkspace_roots = \"~/code\"\nfilesystem = 7\n" +
			"[permissions.p.network]\nenabled = \"yes\"\ndomains = \"api.example.com\"\n" +
			"[permissions.q.filesystem]\n\"~/src\" = \"write\"\n",
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
		"default_permissions: expected a string, found a value of another type",
		"permissions.p.workspace_roots: expected a table, found a string",
		"permissions.p.filesystem: expected a table, found a value of another type",
		"permissions.p.network.enabled: expected a boolean, found a string",
		"permissions.p.network.domains: expected a table, found a string",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %+v, want %+v", got, want)
	}

	wantEntities := []ir.Entity{ir.Sandbox{
		Path:     "~/src",
		Access:   "write",
		Location: ir.Location{File: configFileName, Key: "permissions.q.filesystem.~/src"},
	}}
	if !reflect.DeepEqual(entities, wantEntities) {
		t.Fatalf("Parse() entities = %+v, want the well-formed sibling %+v", entities, wantEntities)
	}
}

// A profile that is not a table degrades alone, and the sibling profile still
// reaches the report.
func TestParseDegradesAProfileThatIsNotATableWithoutItsSiblings(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions]\np = \"inherited\"\n[permissions.q.filesystem]\n\"~/src\" = \"write\"\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warnings)
	}
	if got, want := warnings[0].Err.Error(), "permissions.p: expected a table, found a string"; got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}
	want := []ir.Entity{ir.Sandbox{
		Path:     "~/src",
		Access:   "write",
		Location: ir.Location{File: configFileName, Key: "permissions.q.filesystem.~/src"},
	}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A grant whose value is not the spelling its table accepts degrades rather
// than reaching the report under a level nobody declared.
func TestParseDegradesAWrongTypedGrantValue(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[permissions.p.workspace_roots]\n\"~/code\" = \"yes\"\n" +
			"[permissions.p.filesystem]\n\"~/src\" = 7\n" +
			"[permissions.p.network.domains]\n\"api.example.com\" = 7\n" +
			"[permissions.p.network.unix_sockets]\n\"/run/docker.sock\" = true\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("Parse() entities = %+v, want none", entities)
	}

	var got []string
	for _, w := range warnings {
		got = append(got, w.Err.Error())
	}
	want := []string{
		"permissions.p.workspace_roots.~/code: expected a boolean, found a string",
		"permissions.p.filesystem.~/src: expected a string, found a value of another type",
		"permissions.p.network.domains.api.example.com: expected a string, found a value of another type",
		"permissions.p.network.unix_sockets./run/docker.sock: expected a string, found a boolean",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %+v, want %+v", got, want)
	}
}

// The fallback keys on the tokens the vendor documents, so an empty or
// unknown sandbox_mode leaves the profile live.
func TestParseWithholdsAProfileShadowedByASandboxMode(t *testing.T) {
	const selects = "default_permissions = \":danger-full-access\"\n"
	const grants = "[permissions.release.filesystem]\n\"~/src\" = \"write\"\n"

	selected := ir.PermissionMode{
		Mode:     ":danger-full-access",
		Source:   "default_permissions",
		Location: ir.Location{File: configFileName, Key: "default_permissions"},
	}
	granted := ir.Sandbox{
		Path:     "~/src",
		Access:   "write",
		Location: ir.Location{File: configFileName, Key: "permissions.release.filesystem.~/src"},
	}

	type scenario struct {
		name string
		body string
		want []ir.Entity
	}

	tests := []scenario{
		{
			name: "the profile alone",
			body: selects + grants,
			want: []ir.Entity{selected, granted},
		},
		{
			name: "beside a sandbox_mode holding no mode",
			body: "sandbox_mode = \"\"\n" + selects + grants,
			want: []ir.Entity{selected, granted},
		},
		{
			name: "beside a sandbox_mode Codex does not document",
			body: "sandbox_mode = \"enforcing\"\n" + selects + grants,
			want: []ir.Entity{
				ir.Sandbox{
					Mode:     "enforcing",
					Location: ir.Location{File: configFileName, Key: "sandbox_mode"},
				},
				selected,
				granted,
			},
		},
		{
			name: "beside a sandbox_workspace_write table",
			body: selects + "[sandbox_workspace_write]\nnetwork_access = true\n" + grants,
			want: []ir.Entity{
				ir.NetworkPolicy{
					Default:  "true",
					Location: ir.Location{File: configFileName, Key: "sandbox_workspace_write.network_access"},
				},
				selected,
				granted,
			},
		},
	}

	for _, mode := range sandboxModes {
		tests = append(tests, scenario{
			name: "beside a " + mode + " sandbox_mode",
			body: "sandbox_mode = \"" + mode + "\"\n" + selects + grants,
			want: []ir.Entity{ir.Sandbox{
				Mode:     mode,
				Location: ir.Location{File: configFileName, Key: "sandbox_mode"},
			}},
		})
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

// A profile key that did not decode is still named where a sandbox_mode
// leaves the block unapplied.
func TestParseWarnsAboutAShadowedProfileKeyItCouldNotRead(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"sandbox_mode = \"read-only\"\n[permissions.p]\nfilesystem = 7\n",
	))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}

	var got []string
	for _, w := range warnings {
		got = append(got, w.Err.Error())
	}
	want := []string{"permissions.p.filesystem: expected a table, found a value of another type"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %+v, want %+v", got, want)
	}

	wantEntities := []ir.Entity{ir.Sandbox{
		Mode:     "read-only",
		Location: ir.Location{File: configFileName, Key: "sandbox_mode"},
	}}
	if !reflect.DeepEqual(entities, wantEntities) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, wantEntities)
	}
}
