package ir

import "testing"

// wantLocation extracts the Location field from a concrete entity via a
// type switch (not reflection), so this test cross-checks LocationOf's
// reflection-based result against a wholly independent access path.
func wantLocation(t *testing.T, e Entity) Location {
	t.Helper()
	switch v := e.(type) {
	case Hook:
		return v.Location
	case MCPServer:
		return v.Location
	case EnvVar:
		return v.Location
	case Subagent:
		return v.Location
	case Skill:
		return v.Location
	case Plugin:
		return v.Location
	case Sandbox:
		return v.Location
	case StatusLine:
		return v.Location
	case CredentialHelper:
		return v.Location
	case PermissionMode:
		return v.Location
	case MCPApproval:
		return v.Location
	case BundledPayload:
		return v.Location
	case InlineShell:
		return v.Location
	case PluginExecutable:
		return v.Location
	case Provisioner:
		return v.Location
	case NetworkPolicy:
		return v.Location
	case ToolPermission:
		return v.Location
	case InstructionText:
		return v.Location
	case LSPServer:
		return v.Location
	default:
		t.Fatalf("wantLocation: unhandled entity type %T", e)
		return Location{}
	}
}

// A Location must survive the round trip out of LocationOf for each entity
// canonicalEntities builds, non-zero and exactly as declared.
func TestLocationOfAllKinds(t *testing.T) {
	entities := canonicalEntities()

	seenKinds := map[string]bool{
		KindHook:             false,
		KindMCPServer:        false,
		KindLSPServer:        false,
		KindEnvVar:           false,
		KindSubagent:         false,
		KindSkill:            false,
		KindPlugin:           false,
		KindSandbox:          false,
		KindStatusLine:       false,
		KindCredentialHelper: false,
		KindPermissionMode:   false,
		KindMCPApproval:      false,
		KindBundledPayload:   false,
		KindInlineShell:      false,
		KindPluginExecutable: false,
		KindProvisioner:      false,
		KindNetworkPolicy:    false,
		KindToolPermission:   false,
		KindInstructionText:  false,
	}

	for _, e := range entities {
		kind := e.Kind()
		if _, known := seenKinds[kind]; !known {
			t.Fatalf("canonicalEntities contains unknown Kind %q", kind)
		}
		seenKinds[kind] = true

		want := wantLocation(t, e)
		if want == (Location{}) {
			t.Fatalf("canonicalEntities entry for Kind %q has zero Location; fixture must be non-zero", kind)
		}

		got := LocationOf(e)
		if got != want {
			t.Errorf("LocationOf(%T) = %+v, want %+v", e, got, want)
		}
	}

	for kind, seen := range seenKinds {
		if !seen {
			t.Errorf("Kind %q not covered by canonicalEntities", kind)
		}
	}
}

type nonStructEntity string

func (nonStructEntity) Kind() string     { return "nonStruct" }
func (nonStructEntity) Identity() string { return "" }

type fieldlessEntity struct{}

func (fieldlessEntity) Kind() string     { return "fieldless" }
func (fieldlessEntity) Identity() string { return "" }

// Degenerate input, non-struct or field-less, must yield the zero Location
// rather than panic.
func TestLocationOfNeverPanics(t *testing.T) {
	tests := []struct {
		name   string
		entity Entity
	}{
		{"nil entity", nil},
		{"non-struct entity", nonStructEntity("x")},
		{"field-less struct entity", fieldlessEntity{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("LocationOf panicked: %v", r)
				}
			}()
			if got := LocationOf(tt.entity); got != (Location{}) {
				t.Errorf("LocationOf(%v) = %+v, want zero Location", tt.entity, got)
			}
		})
	}
}
