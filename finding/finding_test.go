package finding

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestID_Deterministic(t *testing.T) {
	f := Finding{
		RuleID: "secrets.env-plaintext",
		Capability: Capability{
			Entity:     ir.EnvVar{Name: "API_KEY", Value: "secret"},
			Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"},
		},
	}

	first := f.ID()
	second := f.ID()

	if first != second {
		t.Fatalf("ID() not deterministic: %q vs %q", first, second)
	}
	if first == "" {
		t.Fatalf("ID() returned empty string")
	}
}

func TestID_IdenticalCapabilityYieldsEqualID(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{RuleID: "secrets.env-plaintext", Message: "first message", Capability: Capability{Entity: entity, Provenance: prov}}
	b := Finding{RuleID: "secrets.env-plaintext", Message: "different message", Capability: Capability{Entity: entity, Provenance: prov}}

	if a.ID() != b.ID() {
		t.Fatalf("ID() differs for identical capability: %q vs %q", a.ID(), b.ID())
	}
}

func TestID_DifferingProvenanceKeyYieldsDistinctID(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}

	a := Finding{
		RuleID:     "secrets.env-plaintext",
		Capability: Capability{Entity: entity, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}},
	}
	b := Finding{
		RuleID:     "secrets.env-plaintext",
		Capability: Capability{Entity: entity, Provenance: Provenance{File: "settings.json", Key: "env.OTHER_KEY"}},
	}

	if a.ID() == b.ID() {
		t.Fatalf("ID() equal despite differing Provenance.Key: %q", a.ID())
	}
}

func TestID_DifferingRuleIDYieldsDistinctID(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{RuleID: "secrets.env-plaintext", Capability: Capability{Entity: entity, Provenance: prov}}
	b := Finding{RuleID: "secrets.other-rule", Capability: Capability{Entity: entity, Provenance: prov}}

	if a.ID() == b.ID() {
		t.Fatalf("ID() equal despite differing RuleID: %q", a.ID())
	}
}

func TestID_DifferingEntityIdentityYieldsDistinctID(t *testing.T) {
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{
		RuleID:     "secrets.env-plaintext",
		Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "secret"}, Provenance: prov},
	}
	b := Finding{
		RuleID:     "secrets.env-plaintext",
		Capability: Capability{Entity: ir.EnvVar{Name: "OTHER_KEY", Value: "secret"}, Provenance: prov},
	}

	if a.ID() == b.ID() {
		t.Fatalf("ID() equal despite differing entity Identity(): %q", a.ID())
	}
}

// TestID_FrozenLiteralUnaffectedByAgent pins ID()'s exact output against a
// literal, byte for byte, on a Finding carrying a non-empty Agent: Agent
// must never become a stableID input.
func TestID_FrozenLiteralUnaffectedByAgent(t *testing.T) {
	f := Finding{
		RuleID: "secrets.env-plaintext",
		Agent:  "claude-code",
		Capability: Capability{
			Entity:     ir.EnvVar{Name: "API_KEY", Value: "secret"},
			Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"},
		},
	}

	const want = "secrets.env-plaintext\x1fenvVar\x1fAPI_KEY\x1fsecret\x1fsettings.json\x1fenv.API_KEY"
	if got := f.ID(); got != want {
		t.Fatalf("ID() = %q, want %q", got, want)
	}
}

func TestFinding_CategoriesOrderPreserved(t *testing.T) {
	want := []Category{"secrets", "network", "secrets"}
	f := Finding{Categories: want}

	if !reflect.DeepEqual(f.Categories, want) {
		t.Fatalf("Categories = %v, want %v (order/duplicates must be preserved)", f.Categories, want)
	}
}
