package finding

import (
	"reflect"
	"regexp"
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

// A finding's digest is the id the JSON report prints for it: want is the id
// the json reporter's golden carries for this same hand-built finding.
func TestDigest_FrozenLiteralMatchesTheJSONReportID(t *testing.T) {
	f := Finding{
		RuleID:     "hook.autostart",
		Agent:      "claude-code",
		Categories: []Category{"lifecycle"},
		Capability: Capability{
			Entity:     ir.Hook{Event: "SessionStart", Command: "notify.sh"},
			Provenance: Provenance{File: ".claude/settings.json", Key: "hooks[0]"},
		},
	}

	const want = "8308ec88ad87a751c7edda0a69cf6bcd"
	if got := f.Digest(); got != want {
		t.Fatalf("Digest() = %q, want %q", got, want)
	}
}

func TestDigest_IsStableAndFormatted(t *testing.T) {
	f := Finding{
		RuleID: "hook.autostart",
		Capability: Capability{
			Entity:     ir.Hook{Event: "SessionStart", Command: "notify.sh"},
			Provenance: Provenance{File: ".claude/settings.json", Key: "hooks[0]"},
		},
	}
	hexPattern := regexp.MustCompile(`^[0-9a-f]{32}$`)

	first := f.Digest()
	second := f.Digest()

	if first != second {
		t.Fatalf("Digest() = %q then %q, want the same value both times", first, second)
	}
	if !hexPattern.MatchString(first) {
		t.Fatalf("Digest() = %q, want it to match %s", first, hexPattern)
	}
}

func TestDigest_DistinctRuleIDsOnOneEntityYieldDistinctDigests(t *testing.T) {
	capability := Capability{
		Entity:     ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx mcp-fs"},
		Provenance: Provenance{File: ".mcp.json", Key: "mcpServers.fs"},
	}
	a := Finding{RuleID: "mcp.stdio", Capability: capability}
	b := Finding{RuleID: "mcp.unpinned-npx-command", Capability: capability}

	if a.Digest() == b.Digest() {
		t.Fatalf("Digest() collapsed two distinct findings to the same digest %q", a.Digest())
	}
}

func TestFinding_CategoriesOrderPreserved(t *testing.T) {
	want := []Category{"secrets", "network", "secrets"}
	f := Finding{Categories: want}

	if !reflect.DeepEqual(f.Categories, want) {
		t.Fatalf("Categories = %v, want %v (order/duplicates must be preserved)", f.Categories, want)
	}
}
