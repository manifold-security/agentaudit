package finding

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestNewReport_Dedup(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{RuleID: "secrets.env-plaintext", Message: "first", Capability: Capability{Entity: entity, Provenance: prov}}
	b := Finding{
		RuleID:     "network.open-transport",
		Message:    "second",
		Capability: Capability{Entity: ir.EnvVar{Name: "OTHER", Value: "x"}, Provenance: Provenance{File: "other.json", Key: "env.OTHER"}},
	}
	aPrime := Finding{RuleID: "secrets.env-plaintext", Message: "duplicate", Capability: Capability{Entity: entity, Provenance: prov}}

	if a.ID() != aPrime.ID() {
		t.Fatalf("test setup invalid: a.ID() != aPrime.ID()")
	}

	report := NewReport([]Finding{a, b, aPrime})
	got := report.Findings()

	want := []Finding{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Findings() = %+v, want %+v", got, want)
	}

	// Mutating the returned slice must not affect internal state.
	got[0].Message = "mutated"
	again := report.Findings()
	if again[0].Message != "first" {
		t.Fatalf("Findings() leaked internal state: got %q after external mutation, want %q", again[0].Message, "first")
	}
}

// TestNewReport_DistinctAgentsSurvive proves NewReport dedupes on
// (Agent, ID()), not ID() alone: two findings sharing an ID() but produced
// by different agents must both survive. The premise assertion
// (a.ID() == b.ID()) is checked FIRST so this test cannot pass for the wrong
// reason if provenance keys ever change and the ids stop colliding.
func TestNewReport_DistinctAgentsSurvive(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{RuleID: "secrets.env-plaintext", Agent: "claude-code", Capability: Capability{Entity: entity, Provenance: prov}}
	b := Finding{RuleID: "secrets.env-plaintext", Agent: "mirror-agent", Capability: Capability{Entity: entity, Provenance: prov}}

	if a.ID() != b.ID() {
		t.Fatalf("test setup invalid: a.ID() != b.ID(): %q vs %q", a.ID(), b.ID())
	}

	report := NewReport([]Finding{a, b})
	got := report.Findings()

	want := []Finding{a, b}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Findings() = %+v, want %+v (both agents' findings must survive)", got, want)
	}
}

// TestNewReport_SameAgentDuplicateCollapses guards against dedupe skipping a
// duplicate merely because it carries a non-empty Agent: a matched Agent
// must still collapse an otherwise-identical pair.
func TestNewReport_SameAgentDuplicateCollapses(t *testing.T) {
	entity := ir.EnvVar{Name: "API_KEY", Value: "secret"}
	prov := Provenance{File: "settings.json", Key: "env.API_KEY"}

	a := Finding{RuleID: "secrets.env-plaintext", Agent: "claude-code", Message: "first", Capability: Capability{Entity: entity, Provenance: prov}}
	aPrime := Finding{RuleID: "secrets.env-plaintext", Agent: "claude-code", Message: "duplicate", Capability: Capability{Entity: entity, Provenance: prov}}

	if a.ID() != aPrime.ID() {
		t.Fatalf("test setup invalid: a.ID() != aPrime.ID()")
	}

	report := NewReport([]Finding{a, aPrime})
	got := report.Findings()

	want := []Finding{a}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Findings() = %+v, want %+v (same-agent duplicate must collapse)", got, want)
	}
}

func TestHasFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{
			name:     "nil findings",
			findings: nil,
			want:     false,
		},
		{
			name: "one finding",
			findings: []Finding{
				{RuleID: "r1", Capability: Capability{Entity: ir.EnvVar{Name: "A", Value: "v"}, Provenance: Provenance{File: "a.json", Key: "env.A"}}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport(tt.findings)
			if got := r.HasFindings(); got != tt.want {
				t.Fatalf("HasFindings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCounts(t *testing.T) {
	secretsFinding := Finding{
		RuleID:     "secrets.env-plaintext",
		Categories: []Category{"secrets"},
		Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "x"}, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}},
	}
	networkFinding := Finding{
		RuleID:     "network.open-transport",
		Categories: []Category{"network"},
		Capability: Capability{Entity: ir.EnvVar{Name: "URL", Value: "y"}, Provenance: Provenance{File: "config.json", Key: "env.URL"}},
	}

	// comboFinding carries a primary category ("network", already produced
	// by networkFinding) plus a secondary tag ("extra-secondary") that
	// exists nowhere else. Counts must count only the primary category, so
	// this finding must NOT add "extra-secondary" to the distinct count.
	comboFinding := Finding{
		RuleID:     "combo.rule",
		Categories: []Category{"network", "extra-secondary"},
		Capability: Capability{Entity: ir.EnvVar{Name: "TOKEN", Value: "z"}, Provenance: Provenance{File: "other.json", Key: "env.TOKEN"}},
	}

	tests := []struct {
		name     string
		findings []Finding
		want     Counts
	}{
		{
			name:     "empty report",
			findings: nil,
			want:     Counts{},
		},
		{
			name:     "two files two categories",
			findings: []Finding{secretsFinding, networkFinding},
			want:     Counts{Findings: 2, Files: 2, Categories: 2},
		},
		{
			name:     "primary-category-only counting collapses secondary tags",
			findings: []Finding{secretsFinding, networkFinding, comboFinding},
			want:     Counts{Findings: 3, Files: 3, Categories: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport(tt.findings)
			if got := r.Counts(); got != tt.want {
				t.Fatalf("Counts() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCounts_CategoriesMatchesGroupByCategoryLength(t *testing.T) {
	newFinding := func(agent, category, ruleID string) Finding {
		f := Finding{
			RuleID: ruleID,
			Agent:  agent,
			Capability: Capability{
				Entity:     ir.EnvVar{Name: "X", Value: "y"},
				Provenance: Provenance{File: ruleID + ".json"},
			},
		}
		if category != "" {
			f.Categories = []Category{Category(category)}
		}
		return f
	}

	tests := []struct {
		name     string
		findings []Finding
	}{
		{name: "empty report", findings: nil},
		{name: "single category", findings: []Finding{newFinding("a", "network", "r1")}},
		{name: "categoryless finding", findings: []Finding{newFinding("a", "", "r1")}},
		{
			name: "two agents sharing one category",
			findings: []Finding{
				newFinding("a", "network", "r1"),
				newFinding("b", "network", "r2"),
			},
		},
		{
			name: "categoryless finding alongside categorized findings across agents",
			findings: []Finding{
				newFinding("a", "network", "r1"),
				newFinding("b", "", "r2"),
				newFinding("c", "secrets", "r3"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReport(tt.findings)
			if got, want := r.Counts().Categories, len(r.GroupByCategory()); got != want {
				t.Fatalf("Counts().Categories = %d, want len(GroupByCategory()) = %d", got, want)
			}
		})
	}
}

// TestReportUnreadableSources proves UnreadableSources defaults to 0,
// round-trips through WithUnreadableSources, clamps a negative input to 0,
// leaves findings-derived fields untouched, and is mirrored on Counts.
func TestReportUnreadableSources(t *testing.T) {
	findings := []Finding{
		{RuleID: "secrets.env-plaintext", Categories: []Category{"secrets"}, Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "x"}, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}}},
	}

	base := NewReport(findings)
	if got := base.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() default = %d, want 0", got)
	}

	degraded := base.WithUnreadableSources(3)
	if got := degraded.UnreadableSources(); got != 3 {
		t.Fatalf("UnreadableSources() after WithUnreadableSources(3) = %d, want 3", got)
	}
	if got, want := degraded.Findings(), base.Findings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("WithUnreadableSources() changed Findings() = %+v, want %+v", got, want)
	}
	if got, want := degraded.Counts().Findings, base.Counts().Findings; got != want {
		t.Fatalf("WithUnreadableSources() changed Counts().Findings = %d, want %d", got, want)
	}
	if got := degraded.Counts().UnreadableSources; got != 3 {
		t.Fatalf("Counts().UnreadableSources = %d, want 3", got)
	}

	clamped := base.WithUnreadableSources(-1)
	if got := clamped.UnreadableSources(); got != 0 {
		t.Fatalf("WithUnreadableSources(-1).UnreadableSources() = %d, want clamped to 0", got)
	}
	if got := degraded.UnparsedSources(); got != 0 {
		t.Fatalf("WithUnreadableSources(3).UnparsedSources() = %d, want 0 (the two counts are independent)", got)
	}
}

// TestReportUnparsedSources proves UnparsedSources defaults to 0, round-trips
// through WithUnparsedSources, clamps a negative input to 0, leaves
// findings-derived fields untouched, is mirrored on Counts, and carries
// independently of UnreadableSources.
func TestReportUnparsedSources(t *testing.T) {
	findings := []Finding{
		{RuleID: "secrets.env-plaintext", Categories: []Category{"secrets"}, Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "x"}, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}}},
	}

	base := NewReport(findings)
	if got := base.UnparsedSources(); got != 0 {
		t.Fatalf("UnparsedSources() default = %d, want 0", got)
	}

	degraded := base.WithUnparsedSources(2)
	if got := degraded.UnparsedSources(); got != 2 {
		t.Fatalf("UnparsedSources() after WithUnparsedSources(2) = %d, want 2", got)
	}
	if got := degraded.UnreadableSources(); got != 0 {
		t.Fatalf("WithUnparsedSources(2).UnreadableSources() = %d, want 0 (the two counts are independent)", got)
	}
	if got, want := degraded.Findings(), base.Findings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("WithUnparsedSources() changed Findings() = %+v, want %+v", got, want)
	}
	if got, want := degraded.Counts().Findings, base.Counts().Findings; got != want {
		t.Fatalf("WithUnparsedSources() changed Counts().Findings = %d, want %d", got, want)
	}
	if got := degraded.Counts().UnparsedSources; got != 2 {
		t.Fatalf("Counts().UnparsedSources = %d, want 2", got)
	}

	clamped := base.WithUnparsedSources(-1)
	if got := clamped.UnparsedSources(); got != 0 {
		t.Fatalf("WithUnparsedSources(-1).UnparsedSources() = %d, want clamped to 0", got)
	}

	both := base.WithUnreadableSources(3).WithUnparsedSources(2)
	if got := both.Counts(); got.UnreadableSources != 3 || got.UnparsedSources != 2 {
		t.Fatalf("Counts() = %+v, want UnreadableSources 3 and UnparsedSources 2", got)
	}
}

// The scanned-agent list starts empty, round-trips in the order given
// without sorting or deduping, and leaves the findings untouched.
func TestReportScannedAgents(t *testing.T) {
	findings := []Finding{
		{RuleID: "secrets.env-plaintext", Categories: []Category{"secrets"}, Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "x"}, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}}},
	}

	base := NewReport(findings)
	if got := base.ScannedAgents(); len(got) != 0 {
		t.Fatalf("ScannedAgents() default = %+v, want empty", got)
	}

	scanned := base.WithScannedAgents([]string{"cursor", "claude-code", "cursor"})
	want := []string{"cursor", "claude-code", "cursor"}
	if got := scanned.ScannedAgents(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ScannedAgents() = %+v, want %+v", got, want)
	}
	if got, want := scanned.Findings(), base.Findings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("WithScannedAgents() changed Findings() = %+v, want %+v", got, want)
	}
	if got := base.ScannedAgents(); len(got) != 0 {
		t.Fatalf("WithScannedAgents() mutated the receiver: ScannedAgents() = %+v, want empty", got)
	}
}

// Neither the slice handed to WithScannedAgents nor the one ScannedAgents
// hands back aliases the Report, so a caller mutating either cannot rewrite
// which agents a rendered report claims were scanned.
func TestReportScannedAgentsCopiesBothWays(t *testing.T) {
	in := []string{"claude-code", "cursor"}
	scanned := NewReport(nil).WithScannedAgents(in)

	in[0] = "forged"
	if got := scanned.ScannedAgents()[0]; got != "claude-code" {
		t.Fatalf("ScannedAgents()[0] = %q after the caller mutated its own slice, want %q", got, "claude-code")
	}

	out := scanned.ScannedAgents()
	out[1] = "forged"
	if got := scanned.ScannedAgents()[1]; got != "cursor" {
		t.Fatalf("ScannedAgents()[1] = %q after the returned slice was mutated, want %q", got, "cursor")
	}
}

func TestGroupByCategory(t *testing.T) {
	secretsOnly := Finding{
		RuleID:     "secrets.env-plaintext",
		Categories: []Category{"secrets"},
		Capability: Capability{Entity: ir.EnvVar{Name: "API_KEY", Value: "x"}, Provenance: Provenance{File: "settings.json", Key: "env.API_KEY"}},
	}
	networkOnly := Finding{
		RuleID:     "network.open-transport",
		Categories: []Category{"network"},
		Capability: Capability{Entity: ir.EnvVar{Name: "URL", Value: "y"}, Provenance: Provenance{File: "config.json", Key: "env.URL"}},
	}
	multiCategory := Finding{
		RuleID:     "combo.rule",
		Categories: []Category{"network", "secrets"},
		Capability: Capability{Entity: ir.EnvVar{Name: "TOKEN", Value: "z"}, Provenance: Provenance{File: "other.json", Key: "env.TOKEN"}},
	}

	t.Run("first-appearance order, each finding placed in exactly one group (its primary category)", func(t *testing.T) {
		r := NewReport([]Finding{secretsOnly, networkOnly, multiCategory})
		got := r.GroupByCategory()

		// multiCategory's Categories[0] is "network": it must appear only
		// in the "network" group, never in "secrets", even though
		// Categories also lists "secrets".
		want := []CategoryGroup{
			{Category: "secrets", Findings: []Finding{secretsOnly}},
			{Category: "network", Findings: []Finding{networkOnly, multiCategory}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("GroupByCategory() = %+v, want %+v", got, want)
		}
	})

	t.Run("empty report yields empty non-nil-panicking slice", func(t *testing.T) {
		r := NewReport(nil)
		got := r.GroupByCategory()
		if len(got) != 0 {
			t.Fatalf("GroupByCategory() on empty report = %+v, want empty", got)
		}
	})
}

func TestGroupByAgent(t *testing.T) {
	newFinding := func(agent, category, ruleID string) Finding {
		f := Finding{
			RuleID: ruleID,
			Agent:  agent,
			Capability: Capability{
				Entity:     ir.EnvVar{Name: "X", Value: "y"},
				Provenance: Provenance{File: ruleID + ".json"},
			},
		}
		if category != "" {
			f.Categories = []Category{Category(category)}
		}
		return f
	}

	t.Run("groups by agent in first-appearance order", func(t *testing.T) {
		b1 := newFinding("b", "cat", "r1")
		a1 := newFinding("a", "cat", "r2")
		b2 := newFinding("b", "cat", "r3")

		r := NewReport([]Finding{b1, a1, b2})
		got := r.GroupByAgent()

		if len(got) != 2 {
			t.Fatalf("GroupByAgent() len = %d, want 2: %+v", len(got), got)
		}
		if got[0].Agent != "b" || got[1].Agent != "a" {
			t.Fatalf("GroupByAgent() agent order = [%q, %q], want [\"b\", \"a\"]", got[0].Agent, got[1].Agent)
		}
		if len(got[0].Groups) != 1 || len(got[0].Groups[0].Findings) != 2 {
			t.Fatalf("GroupByAgent()[0] = %+v, want agent \"b\" carrying two findings", got[0])
		}
	})

	t.Run("groups each agent's findings by primary category in first-appearance order", func(t *testing.T) {
		aNetwork := newFinding("a", "network", "r1")
		aSecrets := newFinding("a", "secrets", "r2")

		r := NewReport([]Finding{aNetwork, aSecrets})
		got := r.GroupByAgent()

		if len(got) != 1 {
			t.Fatalf("GroupByAgent() len = %d, want 1", len(got))
		}
		if len(got[0].Groups) != 2 || got[0].Groups[0].Category != "network" || got[0].Groups[1].Category != "secrets" {
			t.Fatalf("GroupByAgent()[0].Groups = %+v, want [network, secrets] in first-appearance order", got[0].Groups)
		}
	})

	t.Run("skips a finding with no categories", func(t *testing.T) {
		withCategory := newFinding("a", "network", "r1")
		withoutCategory := newFinding("a", "", "r2")

		r := NewReport([]Finding{withCategory, withoutCategory})
		got := r.GroupByAgent()

		if len(got) != 1 || len(got[0].Groups) != 1 || len(got[0].Groups[0].Findings) != 1 {
			t.Fatalf("GroupByAgent() = %+v, want the categoryless finding excluded from every group", got)
		}
	})

	t.Run("omits an agent whose every finding is categoryless", func(t *testing.T) {
		bareAgent := newFinding("bare", "", "r1")
		withCategory := newFinding("other", "network", "r2")

		r := NewReport([]Finding{bareAgent, withCategory})
		got := r.GroupByAgent()

		if len(got) != 1 || got[0].Agent != "other" {
			t.Fatalf("GroupByAgent() = %+v, want only \"other\"'s group, no dangling group for \"bare\"", got)
		}
	})

	t.Run("empty report yields no groups", func(t *testing.T) {
		got := NewReport(nil).GroupByAgent()
		if len(got) != 0 {
			t.Fatalf("GroupByAgent() on empty report = %+v, want empty", got)
		}
	})

	t.Run("an empty Agent is its own group", func(t *testing.T) {
		f := newFinding("", "network", "r1")

		got := NewReport([]Finding{f}).GroupByAgent()
		if len(got) != 1 || got[0].Agent != "" {
			t.Fatalf("GroupByAgent() = %+v, want one group with an empty Agent", got)
		}
	})
}
