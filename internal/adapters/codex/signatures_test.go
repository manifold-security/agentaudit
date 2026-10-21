package codex

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/discovery"
)

var _ adapter.Adapter = Adapter{}

var _ adapter.GlobalScoped = Adapter{}

func TestAgentIsTheFrozenCodexID(t *testing.T) {
	if got := New().Agent(); got != adapter.AgentCodex {
		t.Errorf("Agent() = %q, want %q", got, adapter.AgentCodex)
	}
}

// Every declared location is anchored under the agent's own directory or the
// skills root Codex scans, and a sibling whose name merely starts with either
// stays unowned.
func TestSignaturesClaimOnlyTheCodexLocations(t *testing.T) {
	sigs := New().Signatures()
	if len(sigs) == 0 {
		t.Fatal("Signatures() declared nothing, so this guard inspected nothing")
	}

	for _, s := range sigs {
		if s.Dir != ".codex" && s.Dir != skillsRoot {
			t.Errorf("Signatures() declares %+v, which is anchored outside .codex and %s", s, skillsRoot)
		}
	}
	cases := []struct {
		path string
		want bool
	}{
		{configFileName, true},
		{hooksFileName, true},
		{skillsRoot + "/deploy/SKILL.md", true},
		{skillsRoot + "/ops/rotate/scripts/run.sh", true},
		{".codex-evil/config.toml", false},
		{".agents/skills-evil/deploy/SKILL.md", false},
		{".agents/notes.md", false},
		{".codex/skills/deploy/SKILL.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q, Signatures()) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// A project whose only Codex surface is its skills tree is discovered as a
// Codex source, and a nested directory holding one is enumerated as a
// project for -r. The shared capability fixture cannot hold this, because
// its .codex/config.toml activates the adapter regardless.
func TestASkillsOnlyTreeIsDiscoveredAsACodexSource(t *testing.T) {
	fsys := fstest.MapFS{
		skillsRoot + "/ship/SKILL.md":                   {Data: []byte("---\nname: ship\n---\n")},
		skillsRoot + "/ship/scripts/ship.sh":            {Data: []byte("#!/bin/sh\n")},
		"apps/web/" + skillsRoot + "/lint/SKILL.md":     {Data: []byte("---\nname: lint\n---\n")},
		"apps/web/" + skillsRoot + "/lint/scripts/l.sh": {Data: []byte("#!/bin/sh\n")},
	}

	res, _, err := discovery.Discover(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Discover() error = %v, want nil", err)
	}
	want := []discovery.Source{
		{Path: skillsRoot + "/ship/SKILL.md", Agent: adapter.AgentCodex},
		{Path: skillsRoot + "/ship/scripts/ship.sh", Agent: adapter.AgentCodex},
	}
	if !slices.Equal(res.Sources, want) {
		t.Fatalf("discovery.Discover() sources = %+v, want exactly %+v", res.Sources, want)
	}

	roots, _, err := discovery.Projects(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Projects() error = %v, want nil", err)
	}
	if wantRoots := []string{".", "apps/web"}; !slices.Equal(roots, wantRoots) {
		t.Fatalf("discovery.Projects() = %q, want %q", roots, wantRoots)
	}
}
