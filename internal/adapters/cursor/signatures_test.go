package cursor

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/discovery"
)

var _ adapter.Adapter = Adapter{}

var _ adapter.GlobalScoped = Adapter{}

// Agent() resolves to adapter.AgentCursor, which is what makes
// appliesTo:["cursor"] rules and WithAgents filtering match this adapter.
func TestNewAgent(t *testing.T) {
	if got := New().Agent(); got != adapter.AgentCursor {
		t.Fatalf("Agent() = %q, want %q", got, adapter.AgentCursor)
	}
}

// Discovery matches a repository against these literals, so a typo in one
// loses that surface for every scan that would have matched it.
func TestSignatures(t *testing.T) {
	want := []adapter.Signature{
		{Dir: ".cursor", File: "mcp.json"},
		{Dir: ".cursor", File: "hooks.json"},
		{Dir: ".cursor", File: "worktrees.json"},
		{Dir: ".cursor", File: "environment.json"},
		{Dir: ".cursor", File: "sandbox.json"},
		{Dir: ".cursor", File: "cli.json"},
		{Dir: ".cursor", File: "permissions.json"},
		{Dir: ".cursor/hooks", Recursive: true},
		{Dir: ".cursor/skills", Recursive: true},
		{Dir: ".cursor/agents", Recursive: true},
		{Dir: ".cursor-plugin", File: "plugin.json", AnyDepth: true},
		{File: "plugin.json"},
	}

	got := New().Signatures()
	if len(got) != len(want) {
		t.Fatalf("Signatures() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Signatures()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A location another agent owns stays undeclared here. The rows sharing a
// declared basename are the ones a directory-blind matcher admits, so they
// are what hold the matcher to reading more than the file name.
func TestSignaturesLeaveTheBorrowedClaudeAndCodexLocationsUndeclared(t *testing.T) {
	sigs := New().Signatures()
	cases := []struct {
		path string
		want bool
	}{
		{".cursor/mcp.json", true},
		{".cursor/hooks.json", true},
		{".cursor/worktrees.json", true},
		{".cursor/environment.json", true},
		{".cursor/sandbox.json", true},
		{".cursor/cli.json", true},
		{".cursor/permissions.json", true},
		{".cursor/skills", true},
		{".cursor/skills/deploy/SKILL.md", true},
		{".cursor/skills/ops/rotate/scripts/run.sh", true},
		{"plugin.json", true},
		{".cursor-plugin/plugin.json", true},
		{"plugins/ship-tool/.cursor-plugin/plugin.json", true},
		{".cursor-evil/mcp.json", false},
		{".claude-plugin/plugin.json", false},
		{".claude/settings.json", false},
		{".claude/agents/reviewer.md", false},
		{".codex/agents/reviewer.md", false},
		{"CLAUDE.md", false},
		{"AGENTS.md", false},
		{".agents/skills", false},
		{".agents/skills/demo/SKILL.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// The declared Agent Plugins manifest enumerates no project by the directory
// holding it. Dropping projectMarkers' skip turns this red; the declaration
// itself is held by TestABareAgentPluginCloneIsDiscoveredAsACursorSource.
func TestProjectEnumerationSkipsTheDirectoriesHoldingAPluginManifest(t *testing.T) {
	fsys := fstest.MapFS{
		"tools/kit/.cursor-plugin/plugin.json": {Data: []byte(`{"name":"kit"}`)},
		"vendor/panel/plugin.json":             {Data: []byte(`{"id":"panel"}`)},
	}

	roots, _, err := discovery.Projects(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Projects() error = %v, want nil", err)
	}
	if want := []string{"tools/kit"}; !slices.Equal(roots, want) {
		t.Fatalf("discovery.Projects() = %q, want %q", roots, want)
	}
}

// A clone whose only Cursor surface is the Agent Plugins manifest at its root
// is discovered as a Cursor source. Discovery is what gates the project pass,
// so without that source the scan runs no parser over the clone and prints a
// clean report for a plugin it never read. The skill beside the manifest is
// held to contributing no source of its own, so a signature widened to reach
// inside a plugin tree turns this red.
func TestABareAgentPluginCloneIsDiscoveredAsACursorSource(t *testing.T) {
	fsys := fstest.MapFS{
		"plugin.json":          {Data: []byte(`{"$schema":"https://agent-plugins.org/v1/plugin.json","name":"clone"}`)},
		"skills/demo/SKILL.md": {Data: []byte("---\nname: demo\n---\n")},
	}

	res, _, err := discovery.Discover(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Discover() error = %v, want nil", err)
	}
	want := []discovery.Source{{Path: "plugin.json", Agent: adapter.AgentCursor}}
	if !slices.Equal(res.Sources, want) {
		t.Fatalf("discovery.Discover() sources = %+v, want exactly %+v", res.Sources, want)
	}
}

// A project whose only Cursor surface is its skills root is discovered as a
// Cursor source. Discovery is what activates the adapter, so without that
// source no parser runs and the scan prints a clean report over a skills tree
// that ships executable payloads. The shared capability fixture cannot hold
// this, because its .cursor/mcp.json activates the adapter regardless.
func TestASkillsOnlyProjectIsDiscoveredAsACursorSource(t *testing.T) {
	fsys := fstest.MapFS{
		".cursor/skills/deploy/SKILL.md":       {Data: []byte("---\nname: deploy\n---\n")},
		".cursor/skills/deploy/scripts/run.sh": {Data: []byte("#!/bin/sh\n")},
	}

	res, _, err := discovery.Discover(fsys, []adapter.Adapter{New()})
	if err != nil {
		t.Fatalf("discovery.Discover() error = %v, want nil", err)
	}
	want := []discovery.Source{
		{Path: ".cursor/skills/deploy/SKILL.md", Agent: adapter.AgentCursor},
		{Path: ".cursor/skills/deploy/scripts/run.sh", Agent: adapter.AgentCursor},
	}
	if !slices.Equal(res.Sources, want) {
		t.Fatalf("discovery.Discover() sources = %+v, want exactly %+v", res.Sources, want)
	}
}
