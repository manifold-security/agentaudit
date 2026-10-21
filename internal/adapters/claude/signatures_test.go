package claude

import (
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
)

// Agent() resolves to adapter.AgentClaudeCode, which is what makes
// appliesTo:["claude-code"] rules and WithAgents filtering match this adapter.
func TestNewAgent(t *testing.T) {
	if got := New().Agent(); got != adapter.AgentClaudeCode {
		t.Fatalf("Agent() = %q, want %q", got, adapter.AgentClaudeCode)
	}
}

func TestSignatures(t *testing.T) {
	want := []adapter.Signature{
		{Dir: ".claude", File: "settings.json", Recursive: false},
		{Dir: ".claude", File: "settings.local.json", Recursive: false},
		{Dir: ".", File: ".mcp.json", Recursive: false},
		{Dir: ".claude/agents", Recursive: true},
		{Dir: ".claude/skills", Recursive: true},
		{Dir: ".claude/commands", Recursive: true},
		{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true},
	}

	got := New().Signatures()
	if len(got) != len(want) {
		t.Fatalf("Signatures() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Signatures()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A recursive signature matches a nested path through adapter.Matches, not
// just by literal comparison against Signatures().
func TestSignatures_AgentsMatchesNestedPath(t *testing.T) {
	sigs := New().Signatures()

	cases := []struct {
		path string
		want bool
	}{
		{".claude/agents/reviewer.md", true},
		{".claude/agents/team/reviewer.md", true},
		{".claude/agents-evil/reviewer.md", false},
		{".claude/notes.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSignatures_SkillsMatchesNestedPath(t *testing.T) {
	sigs := New().Signatures()

	cases := []struct {
		path string
		want bool
	}{
		{".claude/skills/foo/SKILL.md", true},
		{".claude/skills/nested/deep/SKILL.md", true},
		{".claude/skills-evil/SKILL.md", false},
		{".claude/notes.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestSignatures_CommandsMatchesNestedPath(t *testing.T) {
	sigs := New().Signatures()

	cases := []struct {
		path string
		want bool
	}{
		{".claude/commands/deploy.md", true},
		{".claude/commands/deploy/run.md", true},
		{".claude/commands-evil/deploy.md", false},
		{".claude/notes.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// The depth-agnostic .claude-plugin/plugin.json signature matches both a
// root-level manifest and one nested at arbitrary depth.
func TestSignatures_PluginManifestMatchesAnyDepth(t *testing.T) {
	sigs := New().Signatures()

	cases := []struct {
		path string
		want bool
	}{
		{".claude-plugin/plugin.json", true},
		{"plugins/foo/.claude-plugin/plugin.json", true},
		{"a/b/plugins/foo/.claude-plugin/plugin.json", true},
		{"evil.claude-plugin/plugin.json", false},
		{".claude-plugin/README.md", false},
	}
	for _, tt := range cases {
		if got := adapter.Matches(tt.path, sigs); got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

var _ adapter.Adapter = Adapter{}

var _ adapter.GlobalScoped = Adapter{}

func TestGlobalConfig_Base(t *testing.T) {
	if got := New().GlobalConfig().Base; got != adapter.BaseHome {
		t.Fatalf("GlobalConfig().Base = %q, want %q", got, adapter.BaseHome)
	}
}

// .claude.json backs no Signatures() entry, so discovery cannot treat it as a
// project marker.
func TestSignatures_ClaudeJSONMatchesNoSignature(t *testing.T) {
	if adapter.Matches(".claude.json", New().Signatures()) {
		t.Fatalf("Matches(%q) = true, want false", ".claude.json")
	}
}

func TestGlobalConfig_Entries(t *testing.T) {
	want := []string{
		".claude/settings.json",
		".claude/settings.local.json",
		".claude/agents",
		".claude/skills",
		".claude/commands",
		".claude/plugins",
		".claude.json",
	}
	got := New().GlobalConfig().Entries
	if len(got) != len(want) {
		t.Fatalf("GlobalConfig().Entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("GlobalConfig().Entries[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
