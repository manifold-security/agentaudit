package claude

import (
	"github.com/manifold-security/agentaudit/adapter"
)

// Adapter implements adapter.Adapter for Claude Code.
type Adapter struct{}

func New() Adapter { return Adapter{} }

func (Adapter) Agent() adapter.AgentID { return adapter.AgentClaudeCode }

// Signatures declares which paths this adapter owns. The project pass runs an
// adapter only when its signature matched, so a commands-only or plugin-only
// repo goes unparsed without an entry here.
func (Adapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{Dir: ".claude", File: "settings.json", Recursive: false},
		{Dir: ".claude", File: "settings.local.json", Recursive: false},
		{Dir: ".", File: ".mcp.json", Recursive: false},
		{Dir: ".claude/agents", Recursive: true},
		{Dir: ".claude/skills", Recursive: true},
		{Dir: ".claude/commands", Recursive: true},
		{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true},
	}
}

// GlobalConfig declares the home-relative prefixes Claude Code loads
// configuration from. ~/.claude also holds conversation transcripts, debug
// logs and shell history, so declaring it whole would make the scan read
// private data to no end. ~/.mcp.json is not Claude global config.
func (Adapter) GlobalConfig() adapter.GlobalConfig {
	return adapter.GlobalConfig{
		Base: adapter.BaseHome,
		Entries: []string{
			".claude/settings.json",
			".claude/settings.local.json",
			".claude/agents",
			".claude/skills",
			".claude/commands",
			".claude/plugins",
			".claude.json",
		},
	}
}
