package cursor

import (
	"github.com/manifold-security/agentaudit/adapter"
)

// Adapter implements adapter.Adapter for Cursor.
type Adapter struct{}

func New() Adapter { return Adapter{} }

func (Adapter) Agent() adapter.AgentID { return adapter.AgentCursor }

// Signatures declares which paths this adapter owns.
//
// A declared location this adapter reads nothing from is worse than an
// undeclared one: discovery matches it, the adapter activates, and the scan
// prints a clean report over configuration it saw and ignored. So the set
// holds only what Parse reaches.
//
// Cursor also executes locations other agents own, and
// TestSignaturesLeaveTheBorrowedClaudeAndCodexLocationsUndeclared keeps them
// out: one the Claude adapter already covers would be reported twice, and for
// the rest a Cursor claim would assert ownership of a surface this adapter
// does not parse.
func (Adapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
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
}

// GlobalConfig declares the home-relative prefixes Cursor loads configuration
// from. cli-config.json carries no Signature: no project location for it is
// documented, so there is nothing for it to claim.
func (Adapter) GlobalConfig() adapter.GlobalConfig {
	return adapter.GlobalConfig{
		Base: adapter.BaseHome,
		Entries: []string{
			".cursor/mcp.json",
			".cursor/hooks.json",
			".cursor/hooks",
			".cursor/sandbox.json",
			".cursor/skills",
			".cursor/agents",
			".cursor/plugins/local",
			".cursor/cli-config.json",
			".cursor/permissions.json",
		},
	}
}
