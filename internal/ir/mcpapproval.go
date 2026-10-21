package ir

// MCPApproval is a declared MCP server auto-approval signal, carried as a raw
// Setting/Value pair. The adapter never judges permissiveness — that
// judgment lives in rules/claude/mcp-autoapprove.json.
type MCPApproval struct {
	Setting  string
	Value    string
	Location Location
}

func (MCPApproval) Kind() string { return KindMCPApproval }

func (m MCPApproval) Identity() string {
	return identity(KindMCPApproval, m.Setting, m.Value)
}
