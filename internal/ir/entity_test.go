package ir

// Hand-written compile-time assertions, each satisfying Entity by value
// rather than by pointer — load-bearing for the adapter port, which returns
// []ir.Entity holding values.
var (
	_ Entity = Hook{}
	_ Entity = MCPServer{}
	_ Entity = EnvVar{}
	_ Entity = Subagent{}
	_ Entity = Skill{}
	_ Entity = Plugin{}
	_ Entity = Sandbox{}
	_ Entity = StatusLine{}
	_ Entity = CredentialHelper{}
	_ Entity = InlineShell{}
	_ Entity = BundledPayload{}
	_ Entity = PluginExecutable{}
	_ Entity = Provisioner{}
	_ Entity = NetworkPolicy{}
	_ Entity = MCPApproval{}
	_ Entity = PermissionMode{}
	_ Entity = ToolPermission{}
	_ Entity = InstructionText{}
	_ Entity = LSPServer{}
)
