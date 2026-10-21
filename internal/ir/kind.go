package ir

// Kind* constants are the frozen lowerCamelCase tokens returned by each
// entity's Kind() method. These tokens equal the rule JSON `target:` values
// and MUST NOT change once consumed by adapters and the rule engine.
const (
	KindHook             = "hook"
	KindMCPServer        = "mcpServer"
	KindEnvVar           = "envVar"
	KindSubagent         = "subagent"
	KindSkill            = "skill"
	KindPlugin           = "plugin"
	KindSandbox          = "sandbox"
	KindStatusLine       = "statusLine"
	KindCredentialHelper = "credentialHelper"
	KindPermissionMode   = "permissionMode"
	KindMCPApproval      = "mcpApproval"
	KindBundledPayload   = "bundledPayload"
	KindInlineShell      = "inlineShell"
	KindPluginExecutable = "pluginExecutable"
	KindProvisioner      = "provisioner"
	KindNetworkPolicy    = "networkPolicy"
	KindToolPermission   = "toolPermission"
	KindInstructionText  = "instructionText"
	KindLSPServer        = "lspServer"
)
