package ruleeng

import "github.com/manifold-security/agentaudit/internal/ir"

// targets maps an ir.Kind token to a constructor returning a fresh,
// zero-valued concrete ir.Entity of that kind. A rule's target field must
// resolve here to be usable.
var targets = map[string]func() ir.Entity{
	ir.KindHook:             func() ir.Entity { return ir.Hook{} },
	ir.KindMCPServer:        func() ir.Entity { return ir.MCPServer{} },
	ir.KindEnvVar:           func() ir.Entity { return ir.EnvVar{} },
	ir.KindSubagent:         func() ir.Entity { return ir.Subagent{} },
	ir.KindSkill:            func() ir.Entity { return ir.Skill{} },
	ir.KindPlugin:           func() ir.Entity { return ir.Plugin{} },
	ir.KindSandbox:          func() ir.Entity { return ir.Sandbox{} },
	ir.KindStatusLine:       func() ir.Entity { return ir.StatusLine{} },
	ir.KindCredentialHelper: func() ir.Entity { return ir.CredentialHelper{} },
	ir.KindPermissionMode:   func() ir.Entity { return ir.PermissionMode{} },
	ir.KindMCPApproval:      func() ir.Entity { return ir.MCPApproval{} },
	ir.KindBundledPayload:   func() ir.Entity { return ir.BundledPayload{} },
	ir.KindInlineShell:      func() ir.Entity { return ir.InlineShell{} },
	ir.KindPluginExecutable: func() ir.Entity { return ir.PluginExecutable{} },
	ir.KindProvisioner:      func() ir.Entity { return ir.Provisioner{} },
	ir.KindNetworkPolicy:    func() ir.Entity { return ir.NetworkPolicy{} },
	ir.KindToolPermission:   func() ir.Entity { return ir.ToolPermission{} },
	ir.KindInstructionText:  func() ir.Entity { return ir.InstructionText{} },
	ir.KindLSPServer:        func() ir.Entity { return ir.LSPServer{} },
}

// newEntity returns a fresh ir.Entity for the registered target token and
// reports whether target was known.
func newEntity(target string) (ir.Entity, bool) {
	factory, ok := targets[target]
	if !ok {
		return nil, false
	}
	return factory(), true
}

func knownTarget(target string) bool {
	_, ok := targets[target]
	return ok
}
