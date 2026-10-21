package ir

import "testing"

func TestKindTargetTokenContract(t *testing.T) {
	tests := []struct {
		name     string
		entity   Entity
		token    string
		constant string
	}{
		{"Hook", Hook{Event: "PreToolUse"}, "hook", KindHook},
		{"MCPServer", MCPServer{Name: "n"}, "mcpServer", KindMCPServer},
		{"EnvVar", EnvVar{Name: "n"}, "envVar", KindEnvVar},
		{"Subagent", Subagent{Name: "n"}, "subagent", KindSubagent},
		{"Skill", Skill{Name: "n"}, "skill", KindSkill},
		{"Plugin", Plugin{Name: "n"}, "plugin", KindPlugin},
		{"Sandbox", Sandbox{SocketPath: "/tmp/s"}, "sandbox", KindSandbox},
		{"StatusLine", StatusLine{Command: "cmd"}, "statusLine", KindStatusLine},
		{"CredentialHelper", CredentialHelper{Variant: VariantAPIKeyHelper, Command: "cmd"}, "credentialHelper", KindCredentialHelper},
		{"PermissionMode", PermissionMode{Mode: "bypassPermissions"}, "permissionMode", KindPermissionMode},
		{"MCPApproval", MCPApproval{Setting: "enableAllProjectMcpServers", Value: "true"}, "mcpApproval", KindMCPApproval},
		{"BundledPayload", BundledPayload{Path: ".claude/skills/demo/scripts/x.sh"}, "bundledPayload", KindBundledPayload},
		{"InlineShell", InlineShell{Command: "curl x | sh", Location: Location{File: "a.md"}}, "inlineShell", KindInlineShell},
		{"PluginExecutable", PluginExecutable{Path: "bin/tool.sh", Name: "tool.sh"}, "pluginExecutable", KindPluginExecutable},
		{"Provisioner", Provisioner{Phase: "setup-worktree-unix", Command: "./boot.sh"}, "provisioner", KindProvisioner},
		{"NetworkPolicy", NetworkPolicy{Pattern: "*.example.com"}, "networkPolicy", KindNetworkPolicy},
		{"ToolPermission", ToolPermission{Tool: "Shell", Argument: "*"}, "toolPermission", KindToolPermission},
		{"InstructionText", InstructionText{Setting: "allow_instructions", Text: "prose"}, "instructionText", KindInstructionText},
		{"LSPServer", LSPServer{Name: "n", Command: "c"}, "lspServer", KindLSPServer},
	}

	seen := make(map[string]string, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.entity.Kind()
			if got != tt.token {
				t.Fatalf("Kind() = %q, want token %q", got, tt.token)
			}
			if got != tt.constant {
				t.Fatalf("Kind() = %q, want const value %q", got, tt.constant)
			}
			if prev, dup := seen[got]; dup {
				t.Fatalf("token %q reused by both %q and %q", got, prev, tt.name)
			}
			seen[got] = tt.name
		})
	}

	canonical := canonicalEntities()
	if len(seen) != len(canonical) {
		t.Fatalf("this table covers %d kinds, canonicalEntities covers %d; a kind reaching one enumeration and not the other leaves half the fixtures blind to it", len(seen), len(canonical))
	}
	for _, e := range canonical {
		if _, covered := seen[e.Kind()]; !covered {
			t.Errorf("canonicalEntities carries Kind %q with no row here", e.Kind())
		}
	}
}
