package agentaudit

import (
	"reflect"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

// Whitebox so it can reach the unexported embeddedRules/defaultRulesDir. The
// Claude subset stays exhaustive while the shipped set spans several agents:
// a Claude rule deleted, renamed, or quietly re-scoped to another agent has to
// fail here. Each rule also passed ValidateRule's examples-as-spec harness
// inside Load itself.
func TestEmbeddedClaudeRulesLoad(t *testing.T) {
	rules := claudeRules(t)

	wantIDs := map[string]bool{
		"claude.hook.command":                        true,
		"claude.statusline.command":                  true,
		"claude.credential.api-key-helper":           true,
		"claude.credential.aws-auth-refresh":         true,
		"claude.credential.aws-credential-export":    true,
		"claude.mcp.server":                          true,
		"claude.mcp.headers-helper":                  true,
		"claude.env.anthropic-base-url":              true,
		"claude.env.egress-proxy":                    true,
		"claude.env.node-options":                    true,
		"claude.env.path":                            true,
		"claude.sandbox.dangerous-socket":            true,
		"claude.sandbox.unix-socket":                 true,
		"claude.permissions.permissive-default-mode": true,
		"claude.mcp.auto-approve":                    true,
		"claude.payload.referenced-script":           true,
		"claude.payload.bundled-script":              true,
		"claude.inline-shell.command":                true,
		"claude.plugin.installed":                    true,
		"claude.plugin.executable":                   true,
		"claude.plugin.lsp-server":                   true,
		"claude.preview.command":                     true,
		"claude.permissions.allowed-shell":           true,
	}
	if len(rules) != len(wantIDs) {
		t.Fatalf("claude rules len = %d, want %d", len(rules), len(wantIDs))
	}
	for _, r := range rules {
		if !wantIDs[r.ID] {
			t.Errorf("unexpected rule id %q loaded", r.ID)
		}
		delete(wantIDs, r.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("missing expected rule ids: %v", wantIDs)
	}
}

// claudeRules narrows the shipped multi-agent ruleset to the rules bound to
// Claude Code. An empty appliesTo means every agent, so it belongs to no
// agent's exhaustive list and is rejected rather than silently attributed.
func claudeRules(t *testing.T) []ruleeng.Rule {
	t.Helper()

	all, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	var claude []ruleeng.Rule
	for _, r := range all {
		if len(r.AppliesTo) == 0 {
			t.Errorf("rule %q declares no appliesTo, so it fires for every agent", r.ID)
			continue
		}
		if ruleeng.AppliesTo(r, string(adapter.AgentClaudeCode)) {
			claude = append(claude, r)
		}
	}
	return claude
}

func TestSandboxSocketRulesAreMutuallyExclusive(t *testing.T) {
	rules := claudeRules(t)

	entities := []ir.Entity{
		ir.Sandbox{SocketPath: "/var/run/docker.sock"},
		ir.Sandbox{SocketPath: "/tmp/app.sock"},
		ir.Sandbox{SocketPath: "/tmp/ssh-XXXXXXXXXX/agent.1234"},
	}
	wantRuleBySocket := map[string]string{
		"/var/run/docker.sock":           "claude.sandbox.dangerous-socket",
		"/tmp/app.sock":                  "claude.sandbox.unix-socket",
		"/tmp/ssh-XXXXXXXXXX/agent.1234": "claude.sandbox.dangerous-socket",
	}

	hits := ruleeng.Evaluate(rules, entities, "claude-code")

	gotRulesBySocket := map[string][]string{}
	for _, hit := range hits {
		sandbox, ok := hit.Entity.(ir.Sandbox)
		if !ok {
			continue
		}
		gotRulesBySocket[sandbox.SocketPath] = append(gotRulesBySocket[sandbox.SocketPath], hit.RuleID)
	}

	for socket, wantRule := range wantRuleBySocket {
		got := gotRulesBySocket[socket]
		if len(got) != 1 {
			t.Errorf("socket %q fired %d sandbox rules (%v), want exactly 1", socket, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("socket %q fired rule %q, want %q", socket, got[0], wantRule)
		}
	}
}

// A headersHelper copy fires claude.mcp.headers-helper alone.
func TestClaudeMCPRulesAreMutuallyExclusive(t *testing.T) {
	rules := claudeRules(t)

	entities := []ir.Entity{
		ir.MCPServer{Name: "stdio-only", Transport: ir.TransportStdio, Command: "npx"},
		ir.MCPServer{Name: "http-only", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp"},
		ir.MCPServer{Name: "helper-copy", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", HeadersHelper: "./scripts/headers.sh"},
		ir.MCPServer{Name: "no-transport"},
	}
	wantRulesByName := map[string][]string{
		"stdio-only":   {"claude.mcp.server"},
		"http-only":    {"claude.mcp.server"},
		"helper-copy":  {"claude.mcp.headers-helper"},
		"no-transport": nil,
	}

	hits := ruleeng.Evaluate(rules, entities, "claude-code")

	gotRulesByName := map[string][]string{}
	for _, hit := range hits {
		server, ok := hit.Entity.(ir.MCPServer)
		if !ok {
			continue
		}
		gotRulesByName[server.Name] = append(gotRulesByName[server.Name], hit.RuleID)
	}

	for name, want := range wantRulesByName {
		got := gotRulesByName[name]
		if len(got) != len(want) {
			t.Errorf("server %q fired %v, want %v", name, got, want)
			continue
		}
		for i, ruleID := range want {
			if got[i] != ruleID {
				t.Errorf("server %q fired %v, want %v", name, got, want)
				break
			}
		}
	}
}

// No shipped Claude rule cites docs.claude.com, which answers Claude Code's
// documentation paths with a redirect to code.claude.com. ValidateRule
// ignores what a reference contains, so a cite rots here or nowhere.
func TestNoClaudeRuleCitesTheMovedDocsHost(t *testing.T) {
	rules := claudeRules(t)

	const moved = "docs.claude.com"
	inspected := 0
	for _, rule := range rules {
		for _, ref := range rule.References {
			inspected++
			if strings.Contains(ref, moved) {
				t.Errorf("rule %q cites %q, which answers only by redirect", rule.ID, ref)
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no shipped Claude rule carries a reference, so this sweep asserts nothing")
	}
}

func TestBundledPayloadRulesAreMutuallyExclusive(t *testing.T) {
	rules := claudeRules(t)

	entities := []ir.Entity{
		ir.BundledPayload{Path: "a.sh", Referenced: "true"},
		ir.BundledPayload{Path: "b.sh"},
	}
	wantRuleByPath := map[string]string{
		"a.sh": "claude.payload.referenced-script",
		"b.sh": "claude.payload.bundled-script",
	}

	hits := ruleeng.Evaluate(rules, entities, "claude-code")

	gotRulesByPath := map[string][]string{}
	for _, hit := range hits {
		payload, ok := hit.Entity.(ir.BundledPayload)
		if !ok {
			continue
		}
		gotRulesByPath[payload.Path] = append(gotRulesByPath[payload.Path], hit.RuleID)
	}

	for path, wantRule := range wantRuleByPath {
		got := gotRulesByPath[path]
		if len(got) != 1 {
			t.Errorf("path %q fired %d payload rules (%v), want exactly 1", path, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("path %q fired rule %q, want %q", path, got[0], wantRule)
		}
	}
}

// A bypassPermissions a cloned repository checks in is dropped before the
// session starts: Claude Code ignores the value in a project
// .claude/settings.json and starts in Manual mode, and a subagent declaring
// it keeps the main conversation's mode instead. Claude Code honours
// acceptEdits at either key, so that mode still surfaces.
func TestClaudePermissionModeRuleSkipsBypassPermissions(t *testing.T) {
	rules := claudeRules(t)

	modes := []struct {
		name   string
		entity ir.PermissionMode
		want   []string
	}{
		{"settings bypass", ir.PermissionMode{Mode: "bypassPermissions", Source: "permissions.defaultMode"}, nil},
		{"subagent bypass", ir.PermissionMode{Mode: "bypassPermissions", Source: "permissionMode"}, nil},
		{"settings accept edits", ir.PermissionMode{Mode: "acceptEdits", Source: "permissions.defaultMode"}, []string{"claude.permissions.permissive-default-mode"}},
		{"subagent accept edits", ir.PermissionMode{Mode: "acceptEdits", Source: "permissionMode"}, []string{"claude.permissions.permissive-default-mode"}},
		{"plan", ir.PermissionMode{Mode: "plan", Source: "permissions.defaultMode"}, nil},
		{"manual", ir.PermissionMode{Mode: "default", Source: "permissions.defaultMode"}, nil},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{m.entity}, "claude-code") {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, m.want) {
				t.Fatalf("mode %+v fired %v, want %v", m.entity, got, m.want)
			}
		})
	}
}

// A preview server runs what its entry names, so an entry that names no
// command and no arguments, such as one that only attaches to a url, is not a
// capability.
func TestClaudePreviewRuleSkipsAnAttachOnlyEntry(t *testing.T) {
	rules := claudeRules(t)

	entries := []struct {
		name   string
		entity ir.PreviewServer
		want   []string
	}{
		{"attach only", ir.PreviewServer{Name: "attached", URL: "http://localhost:4000"}, nil},
		{"a command beside a url", ir.PreviewServer{Name: "web", Command: "npm", URL: "http://localhost:3000"}, []string{"claude.preview.command"}},
		{"arguments with no command", ir.PreviewServer{Name: "web", Args: []string{"run", "dev"}}, []string{"claude.preview.command"}},
		{"an empty command and no arguments", ir.PreviewServer{Name: "web", Command: "", Args: []string{}}, nil},
	}

	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{e.entity}, "claude-code") {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, e.want) {
				t.Fatalf("entry %+v fired %v, want %v", e.entity, got, e.want)
			}
		})
	}
}

// Only an exact Bash or PowerShell tool fires the allow rule, whatever its
// argument; a tool of another name, another case or a malformed spelling does
// not.
func TestClaudeAllowRuleFlagsOnlyShellEntries(t *testing.T) {
	rules := claudeRules(t)

	tests := []struct {
		name string
		perm ir.ToolPermission
		want []string
	}{
		{"bare Bash", ir.ToolPermission{Tool: "Bash"}, []string{"claude.permissions.allowed-shell"}},
		{"Bash prefix", ir.ToolPermission{Tool: "Bash", Argument: "npm run test:*"}, []string{"claude.permissions.allowed-shell"}},
		{"Bash exact", ir.ToolPermission{Tool: "Bash", Argument: "git status"}, []string{"claude.permissions.allowed-shell"}},
		{"bare PowerShell", ir.ToolPermission{Tool: "PowerShell"}, []string{"claude.permissions.allowed-shell"}},
		{"PowerShell command", ir.ToolPermission{Tool: "PowerShell", Argument: "Get-ChildItem *"}, []string{"claude.permissions.allowed-shell"}},
		{"WebFetch", ir.ToolPermission{Tool: "WebFetch", Argument: "domain:example.com"}, nil},
		{"Read", ir.ToolPermission{Tool: "Read", Argument: "./.env"}, nil},
		{"MCP tool", ir.ToolPermission{Tool: "mcp__github__create_issue"}, nil},
		{"unclosed Bash", ir.ToolPermission{Tool: "Bash(rm"}, nil},
		{"unclosed PowerShell", ir.ToolPermission{Tool: "PowerShell(ls"}, nil},
		{"lowercase bash", ir.ToolPermission{Tool: "bash", Argument: "ls"}, nil},
		{"lowercase powershell", ir.ToolPermission{Tool: "powershell", Argument: "ls"}, nil},
		{"leading space", ir.ToolPermission{Tool: " Bash", Argument: "ls"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{tt.perm}, "claude-code") {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rules fired = %v, want %v", got, tt.want)
			}
		})
	}
}
