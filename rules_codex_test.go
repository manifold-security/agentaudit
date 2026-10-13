package agentaudit

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

// Rule ids are namespaced by agent so a report reader can tell which agent's
// surface a finding came from without decoding the provenance.
func TestEmbeddedCodexRulesAreNamespaced(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	found := false
	for _, r := range rules {
		if len(r.AppliesTo) != 1 || r.AppliesTo[0] != string(adapter.AgentCodex) {
			continue
		}
		found = true
		if !strings.HasPrefix(r.ID, "codex.") {
			t.Errorf("rule %q applies to codex but is not in the codex. namespace", r.ID)
		}
	}
	if !found {
		t.Fatal("no shipped rule declares appliesTo codex; this guard checked nothing")
	}
}

// End to end through the facade: a sandbox grant declared in the agent's own
// file becomes a finding attributed to the Codex adapter.
func TestScanSurfacesACodexSandboxGrantFromTheShippedRules(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte("sandbox_mode = \"danger-full-access\"\n")},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Scan() findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.Agent != string(adapter.AgentCodex) {
		t.Errorf("Agent = %q, want %q", f.Agent, adapter.AgentCodex)
	}
	if f.RuleID != "codex.sandbox.full-access" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "codex.sandbox.full-access")
	}
	if got := f.Capability.Provenance.File; got != ".codex/config.toml" {
		t.Errorf("Provenance.File = %q, want %q", got, ".codex/config.toml")
	}
}

// A Codex rule must not fire on another agent's source, or a repository
// configured for more than one agent reports one grant under several ids.
func TestScanKeepsTheCodexAndOtherRulesetsApart(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json":          &fstest.MapFile{Data: []byte(`{"mcpServers":{"claude-side":{"command":"npx"}}}`)},
		".cursor/mcp.json":   &fstest.MapFile{Data: []byte(`{"mcpServers":{"cursor-side":{"command":"npx"}}}`)},
		".codex/config.toml": &fstest.MapFile{Data: []byte("sandbox_mode = \"danger-full-access\"\n")},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	byAgent := map[string][]string{}
	for _, f := range report.Findings() {
		byAgent[f.Agent] = append(byAgent[f.Agent], f.RuleID)
	}
	for agent, ids := range byAgent {
		for _, id := range ids {
			if !strings.HasPrefix(id, agentNamespace(agent)) {
				t.Errorf("agent %q fired rule %q, which belongs to another agent", agent, id)
			}
		}
	}
	want := map[string]int{
		string(adapter.AgentClaudeCode): 1,
		string(adapter.AgentCursor):     1,
		string(adapter.AgentCodex):      1,
	}
	for agent, n := range want {
		if len(byAgent[agent]) != n {
			t.Fatalf("findings by agent = %v, want %d from %q", byAgent, n, agent)
		}
	}
}

// The sandbox rules share one target, so their claims have to stay disjoint:
// a second finding over one entity renders as a duplicate line in the pretty
// view without --explain.
func TestCodexSandboxRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	grants := []struct {
		entity    ir.Entity
		key       string
		wantRules []string
	}{
		{ir.Sandbox{Mode: "danger-full-access"}, "danger-full-access", []string{"codex.sandbox.full-access"}},
		{ir.Sandbox{Mode: "workspace-write"}, "workspace-write", nil},
		{ir.Sandbox{Path: "~/.ssh", Access: "readwrite"}, "~/.ssh", []string{"codex.sandbox.writable-root"}},
		{ir.NetworkPolicy{Default: "true"}, "true", []string{"codex.network.sandbox-network-access"}},
	}

	var entities []ir.Entity
	wantRulesByKey := map[string][]string{}
	for _, g := range grants {
		entities = append(entities, g.entity)
		wantRulesByKey[g.key] = g.wantRules
	}

	gotRulesByKey := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCodex)) {
		var key string
		switch v := hit.Entity.(type) {
		case ir.Sandbox:
			key = v.Mode + v.Path
		case ir.NetworkPolicy:
			key = v.Default + v.Pattern
		default:
			continue
		}
		gotRulesByKey[key] = append(gotRulesByKey[key], hit.RuleID)
	}

	for key, wantRules := range wantRulesByKey {
		if got := gotRulesByKey[key]; !reflect.DeepEqual(got, wantRules) {
			t.Errorf("grant %q fired %v, want %v", key, got, wantRules)
		}
	}
}

// The profile model declares the same postures the sandbox keys do, so a
// grant reaches at most one rule however it is spelled.
func TestCodexPermissionProfileRulesAreDisjointFromTheSandboxRules(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	grants := []struct {
		name      string
		entity    ir.Entity
		wantRules []string
	}{
		{"full-access profile", ir.PermissionMode{Mode: ":danger-full-access", Source: "default_permissions"}, []string{"codex.permissions.profile-full-access"}},
		{"workspace profile", ir.PermissionMode{Mode: ":workspace", Source: "default_permissions"}, nil},
		{"read-only profile", ir.PermissionMode{Mode: ":read-only", Source: "extends"}, nil},
		{"named profile", ir.PermissionMode{Mode: "project-edit", Source: "default_permissions"}, nil},
		{"workspace root", ir.Sandbox{Path: "~/code/app", Access: "workspace_root"}, []string{"codex.permissions.workspace-root"}},
		{"filesystem write", ir.Sandbox{Path: "~/.local/bin", Access: "write"}, []string{"codex.permissions.filesystem-write"}},
		{"filesystem read", ir.Sandbox{Path: "~/.aws/credentials", Access: "read"}, []string{"codex.permissions.filesystem-read"}},
		{"unix socket", ir.Sandbox{SocketPath: "/var/run/docker.sock"}, []string{"codex.permissions.unix-socket"}},
		{"profile egress", ir.NetworkPolicy{Default: "enabled"}, []string{"codex.permissions.network-enabled"}},
		{"allowed domain", ir.NetworkPolicy{Pattern: "api.example.com"}, []string{"codex.permissions.network-domain"}},
		{"sandbox mode", ir.Sandbox{Mode: "danger-full-access"}, []string{"codex.sandbox.full-access"}},
		{"writable root", ir.Sandbox{Path: "/", Access: "readwrite"}, []string{"codex.sandbox.writable-root"}},
		{"sandbox egress", ir.NetworkPolicy{Default: "true"}, []string{"codex.network.sandbox-network-access"}},
		{"blanket policy", ir.PermissionMode{Mode: "never", Source: "approval_policy"}, []string{"codex.approval.never"}},
		{"local binding", ir.NetworkPolicy{Default: "allow_local_binding"}, []string{"codex.network.local-binding"}},
		{"every unix socket", ir.NetworkPolicy{Default: "dangerously_allow_all_unix_sockets"}, []string{"codex.network.all-unix-sockets"}},
		{"non-loopback proxy", ir.NetworkPolicy{Default: "dangerously_allow_non_loopback_proxy"}, []string{"codex.network.non-loopback-proxy"}},
	}

	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{g.entity}, string(adapter.AgentCodex)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, g.wantRules) {
				t.Fatalf("grant %+v fired %v, want %v", g.entity, got, g.wantRules)
			}
		})
	}
}

// A profile's path grant reaches a rule by how its path is spelled.
func TestCodexProfilePathRuleBoundaries(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	const (
		readRule  = "codex.permissions.filesystem-read"
		writeRule = "codex.permissions.filesystem-write"
		rootRule  = "codex.permissions.workspace-root"
	)

	grants := []struct {
		path      string
		access    string
		wantRules []string
	}{
		{"~/.ssh", "read", []string{readRule}},
		{"~/.ssh/id_rsa", "read", []string{readRule}},
		{"$HOME/.ssh", "read", []string{readRule}},
		{"/Users/you/.ssh", "read", []string{readRule}},
		{"/home/ci/.aws/credentials", "read", []string{readRule}},
		{"~/.gnupg", "read", []string{readRule}},
		{"~/.kube/config", "read", []string{readRule}},
		{"~/.docker/config.json", "read", []string{readRule}},
		{"~/.netrc", "read", []string{readRule}},
		{"~/.npmrc", "read", []string{readRule}},
		{"~/.git-credentials", "read", []string{readRule}},
		{"~/.config/gh/hosts.yml", "read", []string{readRule}},
		{"~/.azure/credentials", "read", []string{readRule}},
		{"~/.config/gcloud/credentials.db", "read", []string{readRule}},
		{"~/.pypirc", "read", []string{readRule}},
		{"~/.pgpass", "read", []string{readRule}},
		{"/", "read", []string{readRule}},
		{"~", "read", []string{readRule}},
		{"$HOME", "read", []string{readRule}},
		{"~/", "read", []string{readRule}},
		{":root", "read", []string{readRule}},
		{":workspace", "read", nil},
		{".", "read", nil},
		{"./src", "read", nil},
		{"src/main.go", "read", nil},
		{"~/projects/app", "read", []string{readRule}},
		{"~/Documents", "read", []string{readRule}},
		{"/etc/hosts", "read", []string{readRule}},
		{"/var/log", "read", []string{readRule}},
		{".env", "read", nil},
		{"**/*.env", "read", nil},
		{"/Users/you/code/.sshconfig", "read", []string{readRule}},
		{"/Users/you", "read", []string{readRule}},
		{"/root/.ssh", "read", []string{readRule}},
		{`~\.ssh`, "read", []string{readRule}},
		{`~\.aws\credentials`, "read", []string{readRule}},
		{`C:\Users\you\.ssh`, "read", []string{readRule}},
		{`C:\`, "read", []string{readRule}},
		{`C:\Users\you\code\.sshconfig`, "read", []string{readRule}},
		{`src\main.go`, "read", nil},
		{"~/.sshconfig", "read", []string{readRule}},
		{"/Users/dev/projects/app/.aws", "read", []string{readRule}},
		{"/etc", "write", []string{writeRule}},
		{"~/.ssh", "write", []string{writeRule}},
		{".", "write", nil},
		{"./src", "write", nil},
		{"src", "write", nil},
		{"**/*.ts", "write", nil},
		{"$HOME/.aws", "write", []string{writeRule}},
		{":root", "write", []string{writeRule}},
		{":workspace", "write", nil},
		{`C:\Windows\System32`, "write", []string{writeRule}},
		{`~\work`, "write", []string{writeRule}},
		{`src\gen`, "write", nil},
		{"/", "workspace_root", []string{rootRule}},
		{"~", "workspace_root", []string{rootRule}},
		{"/Users/you/projects", "workspace_root", []string{rootRule}},
		{".", "workspace_root", nil},
		{"$HOME", "workspace_root", []string{rootRule}},
		{`C:\work`, "workspace_root", []string{rootRule}},
		{":root", "workspace_root", nil},
	}

	for _, g := range grants {
		t.Run(g.access+" "+g.path, func(t *testing.T) {
			entity := ir.Sandbox{Path: g.path, Access: g.access}
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{entity}, string(adapter.AgentCodex)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, g.wantRules) {
				t.Fatalf("grant %+v fired %v, want %v", entity, got, g.wantRules)
			}
		})
	}
}

// End to end through the facade: the profile a repository selects becomes a
// finding under the key that selected it.
func TestScanSurfacesACodexPermissionProfileFromTheShippedRules(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte("default_permissions = \":danger-full-access\"\n")},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Scan() findings = %+v, want exactly one", findings)
	}
	f := findings[0]
	if f.RuleID != "codex.permissions.profile-full-access" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "codex.permissions.profile-full-access")
	}
	if got := f.Capability.Provenance.Key; got != "default_permissions" {
		t.Errorf("Provenance.Key = %q, want %q", got, "default_permissions")
	}
}

// End to end through the facade: the approval rule reads the token under the
// approval key and not the same token under a profile name.
func TestScanJudgesACodexApprovalTokenByTheKeyThatDeclaredIt(t *testing.T) {
	cases := []struct {
		name      string
		config    string
		wantRules []string
	}{
		{
			name:      "custom profile named for the token",
			config:    "default_permissions = \"never\"\n\n[permissions.never]\nextends = \":read-only\"\n",
			wantRules: nil,
		},
		{
			name:      "the approval key itself",
			config:    "approval_policy = \"never\"\n",
			wantRules: []string{"codex.approval.never"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				".codex/config.toml": &fstest.MapFile{Data: []byte(tt.config)},
			}

			report, err := New().Scan(fsys)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}

			var got []string
			for _, f := range report.Findings() {
				got = append(got, f.RuleID)
			}
			if !reflect.DeepEqual(got, tt.wantRules) {
				t.Fatalf("Scan() findings = %v, want %v", got, tt.wantRules)
			}
		})
	}
}

// Every grant a profile declares reaches its own finding, keyed by the entry
// that declared it: one finding for the whole table would name a single path
// and drop the rest.
func TestScanSurfacesEveryCodexProfileGrant(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte(
			"[permissions.p.workspace_roots]\n\"~/code/app\" = true\n" +
				"[permissions.p.filesystem]\n\"~/.aws/credentials\" = \"read\"\n\"**/*.env\" = \"deny\"\n" +
				"[permissions.p.network]\nenabled = true\n" +
				"[permissions.p.network.domains]\n\"api.example.com\" = \"allow\"\n\"tracking.example.net\" = \"deny\"\n",
		)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		got[f.Capability.Provenance.Key] = f.RuleID
	}
	want := map[string]string{
		"permissions.p.workspace_roots.~/code/app":      "codex.permissions.workspace-root",
		"permissions.p.filesystem.~/.aws/credentials":   "codex.permissions.filesystem-read",
		"permissions.p.network.enabled":                 "codex.permissions.network-enabled",
		"permissions.p.network.domains.api.example.com": "codex.permissions.network-domain",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("profile findings = %+v, want %+v", got, want)
	}
}

// Neither the prompting policy nor the granular table declares a capability.
func TestCodexApprovalRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	wantRulesByMode := map[string][]string{
		"never":      {"codex.approval.never"},
		"granular":   nil,
		"on-request": nil,
	}

	var entities []ir.Entity
	for mode := range wantRulesByMode {
		entities = append(entities, ir.PermissionMode{Mode: mode, Source: "approval_policy"})
	}

	gotRulesByMode := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCodex)) {
		p, isMode := hit.Entity.(ir.PermissionMode)
		if !isMode {
			continue
		}
		gotRulesByMode[p.Mode] = append(gotRulesByMode[p.Mode], hit.RuleID)
	}

	for mode, wantRules := range wantRulesByMode {
		if !reflect.DeepEqual(gotRulesByMode[mode], wantRules) {
			t.Errorf("mode %q fired %v, want %v", mode, gotRulesByMode[mode], wantRules)
		}
	}
}

// Every writable root the file lists reaches its own finding, keyed by the
// element that declared it: one finding for the whole array would name a
// single path and drop the rest.
func TestScanSurfacesEveryCodexWritableRoot(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte(
			"[sandbox_workspace_write]\nwritable_roots = [\"/\", \"~/.aws\"]\n",
		)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		s, isSandbox := f.Capability.Entity.(ir.Sandbox)
		if !isSandbox {
			t.Fatalf("finding %+v does not carry an ir.Sandbox", f)
		}
		got[f.Capability.Provenance.Key] = s.Path + "|" + f.RuleID
	}
	want := map[string]string{
		"sandbox_workspace_write.writable_roots[0]": "/|codex.sandbox.writable-root",
		"sandbox_workspace_write.writable_roots[1]": "~/.aws|codex.sandbox.writable-root",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("writable-root findings = %+v, want %+v", got, want)
	}
}

// Each grant this document makes reaches its own finding under the entry
// that declared it, and a guard spelled in both the proxy table and a
// profile's network table reaches the same rule from either place. The
// web-search allowed_domains array is in the document and in no finding.
func TestScanSurfacesEveryCodexNetworkReachGrant(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte(
			"[features.network_proxy]\nenabled = true\nproxy_url = \"http://127.0.0.1:3128\"\n" +
				"allow_local_binding = true\nallow_upstream_proxy = true\n" +
				"dangerously_allow_all_unix_sockets = true\ndangerously_allow_non_loopback_proxy = true\n" +
				"[features.network_proxy.domains]\n\"**.example.com\" = \"allow\"\n\"tracking.example.net\" = \"deny\"\n" +
				"[features.network_proxy.unix_sockets]\n\"/var/run/docker.sock\" = \"allow\"\n\"/tmp/old.sock\" = \"deny\"\n" +
				"[permissions.release.network]\nallow_local_binding = true\n" +
				"[tools.web_search]\nallowed_domains = [\"docs.example.org\"]\n",
		)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		got[f.Capability.Provenance.Key] = f.RuleID
	}
	want := map[string]string{
		"features.network_proxy.domains.**.example.com":               "codex.permissions.network-domain",
		"features.network_proxy.unix_sockets./var/run/docker.sock":    "codex.permissions.unix-socket",
		"features.network_proxy.allow_local_binding":                  "codex.network.local-binding",
		"features.network_proxy.dangerously_allow_all_unix_sockets":   "codex.network.all-unix-sockets",
		"features.network_proxy.dangerously_allow_non_loopback_proxy": "codex.network.non-loopback-proxy",
		"permissions.release.network.allow_local_binding":             "codex.network.local-binding",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("network findings = %+v, want %+v", got, want)
	}
}

// No shipped rule cites openai/codex's docs/config.md, which hands the
// configuration reference off to developers.openai.com.
func TestNoRuleCitesTheGitHubCodexConfigPage(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	const handedOff = "github.com/openai/codex/blob/main/docs/config.md"
	inspected := 0
	for _, r := range rules {
		for _, ref := range r.References {
			inspected++
			if strings.Contains(ref, handedOff) {
				t.Errorf("rule %q cites %q, which hands the reference off elsewhere", r.ID, ref)
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no shipped rule carries a reference; a sweep over nothing asserts nothing")
	}
}

// A message naming only the proxy would be false where a permission
// profile's network table lifts the same guard, so each message leads with
// the condition the two paths share and then names the key the document
// wrote.
func TestCodexNetworkGuardMessagesLeadWithTheSandboxedNetworkingCondition(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte(
			"[features.network_proxy]\n" +
				"dangerously_allow_all_unix_sockets = true\ndangerously_allow_non_loopback_proxy = true\n" +
				"[permissions.release.network]\nallow_local_binding = true\n",
		)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	const condition = "With sandboxed networking enabled, "
	seen := map[string]bool{}
	for _, f := range report.Findings() {
		key := f.Capability.Provenance.Key
		name := key[strings.LastIndex(key, ".")+1:]
		seen[f.RuleID] = true
		if !strings.HasPrefix(f.Message, condition+name+" ") {
			t.Errorf("finding %q at %s Message = %q, want it to open with %q", f.RuleID, key, f.Message, condition+name)
		}
	}
	want := []string{
		"codex.network.local-binding",
		"codex.network.all-unix-sockets",
		"codex.network.non-loopback-proxy",
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("rule %q did not fire; its message was never inspected", id)
		}
	}
}

// The other agents' hook rules stay out of a Codex scan.
func TestCodexHookRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	hooks := []struct {
		name      string
		entity    ir.Hook
		wantRules []string
	}{
		{"command", ir.Hook{Event: "PreToolUse", Matcher: "Bash", Command: "./gate.sh"}, []string{"codex.hook.command"}},
		{"mcp tool", ir.Hook{Event: "PostToolUse", MCPServer: "release-index", MCPTool: "record"}, []string{"codex.hook.mcp-tool"}},
		{"command beside a tool", ir.Hook{Event: "Stop", Command: "./ok.sh", MCPServer: "audit", MCPTool: "log"}, []string{"codex.hook.command"}},
		{"neither", ir.Hook{Event: "SessionStart"}, nil},
	}
	for _, h := range hooks {
		t.Run(h.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{h.entity}, string(adapter.AgentCodex)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, h.wantRules) {
				t.Fatalf("hook %+v fired %v, want %v", h.entity, got, h.wantRules)
			}
		})
	}
}

// A tree whose only Codex file is hooks.json still activates the adapter,
// and each runnable handler reaches its own finding under the key that
// declared it.
func TestScanSurfacesEveryCodexHookFromAHooksFileAlone(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/hooks.json": &fstest.MapFile{Data: []byte(`{"hooks": {
  "PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": "./gate.sh", "commandWindows": "gate.cmd"},
    {"type": "prompt", "prompt": "Is this safe?"}
  ]}],
  "PostToolUse": [{"hooks": [{"type": "mcp_tool", "server": "release-index", "tool": "record"}]}]
}}`)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		if f.Agent != string(adapter.AgentCodex) {
			t.Errorf("finding %q attributed to %q, want %q", f.RuleID, f.Agent, adapter.AgentCodex)
		}
		got[f.Capability.Provenance.File+":"+f.Capability.Provenance.Key] = f.RuleID
	}
	want := map[string]string{
		".codex/hooks.json:hooks.PreToolUse[0].hooks[0]":                "codex.hook.command",
		".codex/hooks.json:hooks.PreToolUse[0].hooks[0].commandWindows": "codex.hook.command",
		".codex/hooks.json:hooks.PostToolUse[0].hooks[0]":               "codex.hook.mcp-tool",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hook findings = %+v, want %+v", got, want)
	}
}

// The other agents' MCP rules stay out of a Codex scan.
func TestCodexMCPRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	servers := []struct {
		name      string
		entity    ir.MCPServer
		wantRules []string
	}{
		{"server", ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://a"}, []string{"codex.mcp.server"}},
		{"both endpoints", ir.MCPServer{Name: "docs", Transport: ir.TransportStdio, Command: "npx", URL: "https://a"}, []string{"codex.mcp.server"}},
		{"headers helper", ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://a", HeadersHelper: "./h.sh"}, []string{"codex.mcp.headers-helper"}},
		{"forwarded env", ir.MCPServer{Name: "docs", Transport: ir.TransportStdio, Command: "npx", ForwardedEnv: "TOKEN"}, []string{"codex.mcp.env-forward"}},
		{"helper beside a variable", ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://a", HeadersHelper: "./h.sh", ForwardedEnv: "TOKEN"}, []string{"codex.mcp.headers-helper"}},
		{"no transport", ir.MCPServer{Name: "docs"}, nil},
	}
	for _, s := range servers {
		t.Run(s.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{s.entity}, string(adapter.AgentCodex)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, s.wantRules) {
				t.Fatalf("server %+v fired %v, want %v", s.entity, got, s.wantRules)
			}
		})
	}
}

// Each server, helper and locally sourced variable reaches its own finding
// under the key that declared it, and a disabled server and a remote-sourced
// variable reach none while their enabled and local siblings do.
func TestScanSurfacesEveryCodexMCPCapability(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte(`[mcp_servers.docs]
url = "https://mcp.example.test/mcp"
bearer_token_env_var = "DOCS_TOKEN"
env_http_headers = { "X-Team" = "TEAM_ID" }
http_headers_helper = "./scripts/headers.sh"

[mcp_servers.index]
command = "npx"
env_vars = ["LOCAL_TOKEN", { name = "REMOTE_TOKEN", source = "remote" }]

[mcp_servers.off]
enabled = false
command = "./off.sh"
env_vars = ["OFF_TOKEN"]
`)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		if f.Agent != string(adapter.AgentCodex) {
			t.Errorf("finding %q attributed to %q, want %q", f.RuleID, f.Agent, adapter.AgentCodex)
		}
		got[f.Capability.Provenance.Key] = f.RuleID
	}
	want := map[string]string{
		"mcp_servers.docs":                         "codex.mcp.server",
		"mcp_servers.docs.bearer_token_env_var":    "codex.mcp.env-forward",
		"mcp_servers.docs.env_http_headers.X-Team": "codex.mcp.env-forward",
		"mcp_servers.docs.http_headers_helper":     "codex.mcp.headers-helper",
		"mcp_servers.index":                        "codex.mcp.server",
		"mcp_servers.index.env_vars[0]":            "codex.mcp.env-forward",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mcp findings = %+v, want %+v", got, want)
	}
}

// A script a skill bundles reaches exactly the Codex skill-script rule, and
// the other agents' payload rules stay out of a Codex scan.
func TestCodexSkillScriptRuleClaimsOnlyASkillsScripts(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	payloads := []struct {
		name      string
		entity    ir.BundledPayload
		wantRules []string
	}{
		{"skill script", ir.BundledPayload{Path: ".agents/skills/ship/scripts/ship.sh", Extension: ".sh", Origin: "skill"}, []string{"codex.payload.skill-script"}},
		{"executable skill script", ir.BundledPayload{Path: ".agents/skills/ship/scripts/ship", Executable: "true", Origin: "skill"}, []string{"codex.payload.skill-script"}},
		{"hook payload", ir.BundledPayload{Path: ".cursor/hooks/run.sh", Extension: ".sh", Origin: "hook"}, nil},
		{"unclassified payload", ir.BundledPayload{Path: ".claude/skills/demo/run.sh", Extension: ".sh"}, nil},
	}
	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{p.entity}, string(adapter.AgentCodex)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, p.wantRules) {
				t.Fatalf("payload %+v fired %v, want %v", p.entity, got, p.wantRules)
			}
		})
	}
}

// A tree whose only Codex surface is a skill still activates the adapter,
// and each script the skill bundles reaches its own finding located by its
// own path.
func TestScanSurfacesEveryCodexSkillScriptFromASkillsTreeAlone(t *testing.T) {
	fsys := fstest.MapFS{
		".agents/skills/ship/SKILL.md":              &fstest.MapFile{Data: []byte("---\nname: ship\ndescription: ship it\n---\n")},
		".agents/skills/ship/scripts/ship.sh":       &fstest.MapFile{Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		".agents/skills/ship/scripts/lib/notify.py": &fstest.MapFile{Data: []byte("print(1)\n")},
		".agents/skills/ship/references/guide.md":   &fstest.MapFile{Data: []byte("# guide\n")},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		if f.Agent != string(adapter.AgentCodex) {
			t.Errorf("finding %q attributed to %q, want %q", f.RuleID, f.Agent, adapter.AgentCodex)
		}
		got[f.Capability.Provenance.File] = f.RuleID
	}
	want := map[string]string{
		".agents/skills/ship/scripts/ship.sh":       "codex.payload.skill-script",
		".agents/skills/ship/scripts/lib/notify.py": "codex.payload.skill-script",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skill findings = %+v, want %+v", got, want)
	}
}

// A trusted project in a global config reaches no finding: the projects
// table records trust decisions the user already made, not a capability a
// scanned repository could have planted there. The companion arm shows the
// global pass still reaching the shipped rules through the same file.
func TestScanGlobalSurfacesNoFindingForACodexTrustedProject(t *testing.T) {
	fsys := fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte("[projects.\"/repo/alpha\"]\ntrust_level = \"trusted\"\n")},
	}

	report, err := New().ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if findings := report.Findings(); len(findings) != 0 {
		t.Fatalf("ScanGlobal() findings = %+v, want none", findings)
	}

	fsys[".codex/config.toml"] = &fstest.MapFile{Data: []byte(
		"sandbox_mode = \"danger-full-access\"\n\n[projects.\"/repo/alpha\"]\ntrust_level = \"trusted\"\n",
	)}

	report, err = New().ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("ScanGlobal() findings = %+v, want exactly the sandbox grant", findings)
	}
	if findings[0].RuleID != "codex.sandbox.full-access" {
		t.Errorf("RuleID = %q, want %q", findings[0].RuleID, "codex.sandbox.full-access")
	}
}

func TestScanGlobalMalformedCodexConfigDegradesWithExactlyOneWarning(t *testing.T) {
	fsys := fstest.MapFS{".codex/config.toml": &fstest.MapFile{Data: []byte("sandbox_mode = \n")}}

	var warnings []error
	s := New(WithWarnFunc(func(e error) { warnings = append(warnings, e) }))
	report, err := s.ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly 1", warnings)
	}
	if !strings.Contains(warnings[0].Error(), ".codex/config.toml") {
		t.Fatalf("warning = %q, want it to name .codex/config.toml", warnings[0])
	}
	if report.UnreadableSources() != 0 || report.UnparsedSources() != 1 {
		t.Fatalf("UnreadableSources()=%d UnparsedSources()=%d, want 0 and 1", report.UnreadableSources(), report.UnparsedSources())
	}
}
