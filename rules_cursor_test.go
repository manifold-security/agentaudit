package agentaudit

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/registry"
	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

// An adapter wired with no shipped rule emits entities nothing can match, so
// its whole surface goes unreported while the scan still exits clean.
func TestEveryWiredAgentHasAShippedRule(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	byAgent := map[string]bool{}
	for _, r := range rules {
		for _, id := range r.AppliesTo {
			byAgent[id] = true
		}
	}
	for _, a := range registry.Adapters() {
		if !byAgent[string(a.Agent())] {
			t.Errorf("the default ruleset carries no rule declaring appliesTo %q", a.Agent())
		}
	}
}

func TestEmbeddedCursorRulesAreNamespaced(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	found := false
	for _, r := range rules {
		if len(r.AppliesTo) != 1 || r.AppliesTo[0] != string(adapter.AgentCursor) {
			continue
		}
		found = true
		if !strings.HasPrefix(r.ID, "cursor.") {
			t.Errorf("rule %q applies to cursor but is not in the cursor. namespace", r.ID)
		}
	}
	if !found {
		t.Fatal("no shipped rule declares appliesTo cursor; this guard checked nothing")
	}
}

// End to end through the facade: a Cursor MCP server declared in the agent's
// own file becomes a finding attributed to the Cursor adapter.
func TestScanSurfacesACursorMCPServerFromTheShippedRules(t *testing.T) {
	fsys := fstest.MapFS{
		".cursor/mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"build-tool":{"command":"/usr/local/bin/build"}}}`)},
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
	if f.Agent != string(adapter.AgentCursor) {
		t.Errorf("Agent = %q, want %q", f.Agent, adapter.AgentCursor)
	}
	if !strings.HasPrefix(f.RuleID, "cursor.") {
		t.Errorf("RuleID = %q, want a cursor. rule", f.RuleID)
	}
	if got := f.Capability.Provenance.File; got != ".cursor/mcp.json" {
		t.Errorf("Provenance.File = %q, want %q", got, ".cursor/mcp.json")
	}
}

// A Cursor rule must not fire on a Claude source, or every repository
// carrying both agents reports each server twice.
func TestScanKeepsTheCursorAndClaudeRulesetsApart(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json":        &fstest.MapFile{Data: []byte(`{"mcpServers":{"claude-side":{"command":"npx"}}}`)},
		".cursor/mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"cursor-side":{"command":"npx"}}}`)},
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
	if len(byAgent[string(adapter.AgentCursor)]) != 1 || len(byAgent[string(adapter.AgentClaudeCode)]) != 1 {
		t.Fatalf("findings by agent = %v, want one from each side", byAgent)
	}
}

func agentNamespace(agent string) string {
	if agent == string(adapter.AgentClaudeCode) {
		return "claude."
	}
	return agent + "."
}

// The cursor.hook.workspace-open and cursor.hook.command rules never fire on
// the same ir.Hook: a second finding over one entity renders as a duplicate
// line in the pretty view without --explain.
func TestCursorHookRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	entities := []ir.Entity{
		ir.Hook{Event: "workspaceOpen", Command: "./boot.sh"},
		ir.Hook{Event: "beforeShellExecution", Command: "./gate.sh"},
	}
	wantRuleByEvent := map[string]string{
		"workspaceOpen":        "cursor.hook.workspace-open",
		"beforeShellExecution": "cursor.hook.command",
	}

	gotRulesByEvent := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		hook, ok := hit.Entity.(ir.Hook)
		if !ok {
			continue
		}
		gotRulesByEvent[hook.Event] = append(gotRulesByEvent[hook.Event], hit.RuleID)
	}

	for event, wantRule := range wantRuleByEvent {
		got := gotRulesByEvent[event]
		if len(got) != 1 {
			t.Errorf("event %q fired %d hook rules (%v), want exactly 1", event, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("event %q fired rule %q, want %q", event, got[0], wantRule)
		}
	}
}

func TestCursorProvisionerRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	wantRuleByPhase := map[string]string{
		"install":                  "cursor.provisioner.environment-command",
		"start":                    "cursor.provisioner.environment-command",
		"terminals":                "cursor.provisioner.environment-command",
		"build.dockerfile":         "cursor.provisioner.environment-image",
		"build.dockerfileContents": "cursor.provisioner.environment-image",
		"setup-worktree":           "cursor.provisioner.worktree-setup",
		"setup-worktree-unix":      "cursor.provisioner.worktree-setup",
		"setup-worktree-windows":   "cursor.provisioner.worktree-setup",
	}

	var entities []ir.Entity
	for phase := range wantRuleByPhase {
		entities = append(entities, ir.Provisioner{Phase: phase, Command: "./payload.sh"})
	}

	gotRulesByPhase := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		p, ok := hit.Entity.(ir.Provisioner)
		if !ok {
			continue
		}
		gotRulesByPhase[p.Phase] = append(gotRulesByPhase[p.Phase], hit.RuleID)
	}

	for phase, wantRule := range wantRuleByPhase {
		got := gotRulesByPhase[phase]
		if len(got) != 1 {
			t.Errorf("phase %q fired %d provisioner rules (%v), want exactly 1", phase, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("phase %q fired rule %q, want %q", phase, got[0], wantRule)
		}
	}
}

func TestCursorSandboxRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	grants := []struct {
		entity   ir.Entity
		key      string
		wantRule string
	}{
		{ir.Sandbox{Mode: "insecure_none"}, "insecure_none", "cursor.sandbox.disabled"},
		{ir.Sandbox{Path: "~/.aws", Access: "readwrite"}, "~/.aws", "cursor.sandbox.writable-path"},
		{ir.Sandbox{Path: "~/.ssh", Access: "readonly"}, "~/.ssh", "cursor.sandbox.readable-path"},
		{ir.NetworkPolicy{Default: "allow"}, "allow", "cursor.network.egress-allowed-by-default"},
		{ir.NetworkPolicy{Pattern: "*.example.com"}, "*.example.com", "cursor.network.egress-allowed-pattern"},
	}

	var entities []ir.Entity
	wantRuleByKey := map[string]string{}
	for _, g := range grants {
		entities = append(entities, g.entity)
		wantRuleByKey[g.key] = g.wantRule
	}

	gotRulesByKey := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
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

	for key, wantRule := range wantRuleByKey {
		got := gotRulesByKey[key]
		if len(got) != 1 {
			t.Errorf("grant %q fired %d sandbox rules (%v), want exactly 1", key, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("grant %q fired rule %q, want %q", key, got[0], wantRule)
		}
	}
}

// Cursor's default sandbox type grants the workspace, and the path keys
// list what is extra to it, so a workspace-relative entry names reach the
// agent already has and fires no rule.
func TestCursorSandboxPathRuleBoundaries(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	const (
		writeRule = "cursor.sandbox.writable-path"
		readRule  = "cursor.sandbox.readable-path"
	)

	grants := []struct {
		path      string
		access    string
		wantRules []string
	}{
		{"~/.ssh", "readwrite", []string{writeRule}},
		{"~/.aws", "readwrite", []string{writeRule}},
		{"$HOME/.config", "readwrite", []string{writeRule}},
		{"/etc", "readwrite", []string{writeRule}},
		{"/opt/tools", "readwrite", []string{writeRule}},
		{"/", "readwrite", []string{writeRule}},
		{`C:\Windows\System32`, "readwrite", []string{writeRule}},
		{`~\work`, "readwrite", []string{writeRule}},
		{"", "readwrite", nil},
		{".", "readwrite", nil},
		{"./build", "readwrite", nil},
		{"node_modules", "readwrite", nil},
		{"src/gen", "readwrite", nil},
		{"**/*.ts", "readwrite", nil},
		{":root", "readwrite", nil},
		{"~/.ssh", "readonly", []string{readRule}},
		{"~/.config/gcloud", "readonly", []string{readRule}},
		{"~/.aws/credentials", "readonly", []string{readRule}},
		{"$HOME/.netrc", "readonly", []string{readRule}},
		{"/home/ci/.gnupg", "readonly", []string{readRule}},
		{`C:\Users\you\.aws\credentials`, "readonly", []string{readRule}},
		{"/", "readonly", []string{readRule}},
		{"~", "readonly", []string{readRule}},
		{"", "readonly", nil},
		{".", "readonly", nil},
		{"./docs", "readonly", nil},
		{"vendor", "readonly", nil},
		{"/etc/hosts", "readonly", []string{readRule}},
		{"/opt/tools", "readonly", []string{readRule}},
		{"~/Documents", "readonly", []string{readRule}},
		{"~/.sshconfig", "readonly", []string{readRule}},
		{":root", "readonly", nil},
	}

	for _, g := range grants {
		t.Run(g.access+" "+g.path, func(t *testing.T) {
			entity := ir.Sandbox{Path: g.path, Access: g.access}
			var got []string
			for _, hit := range ruleeng.Evaluate(rules, []ir.Entity{entity}, string(adapter.AgentCursor)) {
				got = append(got, hit.RuleID)
			}
			if !reflect.DeepEqual(got, g.wantRules) {
				t.Fatalf("grant %+v fired %v, want %v", entity, got, g.wantRules)
			}
		})
	}
}

// Each sandbox and egress token below fires the one shipped rule that
// claims it, or nothing where no shipped rule claims it. disabled and
// allow_all are the CLI vocabulary, which no shipped rule reads.
func TestCursorSandboxAndNetworkTokensFireOnlyTheRuleThatClaimsThem(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	grants := []struct {
		entity   ir.Entity
		key      string
		wantRule string // empty where no shipped rule claims the token
	}{
		{ir.Sandbox{Mode: "disabled"}, "disabled", ""},
		{ir.Sandbox{Mode: "insecure_none"}, "insecure_none", "cursor.sandbox.disabled"},
		{ir.NetworkPolicy{Default: "allow_all"}, "allow_all", ""},
		{ir.NetworkPolicy{Default: "allow"}, "allow", "cursor.network.egress-allowed-by-default"},
	}

	var entities []ir.Entity
	wantRuleByKey := map[string]string{}
	for _, g := range grants {
		entities = append(entities, g.entity)
		wantRuleByKey[g.key] = g.wantRule
	}

	gotRulesByKey := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		var key string
		switch v := hit.Entity.(type) {
		case ir.Sandbox:
			key = v.Mode
		case ir.NetworkPolicy:
			key = v.Default
		default:
			continue
		}
		gotRulesByKey[key] = append(gotRulesByKey[key], hit.RuleID)
	}

	for key, wantRule := range wantRuleByKey {
		got := gotRulesByKey[key]
		if wantRule == "" {
			if len(got) != 0 {
				t.Errorf("grant %q fired %v, want nothing", key, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Errorf("grant %q fired %d rules (%v), want exactly 1", key, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("grant %q fired rule %q, want %q", key, got[0], wantRule)
		}
	}
}

func TestCursorToolPermissionRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	grants := []struct {
		entity   ir.Entity
		key      string
		wantRule string
	}{
		{ir.ToolPermission{Tool: "Shell", Argument: "*"}, "Shell|*", "cursor.permissions.wildcard-grant"},
		{ir.ToolPermission{Tool: "Read", Argument: "**"}, "Read|**", "cursor.permissions.wildcard-grant"},
		{ir.ToolPermission{Tool: "Shell", Argument: "npm run build"}, "Shell|npm run build", "cursor.permissions.granted-tool"},
		{ir.ToolPermission{Tool: "Write", Argument: "src/**"}, "Write|src/**", "cursor.permissions.granted-tool"},
		{ir.ToolPermission{Tool: "Shell(rm"}, "Shell(rm|", "cursor.permissions.granted-tool"},
	}

	var entities []ir.Entity
	wantRuleByKey := map[string]string{}
	for _, g := range grants {
		entities = append(entities, g.entity)
		wantRuleByKey[g.key] = g.wantRule
	}

	gotRulesByKey := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		v, ok := hit.Entity.(ir.ToolPermission)
		if !ok {
			continue
		}
		key := v.Tool + "|" + v.Argument
		gotRulesByKey[key] = append(gotRulesByKey[key], hit.RuleID)
	}

	for key, wantRule := range wantRuleByKey {
		got := gotRulesByKey[key]
		if len(got) != 1 {
			t.Errorf("grant %q fired %d permission rules (%v), want exactly 1", key, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("grant %q fired rule %q, want %q", key, got[0], wantRule)
		}
	}
}

// No shipped rule matches a Cursor subagent, under either write posture
// the project walk gives one or the empty posture the plugin walk leaves.
// The tool permission evaluated beside them fires, so an empty result is an
// answer rather than an evaluation that ran over nothing.
func TestNoShippedRuleMatchesACursorSubagent(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	entities := []ir.Entity{
		ir.Subagent{Name: "deployer", PermissionMode: "write-enabled"},
		ir.Subagent{Name: "auditor", PermissionMode: "readonly"},
		ir.Subagent{Name: "greeter"},
		ir.ToolPermission{Tool: "Shell", Argument: "git"},
	}

	gotByKind := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		gotByKind[hit.Entity.Kind()] = append(gotByKind[hit.Entity.Kind()], hit.RuleID)
	}

	want := map[string][]string{"toolPermission": {"cursor.permissions.granted-tool"}}
	if !reflect.DeepEqual(gotByKind, want) {
		t.Fatalf("rules by kind = %+v, want %+v", gotByKind, want)
	}
}

func TestCursorBundledPayloadRulesAreMutuallyExclusive(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	wantRuleByOrigin := map[string]string{
		"skill": "cursor.payload.skill-script",
		"hook":  "cursor.payload.hook-script",
	}

	var entities []ir.Entity
	for origin := range wantRuleByOrigin {
		entities = append(entities, ir.BundledPayload{
			Path:   "payload/" + origin + "/run.sh",
			Origin: origin,
		})
	}

	gotRulesByOrigin := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		p, isPayload := hit.Entity.(ir.BundledPayload)
		if !isPayload {
			continue
		}
		gotRulesByOrigin[p.Origin] = append(gotRulesByOrigin[p.Origin], hit.RuleID)
	}

	for origin, wantRule := range wantRuleByOrigin {
		got := gotRulesByOrigin[origin]
		if len(got) != 1 {
			t.Errorf("origin %q fired %d payload rules (%v), want exactly 1", origin, len(got), got)
			continue
		}
		if got[0] != wantRule {
			t.Errorf("origin %q fired rule %q, want %q", origin, got[0], wantRule)
		}
	}
}

// An allow_instructions entry reaches a finding of its own, carrying the
// text rather than a tool name, and the block_instructions entry beside it
// reaches none: one argues for fewer approval prompts and the other for
// more.
func TestScanSurfacesTheCursorAutoRunInstructions(t *testing.T) {
	fsys := fstest.MapFS{
		".cursor/permissions.json": &fstest.MapFile{Data: []byte(
			`{"autoRun":{"allow_instructions":["release scripts are routine"],"block_instructions":["ask before touching prod"]}}`,
		)},
	}

	report, err := New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	got := map[string]string{}
	for _, f := range report.Findings() {
		i, isText := f.Capability.Entity.(ir.InstructionText)
		if !isText {
			t.Fatalf("finding %+v does not carry an ir.InstructionText", f)
		}
		if f.RuleID != "cursor.permissions.auto-run-instructions" {
			t.Errorf("setting %q fired rule %q", i.Setting, f.RuleID)
		}
		got[f.Capability.Provenance.Key] = i.Text
	}
	want := map[string]string{
		"autoRun.allow_instructions[0]": "release scripts are routine",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("instruction findings = %+v, want %+v", got, want)
	}
}

// An allowlist entry and a prose entry sit in one file and must not fire
// each other's rule: the two are different claims about what the file says.
func TestCursorPermissionsFileRulesStayApartByTarget(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	entities := []ir.Entity{
		ir.ToolPermission{Tool: "Shell", Argument: "git"},
		ir.InstructionText{Setting: "allow_instructions", Text: "release scripts are routine"},
	}

	gotByKind := map[string][]string{}
	for _, hit := range ruleeng.Evaluate(rules, entities, string(adapter.AgentCursor)) {
		gotByKind[hit.Entity.Kind()] = append(gotByKind[hit.Entity.Kind()], hit.RuleID)
	}
	want := map[string][]string{
		"toolPermission":  {"cursor.permissions.granted-tool"},
		"instructionText": {"cursor.permissions.auto-run-instructions"},
	}
	if !reflect.DeepEqual(gotByKind, want) {
		t.Fatalf("rules by kind = %+v, want %+v", gotByKind, want)
	}
}
