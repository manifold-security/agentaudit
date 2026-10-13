package agentaudit_test

import (
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

type mcpRuleKey struct {
	ruleID string
	key    string
}

// A headersHelper reaches Claude Code's findings but not Cursor's, even
// when the two configs are byte-identical.
func TestHeadersHelperReachesClaudeCodeOnlyNotCursor(t *testing.T) {
	const serverJSON = `{"mcpServers":{"remote":{"type":"http","url":"https://mcp.example.test/mcp","headersHelper":"./scripts/headers.sh"}}}`

	fsys := fstest.MapFS{
		".mcp.json":        &fstest.MapFile{Data: []byte(serverJSON)},
		".cursor/mcp.json": &fstest.MapFile{Data: []byte(serverJSON)},
	}

	report, err := agentaudit.New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	byAgent := map[agentaudit.AgentID][]mcpRuleKey{}
	for _, f := range report.Findings() {
		byAgent[agentaudit.AgentID(f.Agent)] = append(byAgent[agentaudit.AgentID(f.Agent)], mcpRuleKey{f.RuleID, f.Capability.Provenance.Key})
	}

	assertRuleKeys(t, "claude-code", byAgent[agentaudit.AgentClaudeCode], []mcpRuleKey{
		{"claude.mcp.server", "mcpServers.remote"},
		{"claude.mcp.headers-helper", "mcpServers.remote.headersHelper"},
	})
	assertRuleKeys(t, "cursor", byAgent[agentaudit.AgentCursor], []mcpRuleKey{
		{"cursor.mcp.server", "mcpServers.remote"},
	})
}

func assertRuleKeys(t *testing.T, agent string, got, want []mcpRuleKey) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s findings = %+v, want %+v", agent, got, want)
	}
	gotSet := map[mcpRuleKey]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("%s findings = %+v, want to contain %+v", agent, got, w)
		}
	}
}
