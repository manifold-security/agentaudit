package ruleeng

import (
	"testing"
	"testing/fstest"
)

const envVarRuleJSON = `[
  {
    "id": "no-plaintext-secrets",
    "name": "No plaintext secret in env",
    "description": "Flags env vars whose name suggests a secret",
    "category": ["secrets"],
    "target": "envVar",
    "match": {
      "rules": [
        {"field": "Name", "op": "matches", "value": "(?i)(secret|token|key)"}
      ]
    },
    "message": "Environment variable appears to hold a secret"
  }
]`

const mcpServerRuleJSON = `[
  {
    "id": "stdio-mcp-server",
    "name": "Stdio MCP server",
    "target": "mcpServer",
    "match": {
      "rules": [
        {"field": "Transport", "op": "equals", "value": "stdio"}
      ]
    },
    "message": "stdio MCP server declared"
  }
]`

func TestLoadValidRulesDeterministicOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/z-env.json": {Data: []byte(envVarRuleJSON)},
		"rules/claude/a-mcp.json": {Data: []byte(mcpServerRuleJSON)},
	}

	rules, err := Load(fsys, "rules/claude")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("Load() returned %d rules, want 2", len(rules))
	}
	// a-mcp.json sorts before z-env.json regardless of map iteration order.
	if rules[0].ID != "stdio-mcp-server" || rules[1].ID != "no-plaintext-secrets" {
		t.Fatalf("Load() order = [%s, %s], want sorted-by-filename order", rules[0].ID, rules[1].ID)
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/bad.json": {Data: []byte(`{not valid json`)},
	}
	if _, err := Load(fsys, "rules/claude"); err == nil {
		t.Fatalf("Load() error = nil, want error for malformed JSON")
	}
}

func TestLoadUnknownTarget(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/bad.json": {Data: []byte(`[{"id":"r1","target":"not-a-real-kind","match":{"rules":[{"field":"f","op":"exists"}]},"message":"m"}]`)},
	}
	if _, err := Load(fsys, "rules/claude"); err == nil {
		t.Fatalf("Load() error = nil, want error for unknown target")
	}
}

func TestLoadUncompilableRegex(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/bad.json": {Data: []byte(`[{"id":"r1","target":"envVar","match":{"rules":[{"field":"Name","op":"matches","value":"(unbalanced"}]},"message":"m"}]`)},
	}
	if _, err := Load(fsys, "rules/claude"); err == nil {
		t.Fatalf("Load() error = nil, want error for uncompilable regex")
	}
}

func TestLoadRuleWithPassingExamples(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/mcp.json": {Data: []byte(`[
		  {
		    "id": "stdio-mcp-server",
		    "name": "Stdio MCP server",
		    "target": "mcpServer",
		    "match": {"rules": [{"field": "Transport", "op": "equals", "value": "stdio"}]},
		    "message": "stdio MCP server declared",
		    "examples": [{"Transport": "stdio"}],
		    "negative_examples": [{"Transport": "http"}]
		  }
		]`)},
	}
	rules, err := Load(fsys, "rules/claude")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("Load() returned %d rules, want 1", len(rules))
	}
}

func TestLoadRuleWithFailingExample(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/claude/mcp.json": {Data: []byte(`[
		  {
		    "id": "stdio-mcp-server",
		    "name": "Stdio MCP server",
		    "target": "mcpServer",
		    "match": {"rules": [{"field": "Transport", "op": "equals", "value": "stdio"}]},
		    "message": "stdio MCP server declared",
		    "examples": [{"Transport": "http"}]
		  }
		]`)},
	}
	if _, err := Load(fsys, "rules/claude"); err == nil {
		t.Fatalf("Load() error = nil, want error for rule whose example fails to match")
	}
}

func TestLoadNoFiles(t *testing.T) {
	fsys := fstest.MapFS{}
	rules, err := Load(fsys, "rules/claude")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("Load() = %d rules, want 0", len(rules))
	}
}

// alpha lands before zebra, and neither alpha/notes.md nor alpha/nested
// reaches the set, so a walk that recursed or took directories in map order
// fails on the ids below.
func TestLoadAllReadsEveryAgentSubdirectory(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/zebra/env.json":      {Data: []byte(envVarRuleJSON)},
		"rules/alpha/mcp.json":      {Data: []byte(mcpServerRuleJSON)},
		"rules/alpha/notes.md":      {Data: []byte("not a rule file")},
		"rules/alpha/nested/x.json": {Data: []byte(envVarRuleJSON)},
	}

	rules, err := LoadAll(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	var ids []string
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	want := []string{"stdio-mcp-server", "no-plaintext-secrets"}
	if len(ids) != len(want) {
		t.Fatalf("LoadAll() ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("LoadAll() ids = %v, want %v (subdirectories walked in lexical order)", ids, want)
		}
	}
}

// A rule file sitting directly in the root belongs to no agent directory.
// Loading it would give it whichever appliesTo it happened to carry, with no
// directory to say which agent it was written for.
func TestLoadAllReadsNoRuleFromAJSONFileDirectlyUnderTheRoot(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/loose.json":     {Data: []byte(envVarRuleJSON)},
		"rules/alpha/mcp.json": {Data: []byte(mcpServerRuleJSON)},
	}

	rules, err := LoadAll(fsys, "rules")
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}
	if len(rules) != 1 || rules[0].ID != "stdio-mcp-server" {
		t.Fatalf("LoadAll() = %+v, want only the rule under an agent subdirectory", rules)
	}
}

// A malformed rule anywhere under the root must fail the load rather than
// silently shipping a ruleset missing one agent's checks.
func TestLoadAllFailsOnAMalformedRuleInAnySubdirectory(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/alpha/mcp.json": {Data: []byte(mcpServerRuleJSON)},
		"rules/zebra/bad.json": {Data: []byte(`[{"id":"broken"}]`)},
	}

	if _, err := LoadAll(fsys, "rules"); err == nil {
		t.Fatal("LoadAll() error = nil, want non-nil")
	}
}

// An id claimed by two agents' rule files would make the facade's id-keyed
// rule map depend on load order for the message a finding renders.
func TestLoadAllRejectsAnIDClaimedByTwoAgents(t *testing.T) {
	fsys := fstest.MapFS{
		"rules/alpha/mcp.json": {Data: []byte(mcpServerRuleJSON)},
		"rules/zebra/mcp.json": {Data: []byte(mcpServerRuleJSON)},
	}

	if _, err := LoadAll(fsys, "rules"); err == nil {
		t.Fatal("LoadAll() error = nil, want non-nil for a duplicate rule id")
	}
}
