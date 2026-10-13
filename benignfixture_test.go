package agentaudit_test

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

// benignFixtureRoot declares only keys whose emitted entities match no rule
// — the not-crying-wolf path through the real config->adapter->ruleset
// chain, which IR-shaped negative_examples cannot reach.
const benignFixtureRoot = "testdata/benign/claude-clean"

// syntheticBenignEnvVarRule proves the fixture's settings.json was parsed:
// an absent or never-scanned fixture cannot satisfy it.
const syntheticBenignEnvVarRule = `[
  {
    "id": "test.envvar.benignpresence",
    "name": "Test benign fixture env var presence",
    "description": "Synthetic rule used only to prove the benign fixture's settings.json was parsed.",
    "category": ["code-execution"],
    "appliesTo": [],
    "target": "envVar",
    "match": {"condition": "and", "rules": [{"field": "name", "op": "equals", "value": "CLAUDE_LOG_LEVEL"}]},
    "message": "env var CLAUDE_LOG_LEVEL declared",
    "references": ["https://example.invalid/test-rule"],
    "examples": [{"name": "CLAUDE_LOG_LEVEL", "value": "info"}],
    "negative_examples": [{"name": "OTHER", "value": "info"}]
  }
]`

// Zero findings, zero unreadable sources and zero warnings cannot
// distinguish a fixture that was scanned and found clean from one that
// never activated the adapter; TestScanBenignFixtureActivatesAdapter is the
// companion arm that rules out absence.
func TestScanBenignFixtureIsClean(t *testing.T) {
	var warnings []error
	s := agentaudit.New(agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }))

	report, err := s.Scan(os.DirFS(benignFixtureRoot))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if report.HasFindings() {
		t.Fatalf("HasFindings() = true, want false: %+v", report.Findings())
	}
	if got := report.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() = %d, want 0", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("WarnFunc called %d time(s), want 0: %v", len(warnings), warnings)
	}
}

func TestScanBenignFixtureActivatesAdapter(t *testing.T) {
	rulesFS := fstest.MapFS{
		"testrules/envvar.json": &fstest.MapFile{Data: []byte(syntheticBenignEnvVarRule)},
	}
	s := agentaudit.New(agentaudit.WithRulesFS(rulesFS, "testrules"))

	report, err := s.Scan(os.DirFS(benignFixtureRoot))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	fired := false
	for _, f := range report.Findings() {
		if f.RuleID == "test.envvar.benignpresence" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("findings = %+v, want the synthetic presence rule to fire on this fixture's settings.json", report.Findings())
	}
}
