package agentaudit_test

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

// syntheticPresenceRule gives each parser family its own rule, so a sibling
// surviving a malformed source cannot be another family's rule firing.
func syntheticPresenceRule(id, target, field string) string {
	return fmt.Sprintf(`[
  {
    "id": %q,
    "name": "Test %s presence",
    "description": "Synthetic rule matching any %s entity; test-only, never shipped.",
    "category": ["code-execution"],
    "appliesTo": [],
    "target": %q,
    "match": {"condition": "and", "rules": [{"field": %q, "op": "exists"}]},
    "message": "%s present",
    "references": ["https://example.invalid/test-rule"],
    "examples": [{%q: "present"}],
    "negative_examples": [{%q: ""}]
  }
]`, id, target, target, target, field, field, field, field)
}

var syntheticInlineShellRule = syntheticPresenceRule("test.inlineshell.command", "inlineShell", "command")

var syntheticSubagentRule = syntheticPresenceRule("test.subagent.presence", "subagent", "name")

var syntheticPluginRule = syntheticPresenceRule("test.plugin.presence", "plugin", "name")

func matrixRulesFS() fstest.MapFS {
	return fstest.MapFS{
		"testrules/hook.json":        &fstest.MapFile{Data: []byte(syntheticHookRule)},
		"testrules/inlineshell.json": &fstest.MapFile{Data: []byte(syntheticInlineShellRule)},
		"testrules/subagent.json":    &fstest.MapFile{Data: []byte(syntheticSubagentRule)},
		"testrules/plugin.json":      &fstest.MapFile{Data: []byte(syntheticPluginRule)},
	}
}

// findingIDs is a set: presence checks ignore finding order and count.
func findingIDs(report agentaudit.Report) map[string]bool {
	ids := map[string]bool{}
	for _, f := range report.Findings() {
		ids[f.RuleID] = true
	}
	return ids
}

type malformedMatrixCase struct {
	name              string
	fsys              fstest.MapFS
	wantWarningSubstr string
	wantIDsPresent    []string
	wantIDsAbsent     []string
	wantUnparsed      int
}

func malformedMatrixCases() []malformedMatrixCase {
	skillInvalidFrontmatter := "---\n" +
		"name: demo\n" +
		"tools: [unterminated\n" +
		"---\n\n" +
		"Run !`echo body-command` now.\n"

	skillUnterminatedFence := "---\n" +
		"name: demo\n" +
		"no closing fence\n\n" +
		"Run !`echo should-not-appear` now.\n"

	brokenAgent := "---\nname: [unterminated\n---\n\nbroken agent\n"
	goodAgent := "---\nname: good-agent\n---\n\ngood agent\n"

	return []malformedMatrixCase{
		{
			name: "mcp-json-syntax-error",
			fsys: fstest.MapFS{
				".mcp.json":             &fstest.MapFile{Data: []byte(`{"mcpServers":`)},
				".claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
			},
			wantWarningSubstr: ".mcp.json",
			wantIDsPresent:    []string{"test.hook.pretooluse"},
			wantUnparsed:      1,
		},
		{
			// Invalid YAML in a terminated fence leaves the body scannable.
			name: "skill-frontmatter-invalid-yaml-terminated-fence",
			fsys: fstest.MapFS{
				".claude/skills/demo/SKILL.md": &fstest.MapFile{Data: []byte(skillInvalidFrontmatter)},
				".claude/settings.json":        &fstest.MapFile{Data: []byte(validStubSettings)},
			},
			wantWarningSubstr: "demo/SKILL.md",
			wantIDsPresent:    []string{"test.hook.pretooluse", "test.inlineshell.command"},
			wantUnparsed:      1,
		},
		{
			// An unterminated fence hides the whole file, body included.
			name: "skill-frontmatter-unterminated-fence",
			fsys: fstest.MapFS{
				".claude/skills/demo/SKILL.md": &fstest.MapFile{Data: []byte(skillUnterminatedFence)},
				".claude/settings.json":        &fstest.MapFile{Data: []byte(validStubSettings)},
			},
			wantWarningSubstr: "demo/SKILL.md",
			wantIDsPresent:    []string{"test.hook.pretooluse"},
			wantIDsAbsent:     []string{"test.inlineshell.command"},
			wantUnparsed:      1,
		},
		{
			name: "agent-frontmatter-invalid-yaml",
			fsys: fstest.MapFS{
				".claude/agents/broken.md": &fstest.MapFile{Data: []byte(brokenAgent)},
				".claude/agents/good.md":   &fstest.MapFile{Data: []byte(goodAgent)},
			},
			wantWarningSubstr: "agents/broken.md",
			wantIDsPresent:    []string{"test.subagent.presence"},
			wantUnparsed:      1,
		},
		{
			name: "plugin-manifest-invalid-json",
			fsys: fstest.MapFS{
				"plugins/broken/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{invalid`)},
				"plugins/good/.claude-plugin/plugin.json":   &fstest.MapFile{Data: []byte(`{"name":"good-plugin"}`)},
			},
			wantWarningSubstr: "plugins/broken/.claude-plugin/plugin.json",
			wantIDsPresent:    []string{"test.plugin.presence"},
			wantUnparsed:      1,
		},
	}
}

// Per parser family: a syntactically broken source warns naming the
// offending file, a readable sibling's finding survives, and the fault
// lands in UnparsedSources with UnreadableSources left at zero — the
// scanner read the file, so nothing was hidden from it, but what that file
// declared never reached the report.
func TestScanMalformedSourceMatrix(t *testing.T) {
	for _, tc := range malformedMatrixCases() {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []error
			s := agentaudit.New(
				agentaudit.WithRulesFS(matrixRulesFS(), "testrules"),
				agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
			)

			report, err := s.Scan(tc.fsys)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if len(warnings) == 0 {
				t.Fatalf("WarnFunc was never called, want >=1 call naming the offending file")
			}
			named := false
			for _, warning := range warnings {
				if strings.Contains(warning.Error(), tc.wantWarningSubstr) {
					named = true
					break
				}
			}
			if !named {
				t.Errorf("warnings = %v, want one of them to name %q", warnings, tc.wantWarningSubstr)
			}

			ids := findingIDs(report)
			for _, id := range tc.wantIDsPresent {
				if !ids[id] {
					t.Errorf("findings = %v, want %q present", ids, id)
				}
			}
			for _, id := range tc.wantIDsAbsent {
				if ids[id] {
					t.Errorf("findings = %v, want %q absent", ids, id)
				}
			}
			if got := report.UnreadableSources(); got != 0 {
				t.Errorf("UnreadableSources() = %d, want 0", got)
			}
			if got := report.UnparsedSources(); got != tc.wantUnparsed {
				t.Errorf("UnparsedSources() = %d, want %d", got, tc.wantUnparsed)
			}
		})
	}
}
