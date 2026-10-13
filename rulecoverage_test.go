package agentaudit_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
)

type capabilitySurfaceRow struct {
	root   string
	global bool
}

// capabilitySurfaceRoots marks a row global where the rules under test fire
// from ScanGlobal, which runs unmasked here on purpose: the mask's own reach
// is pinned separately by cmd/agentaudit's per-adapter reach tables and
// runtime-state denial guards.
var capabilitySurfaceRoots = []capabilitySurfaceRow{
	{root: "testdata/malicious/claude-capability-surface"},
	{root: "testdata/malicious/cursor-capability-surface"},
	{root: "testdata/malicious/cursor-global-surface", global: true},
	{root: "testdata/malicious/codex-capability-surface"},
	{root: "testdata/malicious/codex-unattended"},
	{root: "testdata/malicious/codex-permission-profiles"},
	{root: "testdata/malicious/codex-full-access-profile"},
	{root: "testdata/malicious/codex-network-reach"},
}

func scanRow(s *agentaudit.Scanner, row capabilitySurfaceRow) (finding.Report, error) {
	if row.global {
		return s.ScanGlobal(os.DirFS(row.root))
	}
	return s.Scan(os.DirFS(row.root))
}

// The expectation comes from the shipped ruleset, not a hand-written id
// list, so a rule added without fixture coverage fails here.
func TestEveryEmbeddedRuleFiresAcrossCapabilitySurface(t *testing.T) {
	ids, err := agentaudit.EmbeddedRuleIDs()
	if err != nil {
		t.Fatalf("EmbeddedRuleIDs() error = %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("EmbeddedRuleIDs() returned no rule ids; a guard with nothing to check for asserts nothing")
	}

	fired := map[string]bool{}
	for _, row := range capabilitySurfaceRoots {
		s := agentaudit.New()
		report, err := scanRow(s, row)
		if err != nil {
			t.Fatalf("scanning %s error = %v", row.root, err)
		}
		findings := report.Findings()
		if len(findings) == 0 {
			t.Fatalf("scanning %s produced no findings; the row inspected nothing", row.root)
		}
		for _, f := range findings {
			fired[f.RuleID] = true
		}
	}

	var missing []string
	for _, id := range ids {
		if !fired[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("rule ids did not fire against the coverage fixture: %s", strings.Join(missing, ", "))
	}
}
