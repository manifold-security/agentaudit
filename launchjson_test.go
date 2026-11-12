package agentaudit_test

import (
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
)

const previewRuleID = "claude.preview.command"

func launchTree(body string) fstest.MapFS {
	return treeOf(map[string]string{".claude/launch.json": body})
}

func previewFindings(rep finding.Report) []finding.Finding {
	var got []finding.Finding
	for _, f := range rep.Findings() {
		if f.RuleID == previewRuleID {
			got = append(got, f)
		}
	}
	return got
}

func TestScanReportsAPreviewServerOnlyWhenItRunsACommand(t *testing.T) {
	tests := []struct {
		name string
		body string
		keys []string
	}{
		{"an entry that only attaches to a url", `{"configurations":[{"name":"attached","url":"http://localhost:4000"}]}`, nil},
		{"the same entry with a runtime executable", `{"configurations":[{"name":"attached","url":"http://localhost:4000","runtimeExecutable":"npm"}]}`, []string{"configurations[0]"}},
		{"arguments with nothing to run", `{"configurations":[{"name":"web","runtimeArgs":["run","dev"]}]}`, []string{"configurations[0]"}},
		{"an empty executable and no arguments", `{"configurations":[{"name":"web","runtimeExecutable":"","runtimeArgs":[]}]}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := agentaudit.New().Scan(launchTree(tt.body))
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			var keys []string
			for _, f := range previewFindings(rep) {
				if f.Capability.Provenance.File != ".claude/launch.json" {
					t.Errorf("finding file = %q, want .claude/launch.json", f.Capability.Provenance.File)
				}
				keys = append(keys, f.Capability.Provenance.Key)
			}
			if !reflect.DeepEqual(keys, tt.keys) {
				t.Fatalf("preview findings at %v, want %v", keys, tt.keys)
			}
			if got, want := rep.ScannedAgents(), []string{"claude-code"}; !reflect.DeepEqual(got, want) {
				t.Errorf("ScannedAgents() = %v, want %v", got, want)
			}
			if rep.UnparsedSources() != 0 || rep.UnreadableSources() != 0 {
				t.Errorf("UnparsedSources() = %d, UnreadableSources() = %d, want 0 and 0", rep.UnparsedSources(), rep.UnreadableSources())
			}
		})
	}
}

func TestScanKeepsAGoodPreviewServerBesideAMalformedOne(t *testing.T) {
	rep, err := agentaudit.New().Scan(launchTree(
		`{"configurations":[{"name":"web","runtimeExecutable":"npm"}, 7, {"name":"x","runtimeArgs":"dev"}, {"name":"api","program":"server.js"}]}`))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	var keys []string
	for _, f := range previewFindings(rep) {
		keys = append(keys, f.Capability.Provenance.Key)
	}
	if want := []string{"configurations[0]", "configurations[3]"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("preview findings at %v, want %v", keys, want)
	}
	if rep.UnparsedSources() != 1 || rep.UnreadableSources() != 0 {
		t.Errorf("UnparsedSources() = %d, UnreadableSources() = %d, want 1 and 0", rep.UnparsedSources(), rep.UnreadableSources())
	}
}

func TestScanCountsAnUndecodableLaunchFileAsUnparsed(t *testing.T) {
	for name, body := range map[string]string{
		"a comment":      "// dev servers\n{\"configurations\":[{\"runtimeExecutable\":\"npm\"}]}",
		"a truncation":   `{"configurations":[`,
		"a top-level []": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := agentaudit.New().Scan(launchTree(body))
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if rep.HasFindings() {
				t.Fatalf("Findings() = %+v, want none from a file that did not decode", rep.Findings())
			}
			if rep.UnparsedSources() != 1 || rep.UnreadableSources() != 0 {
				t.Fatalf("UnparsedSources() = %d, UnreadableSources() = %d, want 1 and 0", rep.UnparsedSources(), rep.UnreadableSources())
			}
		})
	}
}

func TestScanRecursiveReadsANestedLaunchFileOnlyInItsOwnProject(t *testing.T) {
	const command = `{"configurations":[{"name":"web","runtimeExecutable":"npm"}]}`
	nested := treeOf(map[string]string{
		".claude/settings.json":     `{}`,
		"app/.claude/launch.json":   command,
		"app/.claude/settings.json": `{}`,
	})

	rep, err := agentaudit.New().Scan(nested)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := previewFindings(rep); len(got) != 0 {
		t.Fatalf("Scan() preview findings = %+v, want none: the file is below the scan root", got)
	}

	reports, err := agentaudit.New().ScanRecursive(nested)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	counts := map[string]int{}
	for _, r := range reports {
		counts[r.Path] = len(previewFindings(r.Report))
	}
	if want := map[string]int{".": 0, "app": 1}; !reflect.DeepEqual(counts, want) {
		t.Fatalf("preview findings per project = %v, want %v", counts, want)
	}

	atRoot, err := agentaudit.New().Scan(launchTree(command))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := previewFindings(atRoot); len(got) != 1 {
		t.Fatalf("Scan() preview findings = %+v, want the one at the root", got)
	}
}
