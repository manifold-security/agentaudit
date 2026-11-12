package agentaudit_test

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/finding"
)

const allowedShellRule = "claude.permissions.allowed-shell"

func allowedShellKeys(rep finding.Report) []string {
	var out []string
	for _, f := range rep.Findings() {
		if f.RuleID == allowedShellRule {
			out = append(out, f.Capability.Provenance.File+":"+f.Capability.Provenance.Key)
		}
	}
	slices.Sort(out)
	return out
}

func TestScanReportsShellAllowEntriesFromBothSettingsFiles(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"bare Bash", map[string]string{settingsFile: `{"permissions":{"allow":["Bash"]}}`}, []string{settingsFile + ":permissions.allow[0]"}},
		{"Bash prefix", map[string]string{settingsFile: `{"permissions":{"allow":["Bash(npm run test:*)"]}}`}, []string{settingsFile + ":permissions.allow[0]"}},
		{"Bash exact", map[string]string{settingsFile: `{"permissions":{"allow":["Bash(git status)"]}}`}, []string{settingsFile + ":permissions.allow[0]"}},
		{"bare PowerShell", map[string]string{settingsFile: `{"permissions":{"allow":["PowerShell"]}}`}, []string{settingsFile + ":permissions.allow[0]"}},
		{"PowerShell command", map[string]string{settingsFile: `{"permissions":{"allow":["PowerShell(Get-ChildItem *)"]}}`}, []string{settingsFile + ":permissions.allow[0]"}},
		{"shell entry beside a WebFetch one", map[string]string{settingsFile: `{"permissions":{"allow":["WebFetch(domain:example.com)","Bash(make)"]}}`}, []string{settingsFile + ":permissions.allow[1]"}},
		{"WebFetch alone", map[string]string{settingsFile: `{"permissions":{"allow":["WebFetch(domain:example.com)","mcp__github__create_issue"]}}`}, nil},
		{"unclosed Bash", map[string]string{settingsFile: `{"permissions":{"allow":["Bash(rm"]}}`}, nil},
		{"lowercase bash", map[string]string{settingsFile: `{"permissions":{"allow":["bash(ls)"]}}`}, nil},
		{"leading space", map[string]string{settingsFile: `{"permissions":{"allow":[" Bash(ls)"]}}`}, nil},
		{"both settings files", map[string]string{
			settingsFile:      `{"permissions":{"allow":["Bash(make)"]}}`,
			localSettingsFile: `{"permissions":{"allow":["Bash(npm ci)"]}}`,
		}, []string{settingsFile + ":permissions.allow[0]", localSettingsFile + ":permissions.allow[0]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, warnings := warnedScan(t, projectScan, treeOf(tt.files))

			if got := allowedShellKeys(rep); !slices.Equal(got, tt.want) {
				t.Errorf("%s findings = %q, want %q", allowedShellRule, got, tt.want)
			}
			if len(tt.want) != 0 {
				for _, f := range rep.Findings() {
					if !slices.Equal(f.Categories, []finding.Category{"code-execution"}) {
						t.Errorf("finding %s categories = %v, want [code-execution]", f.RuleID, f.Categories)
					}
				}
			}
			if len(warnings) != 0 || rep.UnparsedSources() != 0 || rep.UnreadableSources() != 0 {
				t.Errorf("warnings = %q, unparsed = %d, unreadable = %d, want a clean scan", warnings, rep.UnparsedSources(), rep.UnreadableSources())
			}
		})
	}
}

func TestScanReportsNothingForDenyAskOrAdditionalDirectories(t *testing.T) {
	const inert = `"deny":["Bash(rm:*)"],"ask":["Bash(git push:*)"],"additionalDirectories":["../shared"]`
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"deny, ask and directories", `{"permissions":{` + inert + `}}`, nil},
		{"the same beside an allow entry", `{"permissions":{` + inert + `,"allow":["Bash(make)"]}}`, []string{settingsFile + ":permissions.allow[0]"}},
		{"an allow entry beside a deny of the bare tool", `{"permissions":{"allow":["Bash(curl:*)"],"deny":["Bash"]}}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, warnings := warnedScan(t, projectScan, treeOf(map[string]string{settingsFile: tt.body}))

			if got := allowedShellKeys(rep); !slices.Equal(got, tt.want) {
				t.Errorf("%s findings = %q, want %q", allowedShellRule, got, tt.want)
			}
			if len(warnings) != 0 || rep.UnparsedSources() != 0 {
				t.Errorf("warnings = %q, unparsed = %d, want a clean scan", warnings, rep.UnparsedSources())
			}
			if got := rep.ScannedAgents(); !slices.Equal(got, []string{"claude-code"}) {
				t.Errorf("ScannedAgents() = %q, want [claude-code]", got)
			}
			if len(tt.want) == 0 && rep.HasFindings() {
				t.Errorf("findings = %q, want none", findingKeys(rep))
			}
		})
	}
}

func TestScanKeepsAGoodAllowEntryBesideAMalformedOne(t *testing.T) {
	tree := treeOf(map[string]string{settingsFile: `{"permissions":{"allow":["Bash(make)",7,null,{"tool":"Bash"},"Bash(npm ci)"]}}`})

	rep, warnings := warnedScan(t, projectScan, tree)

	want := []string{settingsFile + ":permissions.allow[0]", settingsFile + ":permissions.allow[4]"}
	if got := allowedShellKeys(rep); !slices.Equal(got, want) {
		t.Errorf("%s findings = %q, want %q", allowedShellRule, got, want)
	}
	if len(warnings) != 3 {
		t.Errorf("warnings = %q, want one per malformed element", warnings)
	}
	if rep.UnparsedSources() != 1 || rep.UnreadableSources() != 0 {
		t.Errorf("UnparsedSources() = %d, UnreadableSources() = %d, want 1 and 0", rep.UnparsedSources(), rep.UnreadableSources())
	}
}

func TestScanGlobalReportsTheUsersOwnAllowEntries(t *testing.T) {
	home := fstest.MapFS{settingsFile: {Data: []byte(`{"permissions":{"allow":["Bash(make)"]}}`)}}

	rep, _ := warnedScan(t, globalScan, home)

	want := []string{settingsFile + ":permissions.allow[0]"}
	if got := allowedShellKeys(rep); !slices.Equal(got, want) {
		t.Errorf("%s findings = %q, want %q", allowedShellRule, got, want)
	}
}
