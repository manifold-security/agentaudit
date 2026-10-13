package agentaudit_test

import (
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

type skillsDirFinding struct {
	ruleID string
	file   string
	key    string
}

func skillsDirFindings(t *testing.T, report agentaudit.Report) []skillsDirFinding {
	t.Helper()
	var got []skillsDirFinding
	for _, f := range report.Findings() {
		got = append(got, skillsDirFinding{f.RuleID, f.Capability.Provenance.File, f.Capability.Provenance.Key})
	}
	return got
}

func assertExactFindings(t *testing.T, got, want []skillsDirFinding) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("findings = %+v, want exactly %+v", got, want)
	}
	gotSet := map[skillsDirFinding]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("findings = %+v, want to contain %+v", got, w)
		}
	}
}

// A plugin anchored only by a skills-directory manifest scans to exactly
// its plugin-installed finding plus its own hook.
func TestSkillsDirPluginScansToExactFindingSet(t *testing.T) {
	const pluginManifest = ".claude/skills/foo/.claude-plugin/plugin.json"
	const hooksFile = ".claude/skills/foo/hooks/hooks.json"
	const lspFile = ".claude/skills/foo/.lsp.json"

	base := fstest.MapFS{
		pluginManifest: &fstest.MapFile{Data: []byte(`{"name":"foo"}`)},
		hooksFile: &fstest.MapFile{Data: []byte(
			`{"SessionStart":[{"hooks":[{"type":"command","command":"${CLAUDE_PLUGIN_ROOT}/start.sh"}]}]}`,
		)},
	}

	t.Run("hooks and plugin presence only", func(t *testing.T) {
		report, err := agentaudit.New().Scan(base)
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}

		want := []skillsDirFinding{
			{"claude.plugin.installed", pluginManifest, "name"},
			{"claude.hook.command", hooksFile, "hooks.SessionStart[0].hooks[0]"},
		}
		assertExactFindings(t, skillsDirFindings(t, report), want)
	})

	t.Run("adding .lsp.json gains the lsp-server finding", func(t *testing.T) {
		fsys := fstest.MapFS{
			pluginManifest: base[pluginManifest],
			hooksFile:      base[hooksFile],
			lspFile:        &fstest.MapFile{Data: []byte(`{"go":{"command":"gopls"}}`)},
		}

		report, err := agentaudit.New().Scan(fsys)
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}

		want := []skillsDirFinding{
			{"claude.plugin.installed", pluginManifest, "name"},
			{"claude.hook.command", hooksFile, "hooks.SessionStart[0].hooks[0]"},
			{"claude.plugin.lsp-server", lspFile, "lspServers.go"},
		}
		assertExactFindings(t, skillsDirFindings(t, report), want)
	})
}
