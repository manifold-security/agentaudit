package agentaudit_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/discovery"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const claudePluginOnlyFixture = "testdata/malicious/claude-plugin-only"

// A plugin-only tree activates the Claude adapter on the depth-agnostic
// .claude-plugin/plugin.json signature alone, and the manifest's
// ${CLAUDE_PLUGIN_ROOT} is substituted so a finding carries the real path.
func TestScanRealPluginOnlyFixtureActivatesAndReportsPresence(t *testing.T) {
	s := agentaudit.New()

	report, err := s.Scan(os.DirFS(claudePluginOnlyFixture))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	wantRuleCounts := map[string]int{
		"claude.plugin.installed":  1,
		"claude.mcp.server":        1,
		"claude.plugin.executable": 1,
	}
	gotRuleCounts := map[string]int{}
	for _, f := range findings {
		gotRuleCounts[f.RuleID]++
	}
	for id, want := range wantRuleCounts {
		if gotRuleCounts[id] != want {
			t.Errorf("rule %q fired %d times, want %d (findings: %+v)", id, gotRuleCounts[id], want, findings)
		}
	}
	if !report.HasFindings() {
		t.Fatal("HasFindings() = false, want true (plugin-only tree must activate the adapter)")
	}

	for _, f := range findings {
		if f.RuleID != "claude.mcp.server" {
			continue
		}
		mcp, ok := f.Capability.Entity.(ir.MCPServer)
		if !ok {
			t.Fatalf("claude.mcp.server matched a %T, want ir.MCPServer", f.Capability.Entity)
		}
		if mcp.Command != "plugins/vendor/bin/db" {
			t.Errorf("MCPServer.Command = %q, want the substituted %q", mcp.Command, "plugins/vendor/bin/db")
		}
		if strings.Contains(mcp.Command, "CLAUDE_PLUGIN_ROOT") {
			t.Errorf("MCPServer.Command = %q, must not contain the literal placeholder", mcp.Command)
		}
	}
}

const claudePluginFixture = "testdata/malicious/claude-plugin"

// A degraded manifest still reports its plugin root, so a broken or hostile
// manifest cannot make a plugin disappear from the scan.
func TestScanRealPluginFixtureReportsPresenceForEachRoot(t *testing.T) {
	s := agentaudit.New()

	report, err := s.Scan(os.DirFS(claudePluginFixture))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	wantRuleCounts := map[string]int{
		"claude.plugin.installed":  6,
		"claude.hook.command":      4,
		"claude.mcp.server":        4,
		"claude.plugin.executable": 4,
	}
	gotRuleCounts := map[string]int{}
	for _, f := range findings {
		gotRuleCounts[f.RuleID]++
	}
	for id, want := range wantRuleCounts {
		if gotRuleCounts[id] != want {
			t.Errorf("rule %q fired %d times, want %d (findings: %+v)", id, gotRuleCounts[id], want, findings)
		}
	}

	wantTotal := 0
	for _, want := range wantRuleCounts {
		wantTotal += want
	}
	if len(findings) != wantTotal {
		t.Errorf("len(findings) = %d, want the exact total %d (findings: %+v)", len(findings), wantTotal, findings)
	}
}

// A plugin.json that is a DIRECTORY rather than a regular file cannot scan
// clean: skipping directory entries before testing the basename would miss
// it entirely, since an empty manifest directory yields no file entries for
// anything else to notice. Built at runtime: git carries no empty directory.
func TestScanDirectoryTypedManifestStillSurfacesPlugin(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "vendored", ".claude-plugin", "plugin.json"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) {
		warnings = append(warnings, w.Error())
	}))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var names []string
	for _, f := range report.Findings() {
		if f.RuleID != "claude.plugin.installed" {
			continue
		}
		p, ok := f.Capability.Entity.(ir.Plugin)
		if !ok {
			t.Fatalf("claude.plugin.installed matched a %T, want ir.Plugin", f.Capability.Entity)
		}
		names = append(names, p.Name)
	}
	if len(names) != 1 || names[0] != "vendored" {
		t.Fatalf("plugin names = %v, want [vendored] (findings: %+v)", names, report.Findings())
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for an unreadable manifest; a skipped surface must never be silent")
	}
}

// The recursive Claude signatures match file entries beneath their
// directory, never the directory entry itself.
func TestScanDirectoryEntriesAddNoSpuriousSources(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/agents/reviewer.md": &fstest.MapFile{Data: []byte("---\nname: reviewer\n---\nbody\n")},
	}

	got, _, err := discovery.Discover(fsys, []adapter.Adapter{claude.New()})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	for _, s := range got.Sources {
		if s.Path == ".claude/agents" {
			t.Fatalf("Discover().Sources contains the DIRECTORY %q; recursive signatures must match only file entries (got %+v)", s.Path, got.Sources)
		}
	}
	if len(got.Sources) != 1 || got.Sources[0].Path != ".claude/agents/reviewer.md" {
		t.Fatalf("Discover().Sources = %+v, want exactly the one file entry", got.Sources)
	}
}

// A manifest-referenced path whose target is a SYMLINK is refused rather
// than followed. Lexical containment is not enough: the runtime fs.FS is a
// real os.DirFS, so a symlink at a textually-contained path resolves to
// wherever it points, outside the scanned repository included. Real disk,
// because fstest.MapFS cannot model a target that is not in the map.
func TestScanRefusesSymlinkedManifestTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside-secret.json")
	if err := os.WriteFile(outside, []byte(`{"mcpServers":{"leaked":{"command":"SECRET-FROM-OUTSIDE-REPO"}}}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	pluginDir := filepath.Join(root, "q")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"q","mcpServers":"./leak.json"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(pluginDir, "leak.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, f := range report.Findings() {
		if srv, ok := f.Capability.Entity.(ir.MCPServer); ok {
			t.Fatalf("surfaced MCP server %q (%q) read through a symlink; the target must be refused, not followed",
				srv.Name, srv.Command)
		}
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the refused symlink target; a skipped surface must never be silent")
	}
}

func symlinkedAgentsDirectoryTree(t *testing.T) string {
	t.Helper()

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "a.md"),
		[]byte("---\nname: outside-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "pl")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"pl","agents":["./linked","./realagents"]}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "realagents"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "realagents", "inside.md"),
		[]byte("---\nname: inside-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(pluginDir, "linked")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	return root
}

// fs.WalkDir stats its root, which follows a symlinked agents/ directory.
func TestScanRefusesSymlinkedAgentsDirectory(t *testing.T) {
	root := symlinkedAgentsDirectoryTree(t)

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))
	if _, err := s.Scan(os.DirFS(root)); err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	if len(warnings) == 0 {
		t.Fatal("Scan() emitted no warning for the refused symlinked agents directory")
	}
	var refused bool
	for _, w := range warnings {
		if strings.Contains(w, "not a real directory") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("warnings = %v, want one refusing to walk the symlinked directory", warnings)
	}
}

func TestScanRefusesSymlinkedAgentsDirectoryUnderSubagentRule(t *testing.T) {
	root := symlinkedAgentsDirectoryTree(t)

	var warnings []string
	s := agentaudit.New(
		agentaudit.WithRulesFS(subagentLeakRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
	)
	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	names := leakedSubagentNames(report)
	if !names["inside-agent"] {
		t.Fatalf("subagent findings = %v, want %q present (warnings: %v)", names, "inside-agent", warnings)
	}
	if names["outside-agent"] {
		t.Errorf("subagent findings = %v, want %q absent: its declared agents path is a symlinked directory", names, "outside-agent")
	}
}

// When the manifest path is itself the symlink, the plugin still surfaces
// under the directory-basename fallback, not the out-of-tree name.
func TestScanRefusesSymlinkedManifestItself(t *testing.T) {
	outsideDir := t.TempDir()
	outsideManifest := filepath.Join(outsideDir, "evil-manifest.json")
	if err := os.WriteFile(outsideManifest, []byte(
		`{"name":"EXFILTRATED-OUT-OF-TREE","version":"9.9.9",`+
			`"mcpServers":{"leaked":{"command":"/out/of/tree/binary"}}}`,
	), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "vendored")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	manifestPath := filepath.Join(pluginDir, ".claude-plugin", "plugin.json")
	if err := os.Symlink(outsideManifest, manifestPath); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var pluginNames []string
	for _, f := range report.Findings() {
		switch e := f.Capability.Entity.(type) {
		case ir.Plugin:
			pluginNames = append(pluginNames, e.Name)
			if e.Name == "EXFILTRATED-OUT-OF-TREE" {
				t.Fatalf("plugin surfaced with the OUT-OF-TREE manifest's name %q; the symlinked manifest must be refused", e.Name)
			}
		case ir.MCPServer:
			t.Fatalf("surfaced MCP server %+v read through the symlinked manifest itself", e)
		}
	}
	if len(pluginNames) != 1 || pluginNames[0] != "vendored" {
		t.Fatalf("plugin names = %v, want [vendored] (the directory-basename fallback)", pluginNames)
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked manifest; a refused surface must never be silent")
	}
}

// blockingPathFS refuses to open one path, naming what a FIFO with no writer
// does to a reader. It carries no ReadFile method, so fs.ReadFile reaches the
// refusal through Open.
type blockingPathFS struct {
	m    fstest.MapFS
	path string
}

func (f blockingPathFS) Open(name string) (fs.File, error) {
	if name == f.path {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errors.New(blockingOpenSentinel)}
	}
	return f.m.Open(name)
}

func (f blockingPathFS) Stat(name string) (fs.FileInfo, error)      { return f.m.Stat(name) }
func (f blockingPathFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }
func (f blockingPathFS) Lstat(name string) (fs.FileInfo, error)     { return fs.Lstat(f.m, name) }
func (f blockingPathFS) ReadLink(name string) (string, error)       { return fs.ReadLink(f.m, name) }

// A manifest's type bits settle it before any read, so the plugin root it names
// still surfaces, the refusal is warned, and nothing reaches the pipe.
func TestScanRefusesAFIFOManifestWithoutReadingIt(t *testing.T) {
	const manifest = "vendored/.claude-plugin/plugin.json"

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(blockingPathFS{
		m:    fstest.MapFS{manifest: &fstest.MapFile{Mode: fs.ModeNamedPipe}},
		path: manifest,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var names []string
	for _, f := range report.Findings() {
		if p, ok := f.Capability.Entity.(ir.Plugin); ok {
			names = append(names, p.Name)
		}
	}
	if len(names) != 1 || names[0] != "vendored" {
		t.Fatalf("plugin names = %v, want [vendored] (findings: %+v)", names, report.Findings())
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the FIFO manifest; a refused surface must never be silent")
	}
	for _, w := range warnings {
		if strings.Contains(w, blockingOpenSentinel) {
			t.Errorf("a read reached the FIFO manifest: %q", w)
		}
	}
}

// A symlinked INTERMEDIATE directory component is refused too, not just a
// symlinked final target: the final-component guards do not see an in-root
// symlink in an earlier segment, which the filesystem follows.
func TestScanRefusesSymlinkedIntermediateDirectoryInManifestPath(t *testing.T) {
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "servers.json"),
		[]byte(`{"leaked-mcp":{"command":"/out/of/tree/mcp-server"}}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "p")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"p","mcpServers":"./link/servers.json"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(pluginDir, "link")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, f := range report.Findings() {
		if srv, ok := f.Capability.Entity.(ir.MCPServer); ok {
			t.Fatalf("surfaced MCP server %q (%q) read through a symlinked INTERMEDIATE directory; must be refused", srv.Name, srv.Command)
		}
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked intermediate directory; a refused surface must never be silent")
	}
}

func TestScanRefusesSymlinkedIntermediateDirectoryForDefaultHooksFile(t *testing.T) {
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "hooks.json"), []byte(
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"LEAKED-HOOK"}]}]}}`,
	), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "p")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(pluginDir, "hooks")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, f := range report.Findings() {
		if h, ok := f.Capability.Entity.(ir.Hook); ok {
			t.Fatalf("surfaced hook %q read through the symlinked hooks/ directory (default location); must be refused", h.Command)
		}
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked hooks/ directory; a refused default location must never be silent")
	}
}

func TestScanRefusesSymlinkedBinDirectory(t *testing.T) {
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "evil-tool"), []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "p")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(pluginDir, "bin")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, f := range report.Findings() {
		if pe, ok := f.Capability.Entity.(ir.PluginExecutable); ok {
			t.Fatalf("surfaced pluginExecutable %+v read through the symlinked bin/ directory; must be refused", pe)
		}
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked bin/ directory; a refused surface must never be silent")
	}
	if report.UnreadableSources() == 0 {
		t.Error("UnreadableSources() = 0, want >0: a refused bin/ hides real executables just as a permission fault would")
	}
}

func symlinkedAgentFileTree(t *testing.T) string {
	t.Helper()

	outsideDir := t.TempDir()
	outsideAgent := filepath.Join(outsideDir, "outside-agent.md")
	if err := os.WriteFile(outsideAgent, []byte("---\nname: outside-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "p")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "agents"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "agents", "inside.md"),
		[]byte("---\nname: inside-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideAgent, filepath.Join(pluginDir, "agents", "linked.md")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	return root
}

func TestScanRefusesSymlinkedAgentFile(t *testing.T) {
	root := symlinkedAgentFileTree(t)

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked agent file; a refused surface must never be silent")
	}
	if report.UnreadableSources() == 0 {
		t.Error("UnreadableSources() = 0, want >0: the agent runtime may follow exactly what this scan refuses, so the refusal must degrade the scan")
	}
}

func TestScanRefusesSymlinkedAgentFileUnderSubagentRule(t *testing.T) {
	root := symlinkedAgentFileTree(t)

	var warnings []string
	s := agentaudit.New(
		agentaudit.WithRulesFS(subagentLeakRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
	)

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	names := leakedSubagentNames(report)
	if !names["inside-agent"] {
		t.Fatalf("subagent findings = %v, want %q present (warnings: %v)", names, "inside-agent", warnings)
	}
	if names["outside-agent"] {
		t.Errorf("subagent findings = %v, want %q absent: it was read through a symlinked agent file", names, "outside-agent")
	}
}

func TestScanRefusesSymlinkedDefaultHooksFileFinalTarget(t *testing.T) {
	outsideDir := t.TempDir()
	outsideHooks := filepath.Join(outsideDir, "leaked-hooks.json")
	if err := os.WriteFile(outsideHooks, []byte(
		`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"LEAKED-HOOK"}]}]}}`,
	), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "p")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "hooks"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outsideHooks, filepath.Join(pluginDir, "hooks", "hooks.json")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, f := range report.Findings() {
		if h, ok := f.Capability.Entity.(ir.Hook); ok {
			t.Fatalf("surfaced hook %+v read through the directly-symlinked hooks.json FINAL target; must be refused", h)
		}
	}
	if len(warnings) == 0 {
		t.Error("Scan() emitted no warning for the symlinked hooks.json final target; a refused surface must never be silent")
	}
}

func symlinkedAgentsPathTree(t *testing.T) string {
	t.Helper()

	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "agentsdir"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "agentsdir", "a.md"),
		[]byte("---\nname: out-of-tree-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}

	root := t.TempDir()
	pluginDir := filepath.Join(root, "pl")
	if err := os.MkdirAll(filepath.Join(pluginDir, ".claude-plugin"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"pl","agents":["./link/agentsdir","./realagents"]}`), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(pluginDir, "realagents"), 0o755); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "realagents", "inside.md"),
		[]byte("---\nname: contained-agent\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("building fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(pluginDir, "link")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	return root
}

// Pins the containment guard at the plugin-agents call site, which the
// sibling intermediate-symlink tests do not reach.
func TestScanRefusesSymlinkedIntermediateDirectoryForAgentsPath(t *testing.T) {
	root := symlinkedAgentsPathTree(t)

	var warnings []string
	s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))
	if _, err := s.Scan(os.DirFS(root)); err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var refused bool
	for _, w := range warnings {
		if strings.Contains(w, "not a real directory") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("warnings = %v, want one refusing to walk the symlinked intermediate component", warnings)
	}
}

func TestScanRefusesSymlinkedIntermediateDirectoryForAgentsPathUnderSubagentRule(t *testing.T) {
	root := symlinkedAgentsPathTree(t)

	var warnings []string
	s := agentaudit.New(
		agentaudit.WithRulesFS(subagentLeakRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
	)
	report, err := s.Scan(os.DirFS(root))
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	names := leakedSubagentNames(report)
	if !names["contained-agent"] {
		t.Fatalf("subagent findings = %v, want %q present (warnings: %v)", names, "contained-agent", warnings)
	}
	if names["out-of-tree-agent"] {
		t.Errorf("subagent findings = %v, want %q absent: its agents path runs through a symlinked intermediate directory", names, "out-of-tree-agent")
	}
}

// subagentLeakRulesFS exists because a leaked entity reaches a Finding only
// through a rule whose target is that entity: with none installed, asserting
// that no ir.Subagent surfaced cannot fail however the guards behave. Its
// callers therefore also pin a contained agent, which is what shows the rule
// reaches a Finding when a leak would.
func subagentLeakRulesFS() fstest.MapFS {
	return fstest.MapFS{"testrules/subagent.json": &fstest.MapFile{Data: []byte(syntheticSubagentRule)}}
}

func leakedSubagentNames(report agentaudit.Report) map[string]bool {
	names := map[string]bool{}
	for _, f := range report.Findings() {
		if sub, ok := f.Capability.Entity.(ir.Subagent); ok {
			names[sub.Name] = true
		}
	}
	return names
}
