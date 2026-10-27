package discovery

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/ir"
)

type stubAdapter struct{}

func (stubAdapter) Agent() adapter.AgentID { return adapter.AgentClaudeCode }

func (stubAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{File: ".mcp.json"},
		{Dir: ".claude", Recursive: true},
		{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true},
	}
}

func (stubAdapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

var _ adapter.Adapter = stubAdapter{}

type stubAdapterAlt struct{}

func (stubAdapterAlt) Agent() adapter.AgentID { return adapter.AgentID("other-agent") }

func (stubAdapterAlt) Signatures() []adapter.Signature {
	return []adapter.Signature{{File: ".mcp.json"}}
}

func (stubAdapterAlt) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

var _ adapter.Adapter = stubAdapterAlt{}

type countingAdapter struct {
	agent adapter.AgentID
	calls *int
}

func (c countingAdapter) Agent() adapter.AgentID { return c.agent }

func (c countingAdapter) Signatures() []adapter.Signature {
	*c.calls++
	return []adapter.Signature{{File: "SKILL.md", AnyDepth: true}}
}

func (countingAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

var _ adapter.Adapter = countingAdapter{}

type failingFS struct {
	m       fstest.MapFS
	failDir string
}

func (f failingFS) Open(name string) (fs.File, error)      { return f.m.Open(name) }
func (f failingFS) Stat(name string) (fs.FileInfo, error)  { return f.m.Stat(name) }
func (f failingFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }
func (f failingFS) ReadLink(name string) (string, error)   { return f.m.ReadLink(name) }

func (f failingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failDir {
		return nil, errors.New("simulated read error")
	}
	return f.m.ReadDir(name)
}

func TestDiscover_WalkSkeleton(t *testing.T) {
	tests := []struct {
		name    string
		fsys    fs.FS
		wantErr bool
	}{
		{"empty filesystem returns empty result and nil error", fstest.MapFS{}, false},
		{"unrelated files with no config dirs return empty result and nil error", fstest.MapFS{
			"README.md":   &fstest.MapFile{Data: []byte("hello")},
			"src/main.go": &fstest.MapFile{Data: []byte("package main")},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := Discover(tt.fsys, []adapter.Adapter{stubAdapter{}})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Discover() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got.Sources) != 0 {
				t.Fatalf("Sources = %v, want empty", got.Sources)
			}
			if len(got.PluginRoots) != 0 {
				t.Fatalf("PluginRoots = %v, want empty", got.PluginRoots)
			}
		})
	}
}

// Discover's below-root degradation: a warning instead of an error, and the
// sources found around the failing directory still returned.
func TestDiscoverBelowRootFailureWarnsAndKeepsSources(t *testing.T) {
	fsys := failingFS{
		m: fstest.MapFS{
			"broken/file.txt": &fstest.MapFile{Data: []byte("x")},
			".mcp.json":       &fstest.MapFile{Data: []byte("{}")},
		},
		failDir: "broken",
	}

	got, warnings, err := Discover(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil (a below-root failure must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("Discover() warnings = none, want a warning for the unreadable broken/ directory")
	}
	if len(got.Sources) != 1 || got.Sources[0].Path != ".mcp.json" {
		t.Fatalf("Discover() Sources = %+v, want [.mcp.json] (found despite the unreadable sibling directory)", got.Sources)
	}
}

// A failure to ReadDir the scan root itself stays fatal: a non-nil error and
// a zero Result, never a degraded warn-and-continue.
func TestDiscoverRootReadDirFailureIsFatal(t *testing.T) {
	fsys := failingFS{
		m: fstest.MapFS{
			"file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: ".",
	}

	got, warnings, err := Discover(fsys, nil)
	if err == nil {
		t.Fatal("Discover() error = nil, want non-nil (a root ReadDir failure must stay fatal)")
	}
	if len(got.Sources) != 0 || len(got.PluginRoots) != 0 {
		t.Fatalf("Discover() result = %+v, want zero Result on a root failure", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("Discover() warnings = %+v, want none (a root failure is provably warning-free — each root shape arrives before any entry below the root is visited)", warnings)
	}
}

// The other root-failure shape fs.WalkDir can deliver — a failed initial
// Stat(root), arriving with d == nil rather than through ReadDir — is equally
// fatal. The fs.FS contract permits either shape, so each is pinned.
func TestDiscoverRootStatFailureIsFatal(t *testing.T) {
	fsys := statFailWalkFS{m: fstest.MapFS{"file.txt": &fstest.MapFile{Data: []byte("x")}}, failPath: "."}

	got, warnings, err := Discover(fsys, nil)
	if err == nil {
		t.Fatal("Discover() error = nil, want non-nil (a root Stat failure must stay fatal)")
	}
	if len(got.Sources) != 0 || len(got.PluginRoots) != 0 {
		t.Fatalf("Discover() result = %+v, want zero Result on a root failure", got)
	}
	if len(warnings) != 0 {
		t.Fatalf("Discover() warnings = %+v, want none", warnings)
	}
}

// Plugin roots lexically before and after the failing directory both survive,
// so a below-root failure blinds neither side of the walk.
func TestDiscoverBelowRootFailureKeepsPluginRootsOnBothSides(t *testing.T) {
	fsys := failingFS{
		m: fstest.MapFS{
			"a/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			"broken/file.txt":              &fstest.MapFile{Data: []byte("x")},
			"z/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
		},
		failDir: "broken",
	}

	got, warnings, err := Discover(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Fatal("Discover() warnings = none, want a warning for the unreadable broken/ directory")
	}

	want := []string{"a", "z"}
	if len(got.PluginRoots) != len(want) {
		t.Fatalf("Discover() PluginRoots = %v, want %v (roots on both sides of the failing directory)", got.PluginRoots, want)
	}
	for i, p := range want {
		if got.PluginRoots[i] != p {
			t.Fatalf("Discover() PluginRoots = %v, want %v", got.PluginRoots, want)
		}
	}
}

// singleProjectFS is shaped to prove recursive WalkDir semantics rather than
// a single-segment glob.
func singleProjectFS() fstest.MapFS {
	return fstest.MapFS{
		".mcp.json":                   &fstest.MapFile{Data: []byte("{}")},
		".claude/settings.json":       &fstest.MapFile{Data: []byte("{}")},
		".claude/settings.local.json": &fstest.MapFile{Data: []byte("{}")},
		".claude/agents/x.md":         &fstest.MapFile{Data: []byte("# x")},
		".claude/skills/a/b/c.md":     &fstest.MapFile{Data: []byte("# c")},
		".claude/skills/a/b/c.sh":     &fstest.MapFile{Data: []byte("#!/bin/sh")},
		".claude/commands/y.md":       &fstest.MapFile{Data: []byte("# y")},
	}
}

func TestDiscover_SingleProjectSources(t *testing.T) {
	got, _, err := Discover(singleProjectFS(), []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	wantPaths := []string{
		".mcp.json",
		".claude/settings.json",
		".claude/settings.local.json",
		".claude/agents/x.md",
		".claude/skills/a/b/c.md",
		".claude/skills/a/b/c.sh",
		".claude/commands/y.md",
	}
	if len(got.Sources) != len(wantPaths) {
		t.Fatalf("Sources = %+v (len %d), want %d entries", got.Sources, len(got.Sources), len(wantPaths))
	}
	byPath := map[string]adapter.AgentID{}
	for _, s := range got.Sources {
		byPath[s.Path] = s.Agent
	}
	for _, p := range wantPaths {
		agent, ok := byPath[p]
		if !ok {
			t.Fatalf("Sources missing expected path %q; got %+v", p, got.Sources)
		}
		if agent != adapter.AgentClaudeCode {
			t.Fatalf("Source[%q].Agent = %q, want %q", p, agent, adapter.AgentClaudeCode)
		}
	}

	if _, ok := byPath[".claude/skills/a/b/c.md"]; !ok {
		t.Fatal("deeply nested .claude/skills/a/b/c.md not found as a distinct Source")
	}
	if _, ok := byPath[".claude/commands/y.md"]; !ok {
		t.Fatal(".claude/commands/y.md not found as a distinct Source")
	}
}

func TestDiscover_PluginRoots(t *testing.T) {
	tests := []struct {
		name        string
		fsys        fstest.MapFS
		wantRoots   []string
		wantSources []string
	}{
		{
			name: "root plugin manifest flags dot as plugin root",
			fsys: fstest.MapFS{
				".claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots:   []string{"."},
			wantSources: []string{".claude-plugin/plugin.json"},
		},
		{
			name: "nested plugin manifest flags containing directory",
			fsys: fstest.MapFS{
				"plugins/foo/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots:   []string{"plugins/foo"},
			wantSources: []string{"plugins/foo/.claude-plugin/plugin.json"},
		},
		{
			name: "claude-plugin dir without manifest is not flagged",
			fsys: fstest.MapFS{
				".claude-plugin/README.md": &fstest.MapFile{Data: []byte("not a manifest")},
			},
			wantRoots: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := Discover(tt.fsys, []adapter.Adapter{stubAdapter{}})
			if err != nil {
				t.Fatalf("Discover() error = %v, want nil", err)
			}
			if len(got.PluginRoots) != len(tt.wantRoots) {
				t.Fatalf("PluginRoots = %v, want %v", got.PluginRoots, tt.wantRoots)
			}
			for i, r := range tt.wantRoots {
				if got.PluginRoots[i] != r {
					t.Fatalf("PluginRoots = %v, want %v", got.PluginRoots, tt.wantRoots)
				}
			}
			if len(got.Sources) != len(tt.wantSources) {
				t.Fatalf("Sources = %+v, want %v", got.Sources, tt.wantSources)
			}
			for i, s := range tt.wantSources {
				if got.Sources[i].Path != s {
					t.Fatalf("Sources = %+v, want %v", got.Sources, tt.wantSources)
				}
			}
		})
	}
}

// The marker's presence is the whole signal here: a decoy DIRECTORY named
// plugin.json must still flag its root, or a hostile repo buys silence with
// nothing more than the entry's file type.
func TestDiscoverDirectoryTypedManifestStillFlagsPluginRoot(t *testing.T) {
	fsys := fstest.MapFS{
		"plugins/foo/.claude-plugin/plugin.json": &fstest.MapFile{Mode: fs.ModeDir},
	}

	got, _, err := Discover(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if len(got.PluginRoots) != 1 || got.PluginRoots[0] != "plugins/foo" {
		t.Fatalf("Discover() PluginRoots = %v, want [plugins/foo]", got.PluginRoots)
	}
}

// Result.Sources is sorted by (Path, Agent) regardless of adapter input order.
func TestDiscover_Determinism(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json":             &fstest.MapFile{Data: []byte("{}")},
		".claude/settings.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Discover(fsys, []adapter.Adapter{stubAdapterAlt{}, stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}

	// Path sorts first: ".claude/settings.json" < ".mcp.json" lexically.
	// Both adapters match .mcp.json; claude-code < other-agent breaks the
	// tie there, so it must sort first despite being passed second.
	if len(got.Sources) != 3 {
		t.Fatalf("Sources = %+v (len %d), want 3 entries", got.Sources, len(got.Sources))
	}
	if got.Sources[0].Path != ".claude/settings.json" {
		t.Fatalf("Sources[0] = %+v, want Path .claude/settings.json (Path-first sort)", got.Sources[0])
	}
	if got.Sources[1].Path != ".mcp.json" || got.Sources[1].Agent != adapter.AgentClaudeCode {
		t.Fatalf("Sources[1] = %+v, want {.mcp.json claude-code} (Agent tie-break)", got.Sources[1])
	}
	if got.Sources[2].Path != ".mcp.json" || got.Sources[2].Agent != adapter.AgentID("other-agent") {
		t.Fatalf("Sources[2] = %+v, want {.mcp.json other-agent} (Agent tie-break)", got.Sources[2])
	}
}

func TestDiscoverBuildsEachAdaptersSignaturesOncePerWalk(t *testing.T) {
	fsys := fstest.MapFS{}
	for i := range 64 {
		fsys[fmt.Sprintf("pkg%d/SKILL.md", i)] = &fstest.MapFile{Data: []byte("x")}
	}
	var claudeCalls, otherCalls int
	adapters := []adapter.Adapter{
		countingAdapter{agent: adapter.AgentClaudeCode, calls: &claudeCalls},
		countingAdapter{agent: adapter.AgentID("other-agent"), calls: &otherCalls},
	}

	got, _, err := Discover(fsys, adapters)
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if len(got.Sources) != 2*len(fsys) {
		t.Fatalf("Discover() found %d Sources, want %d (every file matched by both adapters)", len(got.Sources), 2*len(fsys))
	}
	if claudeCalls != 1 || otherCalls != 1 {
		t.Fatalf("Signatures() calls = %d and %d over %d files, want 1 per adapter per walk", claudeCalls, otherCalls, len(fsys))
	}
}

func TestDiscover_Dedup(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Discover(fsys, []adapter.Adapter{stubAdapter{}, stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if len(got.Sources) != 1 {
		t.Fatalf("Sources = %+v (len %d), want exactly 1 (deduplicated)", got.Sources, len(got.Sources))
	}
	if got.Sources[0] != (Source{Path: ".mcp.json", Agent: adapter.AgentClaudeCode}) {
		t.Fatalf("Sources[0] = %+v, want {.mcp.json claude-code}", got.Sources[0])
	}
}

// A relative symlink to an in-tree directory is descended: a source nested
// inside the resolved target is discovered under the symlink's own path,
// beyond what fs.WalkDir's documented contract gives a symlink entry.
func TestDiscover_SymlinkedDirectoryResolvingInTreeIsDescended(t *testing.T) {
	fsys := fstest.MapFS{
		"real-target/nested/file.md": &fstest.MapFile{Data: []byte("# hi")},
		".claude":                    &fstest.MapFile{Data: []byte("real-target"), Mode: fs.ModeSymlink},
	}

	got, warnings, err := Discover(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Discover() warnings = %v, want none", warnings)
	}

	found := false
	for _, s := range got.Sources {
		if s.Path == ".claude/nested/file.md" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Sources = %+v, want .claude/nested/file.md discovered through the resolved symlink", got.Sources)
	}
}

// Discover reports no Source for .claude.json, at root or nested, against a
// fixture that DOES contain it, so the absence is not vacuous.
// See TestSignatures_ClaudeJSONMatchesNoSignature for why.
func TestDiscover_UserScopeNonGoal(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json":         &fstest.MapFile{Data: []byte("{}")},
		".claude/.claude.json": &fstest.MapFile{Data: []byte("{}")},
	}
	got, _, err := Discover(fsys, []adapter.Adapter{claude.New()})
	if err != nil {
		t.Fatalf("Discover() error = %v, want nil", err)
	}
	for _, s := range got.Sources {
		if s.Path == ".claude.json" || s.Path == ".claude/.claude.json" {
			t.Fatalf("Sources contains %q; ~/.claude.json is out of scope", s.Path)
		}
	}
}

// pluginSigAdapter stands in for any agent whose plugins live under its own
// manifest directory. The literal differs from Claude's on purpose: a
// predicate reading ".claude-plugin" out of the code rather than out of this
// declaration would flag nothing here.
type pluginSigAdapter struct{}

func (pluginSigAdapter) Agent() adapter.AgentID { return adapter.AgentID("other-agent") }

func (pluginSigAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{Dir: ".cursor-plugin", File: "plugin.json", AnyDepth: true},
		{Dir: ".cursor-plugin", File: "marketplace.json", AnyDepth: true},
		{Dir: ".cursor/skills", AnyDepth: true},
		{File: "plugin.json", AnyDepth: true},
		{Dir: ".anchored-plugin", File: "plugin.json"},
	}
}

func (pluginSigAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

var _ adapter.Adapter = pluginSigAdapter{}

// A plugin root is whatever an adapter's depth-agnostic file signature says it
// is. Hardcoding one agent's manifest names means discovery flags a root the
// owning adapter never declared, and stays blind to one it did.
func TestDiscoverDerivesPluginRootsFromDepthAgnosticSignatures(t *testing.T) {
	tests := []struct {
		name      string
		adapters  []adapter.Adapter
		fsys      fstest.MapFS
		wantRoots []string
	}{
		{
			name:     "a declared manifest under another agent's directory name",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"vendor/pkg/.cursor-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: []string{"vendor/pkg"},
		},
		{
			name:     "an undeclared manifest is not a root",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"vendor/pkg/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: nil,
		},
		{
			name:     "a manifest reachable at one depth only roots nothing",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				".anchored-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: nil,
		},
		{
			name:     "a manifest name with no directory to anchor it roots nothing",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"vendor/pkg/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: nil,
		},
		{
			name:     "a directory-typed marker names no manifest, so it roots nothing",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"apps/web/.cursor/skills/demo/SKILL.md": &fstest.MapFile{Data: []byte("x")},
			},
			wantRoots: nil,
		},
		{
			name:     "a marketplace catalogue is not itself a plugin",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"mkt/.cursor-plugin/marketplace.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: nil,
		},
		{
			name:     "a catalogued plugin roots, its catalogue does not",
			adapters: []adapter.Adapter{pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"mkt/.cursor-plugin/marketplace.json": &fstest.MapFile{Data: []byte("{}")},
				"mkt/a/.cursor-plugin/plugin.json":    &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: []string{"mkt/a"},
		},
		{
			name:     "each adapter contributes its own manifest name",
			adapters: []adapter.Adapter{stubAdapter{}, pluginSigAdapter{}},
			fsys: fstest.MapFS{
				"a/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
				"b/.cursor-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
			},
			wantRoots: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := Discover(tt.fsys, tt.adapters)
			if err != nil {
				t.Fatalf("Discover() error = %v, want nil", err)
			}
			if len(got.PluginRoots) != len(tt.wantRoots) {
				t.Fatalf("PluginRoots = %v, want %v", got.PluginRoots, tt.wantRoots)
			}
			for i, r := range tt.wantRoots {
				if got.PluginRoots[i] != r {
					t.Fatalf("PluginRoots = %v, want %v", got.PluginRoots, tt.wantRoots)
				}
			}
		})
	}
}

type signedAdapter struct {
	agent adapter.AgentID
	sigs  []adapter.Signature
}

func (a signedAdapter) Agent() adapter.AgentID          { return a.agent }
func (a signedAdapter) Signatures() []adapter.Signature { return a.sigs }

func (signedAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

// A link stopped mid-descent and one refused before resolving both yield
// Sources; the anchor match respects a segment boundary, and an any-depth
// signature is no anchor.
func TestDiscover_CappedLinkStillYieldsTheAdaptersAnchoredBeneathIt(t *testing.T) {
	adapters := []adapter.Adapter{
		signedAdapter{agent: adapter.AgentCursor, sigs: []adapter.Signature{{Dir: ".cursor", File: "mcp.json"}}},
		signedAdapter{agent: adapter.AgentClaudeCode, sigs: []adapter.Signature{{Dir: ".cursor/skills", Recursive: true}}},
		signedAdapter{agent: adapter.AgentCodex, sigs: []adapter.Signature{{Dir: ".cursor-x", File: "mcp.json"}}},
		signedAdapter{agent: adapter.AgentID("other-agent"), sigs: []adapter.Signature{{Dir: ".cursor/plugin", File: "plugin.json", AnyDepth: true}}},
	}
	tests := []struct {
		name  string
		links []string
		files int
	}{
		{"stopped mid-descent", []string{".a-big", ".cursor"}, symlinkVisitFloor/2 + 10},
		{"refused before resolving", []string{".a-big", ".b-big", ".cursor"}, symlinkVisitFloor/2 - 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{"data/mcp.json": &fstest.MapFile{Data: []byte("{}")}}
			for i := range tt.files {
				fsys[fmt.Sprintf("data/aaa/f%05d", i)] = &fstest.MapFile{Data: []byte("x")}
			}
			for _, l := range tt.links {
				fsys[l] = &fstest.MapFile{Data: []byte("data"), Mode: fs.ModeSymlink}
			}

			got, warnings, err := Discover(fsys, adapters)
			if err != nil {
				t.Fatalf("Discover() error = %v, want nil", err)
			}
			capped := false
			for _, w := range warnings {
				capped = capped || w.File == ".cursor" && errors.Is(w.Err, adapter.ErrUnreadable)
			}
			if !capped {
				t.Fatalf("warnings = %d, want one refusing .cursor", len(warnings))
			}
			want := []Source{{Path: ".cursor", Agent: adapter.AgentClaudeCode}, {Path: ".cursor", Agent: adapter.AgentCursor}}
			if fmt.Sprint(got.Sources) != fmt.Sprint(want) {
				t.Fatalf("Sources = %v, want %v", got.Sources, want)
			}
		})
	}
}
