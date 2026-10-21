package main

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/adapters/codex"
	"github.com/manifold-security/agentaudit/internal/adapters/cursor"
	"github.com/manifold-security/agentaudit/internal/ir"
)

type stubBaseAdapter struct{ agent adapter.AgentID }

func (s stubBaseAdapter) Agent() adapter.AgentID          { return s.agent }
func (s stubBaseAdapter) Signatures() []adapter.Signature { return nil }
func (s stubBaseAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

type stubGlobalAdapter struct {
	stubBaseAdapter
	cfg adapter.GlobalConfig
}

func (s stubGlobalAdapter) GlobalConfig() adapter.GlobalConfig { return s.cfg }

func (s stubGlobalAdapter) ParseGlobal(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

func TestGlobalSpecs(t *testing.T) {
	t.Run("no GlobalScoped adapter yields no spec", func(t *testing.T) {
		got, err := globalSpecs([]adapter.Adapter{stubBaseAdapter{agent: "a"}})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 0 {
			t.Fatalf("globalSpecs() = %v, want none", got)
		}
	})

	t.Run("one GlobalScoped adapter yields one spec with its admitted set", func(t *testing.T) {
		a := stubGlobalAdapter{
			stubBaseAdapter{agent: "a"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".claude"}},
		}
		got, err := globalSpecs([]adapter.Adapter{a})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 1 {
			t.Fatalf("globalSpecs() len = %d, want 1", len(got))
		}
		if got[0].base != adapter.BaseHome {
			t.Fatalf("globalSpecs()[0].base = %q, want %q", got[0].base, adapter.BaseHome)
		}
		if len(got[0].allow) != 1 || !got[0].allow[".claude"] {
			t.Fatalf("globalSpecs()[0].allow = %v, want exactly {\".claude\"}", got[0].allow)
		}
	})

	t.Run("two adapters on the same base union their admitted sets into one spec", func(t *testing.T) {
		a1 := stubGlobalAdapter{
			stubBaseAdapter{agent: "a"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".claude"}},
		}
		a2 := stubGlobalAdapter{
			stubBaseAdapter{agent: "b"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".config"}},
		}
		got, err := globalSpecs([]adapter.Adapter{a1, a2})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 1 {
			t.Fatalf("globalSpecs() len = %d, want 1", len(got))
		}
		want := map[string]bool{".claude": true, ".config": true}
		if len(got[0].allow) != len(want) || !got[0].allow[".claude"] || !got[0].allow[".config"] {
			t.Fatalf("globalSpecs()[0].allow = %v, want %v", got[0].allow, want)
		}
	})

	t.Run("a non-GlobalScoped adapter alongside a GlobalScoped one is ignored", func(t *testing.T) {
		a := stubGlobalAdapter{
			stubBaseAdapter{agent: "a"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".claude"}},
		}
		got, err := globalSpecs([]adapter.Adapter{stubBaseAdapter{agent: "x"}, a})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 1 {
			t.Fatalf("globalSpecs() len = %d, want 1", len(got))
		}
	})

	t.Run("order is first appearance across distinct bases", func(t *testing.T) {
		second := adapter.Base("other-base")
		a1 := stubGlobalAdapter{
			stubBaseAdapter{agent: "a"},
			adapter.GlobalConfig{Base: second, Entries: []string{".other"}},
		}
		a2 := stubGlobalAdapter{
			stubBaseAdapter{agent: "b"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".claude"}},
		}
		got, err := globalSpecs([]adapter.Adapter{a1, a2})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 2 {
			t.Fatalf("globalSpecs() len = %d, want 2", len(got))
		}
		if got[0].base != second || got[1].base != adapter.BaseHome {
			t.Fatalf("globalSpecs() bases = [%q, %q], want [%q, %q] in first-appearance order", got[0].base, got[1].base, second, adapter.BaseHome)
		}
	})

	t.Run("a multi-segment entry is admitted as a declared prefix", func(t *testing.T) {
		a := stubGlobalAdapter{
			stubBaseAdapter{agent: "a"},
			adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{".codeium/windsurf"}},
		}
		got, err := globalSpecs([]adapter.Adapter{a})
		if err != nil {
			t.Fatalf("globalSpecs() error = %v, want nil", err)
		}
		if len(got) != 1 || !got[0].allow[".codeium/windsurf"] {
			t.Fatalf("globalSpecs() = %v, want one spec admitting %q", got, ".codeium/windsurf")
		}
	})

	malformed := []string{"", ".", "..", "../x", "x/..", "x/../y", "/abs", "x/", "x//y"}
	for _, entry := range malformed {
		t.Run("a malformed entry is a declaration error: "+entry, func(t *testing.T) {
			a := stubGlobalAdapter{
				stubBaseAdapter{agent: "evil"},
				adapter.GlobalConfig{Base: adapter.BaseHome, Entries: []string{entry}},
			}
			_, err := globalSpecs([]adapter.Adapter{a})
			if err == nil {
				t.Fatalf("globalSpecs() error = nil, want an error for entry %q", entry)
			}
			if !strings.HasPrefix(err.Error(), "agentaudit:") {
				t.Fatalf("globalSpecs() error = %q, want an agentaudit:-prefixed message", err)
			}
			if !strings.Contains(err.Error(), "evil") {
				t.Fatalf("globalSpecs() error = %q, want it to name the declaring adapter", err)
			}
		})
	}
}

// claudeGlobalReach maps each Claude signature to the paths under the global
// Base that Claude Code loads it from; an empty list marks one deliberately
// not global config. A signature with no entry here fails
// TestGlobalConfig_ReachesEveryClaudeSignatureLoadPath, which is the point.
var claudeGlobalReach = map[adapter.Signature][]string{
	{Dir: ".claude", File: "settings.json", Recursive: false}:       {".claude/settings.json"},
	{Dir: ".claude", File: "settings.local.json", Recursive: false}: {".claude/settings.local.json"},
	// ~/.mcp.json is not Claude global config.
	{Dir: ".", File: ".mcp.json", Recursive: false}: nil,
	{Dir: ".claude/agents", Recursive: true}:        {".claude/agents", ".claude/agents/deep/a.md"},
	{Dir: ".claude/skills", Recursive: true}:        {".claude/skills", ".claude/skills/s/SKILL.md"},
	{Dir: ".claude/commands", Recursive: true}:      {".claude/commands", ".claude/commands/deep/c.md"},
	// The manifest sits at an unbounded depth under ~/.claude/plugins.
	{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true}: {
		".claude/plugins/cache/p/.claude-plugin/plugin.json",
		".claude/plugins/marketplaces/m/plugins/p/.claude-plugin/plugin.json",
	},
}

func TestGlobalConfig_ReachesEveryClaudeSignatureLoadPath(t *testing.T) {
	a := claude.New()
	specs, err := globalSpecs([]adapter.Adapter{a})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	if len(specs) != 1 {
		t.Fatalf("globalSpecs() len = %d, want 1", len(specs))
	}
	m := maskFS{parent: fstest.MapFS{}, allow: specs[0].allow}

	sigs := a.Signatures()
	if len(sigs) == 0 {
		t.Fatal("Signatures() is empty; the reach guard inspected nothing")
	}
	for _, s := range sigs {
		paths, declared := claudeGlobalReach[s]
		if !declared {
			t.Errorf("signature %+v has no declared global reach; decide whether --global-config must read it", s)
			continue
		}
		for _, p := range paths {
			if !adapter.Matches(p, sigs) {
				t.Errorf("claudeGlobalReach lists %q, which no signature matches", p)
			}
			if err := m.admit(p); err != nil {
				t.Errorf("admit(%q) error = %v, want nil: the global mask no longer reaches a load path", p, err)
			}
		}
	}

	if err := m.admit(".claude.json"); err != nil {
		t.Errorf("admit(%q) error = %v, want nil", ".claude.json", err)
	}
}

// cursorGlobalReach twins claudeGlobalReach for the Cursor adapter. A Signature
// mapped to no path has no home-relative load path; what the mask admits
// follows from the entry set TestGlobalConfigDeclaresEveryCursorHomeEntry pins.
var cursorGlobalReach = map[adapter.Signature][]string{
	{Dir: ".cursor", File: "mcp.json"}:         {".cursor/mcp.json"},
	{Dir: ".cursor", File: "hooks.json"}:       {".cursor/hooks.json"},
	{Dir: ".cursor", File: "sandbox.json"}:     {".cursor/sandbox.json"},
	{Dir: ".cursor", File: "worktrees.json"}:   nil,
	{Dir: ".cursor", File: "environment.json"}: nil,
	{Dir: ".cursor", File: "cli.json"}:         nil,
	{Dir: ".cursor", File: "permissions.json"}: {".cursor/permissions.json"},
	{Dir: ".cursor/hooks", Recursive: true}:    {".cursor/hooks", ".cursor/hooks/boot.sh"},
	{Dir: ".cursor/skills", Recursive: true}:   {".cursor/skills", ".cursor/skills/s/SKILL.md"},
	{Dir: ".cursor/agents", Recursive: true}:   {".cursor/agents", ".cursor/agents/a.md"},
	{Dir: ".cursor-plugin", File: "plugin.json", AnyDepth: true}: {
		".cursor/plugins/local/p/.cursor-plugin/plugin.json",
	},
	{File: "plugin.json"}: nil,
}

func TestGlobalConfig_ReachesEveryCursorSignatureLoadPath(t *testing.T) {
	a := cursor.New()
	specs, err := globalSpecs([]adapter.Adapter{a})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	if len(specs) != 1 {
		t.Fatalf("globalSpecs() len = %d, want 1", len(specs))
	}
	m := maskFS{parent: fstest.MapFS{}, allow: specs[0].allow}

	sigs := a.Signatures()
	if len(sigs) == 0 {
		t.Fatal("Signatures() is empty; the reach guard inspected nothing")
	}
	for _, s := range sigs {
		paths, declared := cursorGlobalReach[s]
		if !declared {
			t.Errorf("signature %+v has no declared global reach; decide whether --global-config must read it", s)
			continue
		}
		for _, p := range paths {
			if !adapter.Matches(p, sigs) {
				t.Errorf("cursorGlobalReach lists %q, which no signature matches", p)
			}
			if err := m.admit(p); err != nil {
				t.Errorf("admit(%q) error = %v, want nil: the global mask no longer reaches a load path", p, err)
			}
		}
	}

	if err := m.admit(".cursor/cli-config.json"); err != nil {
		t.Errorf("admit(%q) error = %v, want nil", ".cursor/cli-config.json", err)
	}
}

// codexGlobalReach twins claudeGlobalReach for the Codex adapter.
var codexGlobalReach = map[adapter.Signature][]string{
	{Dir: ".codex", File: "config.toml"}: {".codex/config.toml"},
	{Dir: ".codex", File: "hooks.json"}:  {".codex/hooks.json"},
	{Dir: ".agents/skills", Recursive: true}: {
		".agents/skills",
		".agents/skills/s/SKILL.md",
	},
}

func TestGlobalConfig_ReachesEveryCodexSignatureLoadPath(t *testing.T) {
	a := codex.New()
	specs, err := globalSpecs([]adapter.Adapter{a})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	if len(specs) != 1 {
		t.Fatalf("globalSpecs() len = %d, want 1", len(specs))
	}
	m := maskFS{parent: fstest.MapFS{}, allow: specs[0].allow}

	sigs := a.Signatures()
	if len(sigs) == 0 {
		t.Fatal("Signatures() is empty; the reach guard inspected nothing")
	}
	for _, s := range sigs {
		paths, declared := codexGlobalReach[s]
		if !declared {
			t.Errorf("signature %+v has no declared global reach; decide whether --global-config must read it", s)
			continue
		}
		for _, p := range paths {
			if !adapter.Matches(p, sigs) {
				t.Errorf("codexGlobalReach lists %q, which no signature matches", p)
			}
			if err := m.admit(p); err != nil {
				t.Errorf("admit(%q) error = %v, want nil: the global mask no longer reaches a load path", p, err)
			}
		}
	}
}

// The home permissions file is read by Parse, which the global pass runs
// beside ParseGlobal. A mask admitting the path while no parser reads it
// prints a clean home over a file the agent loads.
func TestGlobalBlocks_CursorHomePermissionsFileIsRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{home: fstest.MapFS{
		".cursor/permissions.json": &fstest.MapFile{Data: []byte(`{"terminalAllowlist":["sudo"]}`)},
	}})

	blocks, _, err := globalBlocks([]adapter.Adapter{cursor.New()}, noopWarn)
	if err != nil {
		t.Fatalf("globalBlocks() error = %v, want nil", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("globalBlocks() len = %d, want 1", len(blocks))
	}
	findings := blocks[0].Report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() = %+v, want exactly the home permissions grant", findings)
	}
	want := ".cursor/permissions.json:terminalAllowlist[0]"
	got := findings[0].Capability.Provenance.File + ":" + findings[0].Capability.Provenance.Key
	if got != want {
		t.Fatalf("finding provenance = %q, want %q", got, want)
	}
}

// The home .codex/config.toml reaches the global pass through the entry
// codex declares, and its sandbox_mode grant comes back as the finding.
func TestGlobalBlocks_CodexHomeConfigFileIsRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{home: fstest.MapFS{
		".codex/config.toml": &fstest.MapFile{Data: []byte("sandbox_mode = \"danger-full-access\"\n")},
	}})

	blocks, _, err := globalBlocks([]adapter.Adapter{codex.New()}, noopWarn)
	if err != nil {
		t.Fatalf("globalBlocks() error = %v, want nil", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("globalBlocks() len = %d, want 1", len(blocks))
	}
	findings := blocks[0].Report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() = %+v, want exactly the home sandbox grant", findings)
	}
	want := ".codex/config.toml:sandbox_mode"
	got := findings[0].Capability.Provenance.File + ":" + findings[0].Capability.Provenance.Key
	if got != want {
		t.Fatalf("finding provenance = %q, want %q", got, want)
	}
}

func TestGlobalConfig_RuntimeStateSiblingsAreNotAdmitted(t *testing.T) {
	specs, err := globalSpecs([]adapter.Adapter{claude.New()})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	m := maskFS{parent: poisonFS{}, allow: specs[0].allow}

	for _, p := range []string{
		".claude/projects/-Users-x/transcript.jsonl",
		".claude/debug/latest",
		".claude/sessions/s.json",
		".claude/history.jsonl",
		".claude/shell-snapshots/snap.sh",
		".claude/paste-cache/p.txt",
		".claude/file-history/f.json",
		".claude/todos/t.json",
	} {
		if _, err := m.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist", p, err)
		}
	}
}

// A real ~/.cursor carries runtime state beside the declared config files —
// chat transcripts, telemetry and cache the PRD says a security tool has no
// business reading — plus basenames constructed to probe the mask's segment
// boundary. Neither class is admitted.
func TestGlobalConfig_CursorRuntimeStateSiblingsAreNotAdmitted(t *testing.T) {
	specs, err := globalSpecs([]adapter.Adapter{cursor.New()})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	if len(specs) != 1 {
		t.Fatalf("globalSpecs() len = %d, want 1", len(specs))
	}
	m := maskFS{parent: poisonFS{}, allow: specs[0].allow}

	for _, p := range []string{
		".cursor/chats/c.json",
		".cursor/ai-tracking/t.json",
		".cursor/projects/p.json",
		".cursor/statsig-cache.json",
		".cursor/agent-cli-state.json",
		".cursor/skills-cursor/x",
		".cursor/worktrees/w.json",
		".cursor/sdk/auth.json",
		".cursor-evil/mcp.json",
		".cursor/mcp.json.bak",
		".cursor/cli.json",
		".cursor/plugins/other/p/.cursor-plugin/plugin.json",
	} {
		if _, err := m.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist", p, err)
		}
	}
}

// A real ~/.codex's runtime state, auth.json and its plaintext access tokens
// included, is not admitted by the mask.
func TestGlobalConfig_CodexRuntimeStateSiblingsAreNotAdmitted(t *testing.T) {
	specs, err := globalSpecs([]adapter.Adapter{codex.New()})
	if err != nil {
		t.Fatalf("globalSpecs() error = %v, want nil", err)
	}
	if len(specs) != 1 {
		t.Fatalf("globalSpecs() len = %d, want 1", len(specs))
	}
	m := maskFS{parent: poisonFS{}, allow: specs[0].allow}

	for _, p := range []string{
		// Real ~/.codex runtime state.
		".codex/auth.json",
		".codex/history.jsonl",
		".codex/log/latest.log",
		".codex/sessions/s.json",
		".codex/memories/m.json",
		// Constructed boundary probes.
		".codex-evil/config.toml",
		".codex/config.toml.bak",
		".codex/hooks.json.bak",
		".agents/skills-evil/x",
	} {
		if _, err := m.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Stat(%q) error = %v, want fs.ErrNotExist", p, err)
		}
	}
}

func TestResolveBase(t *testing.T) {
	t.Run("BaseHome resolves to $HOME, cleaned", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home+"//sub/..")

		got, err := resolveBase(adapter.BaseHome)
		if err != nil {
			t.Fatalf("resolveBase() error = %v, want nil", err)
		}
		want := filepath.Clean(home + "//sub/..")
		if got != want {
			t.Fatalf("resolveBase() = %q, want %q", got, want)
		}
	})

	t.Run("an unknown base is a usage fault", func(t *testing.T) {
		_, err := resolveBase(adapter.Base("no-such-base"))
		if err == nil {
			t.Fatalf("resolveBase() error = nil, want an error")
		}
		if !strings.HasPrefix(err.Error(), "agentaudit:") {
			t.Fatalf("resolveBase() error = %q, want an agentaudit:-prefixed message", err)
		}
	})

	t.Run("a relative HOME still resolves to an absolute path", func(t *testing.T) {
		wd := t.TempDir()
		t.Chdir(wd)
		t.Setenv("HOME", "relhome")

		got, err := resolveBase(adapter.BaseHome)
		if err != nil {
			t.Fatalf("resolveBase() error = %v, want nil", err)
		}
		want := filepath.Join(wd, "relhome")
		if got != want {
			t.Fatalf("resolveBase() = %q, want %q", got, want)
		}
	})
}

func noopWarn(error) {}

// readFaultFS is the shape an unreadable-but-present file produces.
type readFaultFS struct {
	m        fstest.MapFS
	failPath string
}

func (f readFaultFS) Open(name string) (fs.File, error)     { return f.m.Open(name) }
func (f readFaultFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f readFaultFS) ReadFile(name string) ([]byte, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrPermission}
	}
	return f.m.ReadFile(name)
}

// danglingLinkFS is the shape a symlink to a missing target produces: Lstat
// answers from the link itself while Stat resolves through it and finds
// nothing. fs.ReadLinkFS is satisfied deliberately — fs.Lstat falls back to
// fs.Stat on an FS that is not one, and the fixture would then exercise the
// very call it exists to rule out.
type danglingLinkFS struct {
	m    fstest.MapFS
	link string
}

func (f danglingLinkFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f danglingLinkFS) Stat(name string) (fs.FileInfo, error) {
	if name == f.link {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return f.m.Stat(name)
}

func (f danglingLinkFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }

func (f danglingLinkFS) ReadLink(name string) (string, error) { return f.m.ReadLink(name) }

func danglingClaudeJSON() danglingLinkFS {
	return danglingLinkFS{
		m:    fstest.MapFS{".claude.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("nowhere.json")}},
		link: ".claude.json",
	}
}

// A dangling symlink at a declared entry reads as present through maskFS,
// which forwards the question as an Lstat rather than collapsing it into a
// resolving Stat.
func TestAnyPresent_DanglingSymlink(t *testing.T) {
	allow := map[string]bool{".claude.json": true}
	masked := maskFS{parent: danglingClaudeJSON(), allow: allow}

	if _, ok := fs.FS(danglingClaudeJSON()).(fs.ReadLinkFS); !ok {
		t.Fatal("danglingLinkFS is not an fs.ReadLinkFS, so fs.Lstat would fall back to fs.Stat and the fixture would prove nothing")
	}

	var pathErr *fs.PathError
	_, statErr := fs.Stat(masked, ".claude.json")
	if !errors.As(statErr, &pathErr) || pathErr.Op != "stat" || !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("Stat(%q) error = %v, want a %q PathError wrapping fs.ErrNotExist", ".claude.json", statErr, "stat")
	}
	if _, err := fs.Lstat(masked, ".claude.json"); err != nil {
		t.Fatalf("Lstat(%q) error = %v, want nil: the link entry itself is readable", ".claude.json", err)
	}

	if !anyPresent(masked, allow) {
		t.Fatal("anyPresent() = false, want true")
	}
}

// The companion arm: an entry with no directory entry at all is absent, so
// the presence above is the link's doing rather than a gate that never says
// no.
func TestAnyPresent_NoDeclaredEntry(t *testing.T) {
	allow := map[string]bool{".claude.json": true}
	masked := maskFS{parent: fstest.MapFS{}, allow: allow}

	if anyPresent(masked, allow) {
		t.Fatal("anyPresent() = true, want false")
	}
}

func TestGlobalBlocks(t *testing.T) {
	t.Run("a populated home yields one block with the hook's provenance", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{home: fstest.MapFS{
			".claude/settings.json": &fstest.MapFile{Data: []byte(
				`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]}}`,
			)},
		}})

		blocks, _, err := globalBlocks([]adapter.Adapter{claude.New()}, noopWarn)
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil", err)
		}
		if len(blocks) != 1 {
			t.Fatalf("globalBlocks() len = %d, want 1", len(blocks))
		}
		if blocks[0].Path != home {
			t.Fatalf("globalBlocks()[0].Path = %q, want %q", blocks[0].Path, home)
		}
		findings := blocks[0].Report.Findings()
		if len(findings) != 1 {
			t.Fatalf("globalBlocks()[0].Report.Findings() len = %d, want 1", len(findings))
		}
		if got := findings[0].Capability.Provenance.File; got != ".claude/settings.json" {
			t.Fatalf("finding provenance file = %q, want %q", got, ".claude/settings.json")
		}
	})

	t.Run("a home with no declared global entry yields no block and no warning", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{home: fstest.MapFS{}})

		var warned []error
		blocks, _, err := globalBlocks([]adapter.Adapter{claude.New()}, func(e error) { warned = append(warned, e) })
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil", err)
		}
		if len(blocks) != 0 {
			t.Fatalf("globalBlocks() len = %d, want 0", len(blocks))
		}
		if len(warned) != 0 {
			t.Fatalf("warn calls = %v, want none: an absent global config is not a fault", warned)
		}
	})

	t.Run("siblings outside .claude never surface and cost no unreadable source", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{home: fstest.MapFS{
			".claude/settings.json": &fstest.MapFile{Data: []byte(
				`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]}}`,
			)},
			".mcp.json":                 &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx"}}}`)},
			"Downloads/clone/.mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx"}}}`)},
		}})

		blocks, _, err := globalBlocks([]adapter.Adapter{claude.New()}, noopWarn)
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil", err)
		}
		if len(blocks) != 1 {
			t.Fatalf("globalBlocks() len = %d, want 1", len(blocks))
		}
		if got := blocks[0].Report.Counts().UnreadableSources; got != 0 {
			t.Fatalf("UnreadableSources() = %d, want 0", got)
		}
		findings := blocks[0].Report.Findings()
		if len(findings) != 1 || findings[0].Capability.Provenance.File != ".claude/settings.json" {
			t.Fatalf("Findings() = %+v, want exactly the .claude/settings.json hook", findings)
		}
	})

	t.Run("a ReadDir fault on the declared entry's directory still renders a degraded block", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{home: degradedTargetFS{
			m:       fstest.MapFS{".claude/settings.json": &fstest.MapFile{}},
			failDir: ".claude",
		}})

		blocks, _, err := globalBlocks([]adapter.Adapter{claude.New()}, noopWarn)
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil", err)
		}
		if len(blocks) != 1 {
			t.Fatalf("globalBlocks() len = %d, want 1 (a read fault is PRESENT, not absent)", len(blocks))
		}
		if got := blocks[0].Report.Counts().UnreadableSources; got != 1 {
			t.Fatalf("UnreadableSources() = %d, want 1", got)
		}
	})

	t.Run("a dangling symlink on the declared entry still renders a block that names it", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{home: danglingClaudeJSON()})

		var warned []error
		blocks, _, err := globalBlocks([]adapter.Adapter{claude.New()}, func(e error) { warned = append(warned, e) })
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil", err)
		}
		if len(blocks) != 1 {
			t.Fatalf("globalBlocks() len = %d, want 1 (a dangling link is PRESENT, not absent)", len(blocks))
		}
		if got := blocks[0].Report.Counts().UnreadableSources; got != 0 {
			t.Fatalf("UnreadableSources() = %d, want 0: a missing target hides nothing the agent could read", got)
		}
		if len(warned) == 0 {
			t.Fatal("warn calls = none, want the dangling entry named on the warn channel")
		}
		var named bool
		for _, w := range warned {
			if strings.Contains(w.Error(), ".claude.json") {
				named = true
			}
		}
		if !named {
			t.Fatalf("warnings = %v, want one naming %q", warned, ".claude.json")
		}
	})

	t.Run("an openTarget failure for the resolved base is warned and yields no block", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		withOpenTarget(t, map[string]fs.FS{}) // no fixture registered for home

		var warned []error
		blocks, unreadable, err := globalBlocks([]adapter.Adapter{claude.New()}, func(e error) { warned = append(warned, e) })
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil: a Base fault is warned, not returned", err)
		}
		if len(blocks) != 0 {
			t.Fatalf("globalBlocks() len = %d, want 0", len(blocks))
		}
		if !unreadable {
			t.Fatal("globalBlocks() unreadable = false, want true for a Base that will not open")
		}
		if len(warned) != 1 {
			t.Fatalf("warn calls = %v, want exactly 1 naming the fault", warned)
		}
		if !strings.Contains(warned[0].Error(), home) {
			t.Fatalf("warning = %q, want it to name the unopenable base %q", warned[0].Error(), home)
		}
	})

	t.Run("an unresolvable Base is warned and yields no block", func(t *testing.T) {
		t.Setenv("HOME", "")

		var warned []error
		blocks, unreadable, err := globalBlocks([]adapter.Adapter{claude.New()}, func(e error) { warned = append(warned, e) })
		if err != nil {
			t.Fatalf("globalBlocks() error = %v, want nil: a Base fault is warned, not returned", err)
		}
		if len(blocks) != 0 {
			t.Fatalf("globalBlocks() len = %d, want 0", len(blocks))
		}
		if unreadable {
			t.Fatal("globalBlocks() unreadable = true, want false: an unset HOME names no path to read")
		}
		if len(warned) != 1 {
			t.Fatalf("warn calls = %v, want exactly 1 naming the fault", warned)
		}
		if !strings.Contains(warned[0].Error(), "HOME") {
			t.Fatalf("warning = %q, want it to name the unresolved $HOME base", warned[0].Error())
		}
	})
}

const globalHookJSON = `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]}}`

func TestRun_GlobalConfig_UnresolvableBaseWarnsAndSaysNoConfigFound(t *testing.T) {
	t.Setenv("HOME", "")
	withOpenTarget(t, map[string]fs.FS{".": findingTargetFS()})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	if got, want := stdout.String(), "no user-level agent config found\n"; got != want {
		t.Fatalf("stdout = %q, want %q: the current directory is not a target", got, want)
	}
	if got := stderr.String(); !strings.Contains(got, "warning:") || !strings.Contains(got, "HOME") {
		t.Fatalf("stderr = %q, want a warning naming the unresolved global config base", got)
	}
}

func TestRun_GlobalConfig_NeverImpliedWithoutTheFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{
		"proj": cleanTargetFS(),
		home:   fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(globalHookJSON)}},
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"proj"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	if strings.Count(stdout.String(), "agentaudit ·") != 1 {
		t.Fatalf("stdout = %q, want exactly one block without --global-config", stdout.String())
	}
	if strings.Contains(stdout.String(), home) {
		t.Fatalf("stdout = %q, want no reference to the home path without --global-config", stdout.String())
	}
}

// The current directory is the default target of a plain scan, not of a
// --global-config one.
func TestRun_GlobalConfig_BareFlagRendersTheHomeBlockAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	byPath := map[string]fs.FS{
		".":  findingTargetFS(),
		home: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(globalHookJSON)}},
	}

	c := withCountingOpener(t, byPath)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if got := strings.Count(out, "agentaudit ·"); got != 1 || !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout = %q, want exactly one block, the home's", out)
	}
	if strings.Contains(out, "mcpServer fs") {
		t.Fatalf("stdout = %q, want nothing from the current directory's .mcp.json", out)
	}
	if c.opens != 1 {
		t.Fatalf("opens = %d, want 1: the home base alone", c.opens)
	}

	withOpenTarget(t, byPath)
	var plain, plainErr bytes.Buffer
	run(nil, &plain, &plainErr)
	if !strings.Contains(plain.String(), "mcpServer fs") {
		t.Fatalf("without --global-config, stdout = %q, want the current directory's .mcp.json scanned", plain.String())
	}
}

func TestRun_GlobalConfig_RefusesAProjectTargetAndScansNothing(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		conflict string
	}{
		{"a positional PATH", []string{"proj"}, "PATH"},
		{"a --scan-dir", []string{"--scan-dir", "proj"}, "--scan-dir"},
		{"-r", []string{"-r"}, "-r/--recursive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			byPath := map[string]fs.FS{
				".":    findingTargetFS(),
				"proj": findingTargetFS(),
				home:   fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(globalHookJSON)}},
			}

			c := withCountingOpener(t, byPath)
			var stdout, stderr bytes.Buffer
			if got := run(append(tt.args, "--global-config"), &stdout, &stderr); got != 2 {
				t.Fatalf("run() = %d, want 2\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want nothing rendered for a usage error", stdout.String())
			}
			if want := "--global-config scans only the user-level config and cannot be combined with " + tt.conflict; !strings.Contains(stderr.String(), want) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), want)
			}
			if c.opens != 0 {
				t.Fatalf("opens = %d, want 0: a usage error scans nothing", c.opens)
			}

			companion := withCountingOpener(t, byPath)
			var plain, plainErr bytes.Buffer
			run(tt.args, &plain, &plainErr)
			if companion.opens == 0 {
				t.Fatalf("without --global-config, opens = 0, want the same input to open a target\nstderr:%s", plainErr.String())
			}
		})
	}
}

func TestRun_GlobalConfig_ExitCodeFollowsTheGlobalFindings(t *testing.T) {
	tests := []struct {
		name          string
		globalPresent bool
		globalFinds   bool
		want          int
	}{
		{"global finding", true, true, 1},
		{"clean global", true, false, 0},
		{"absent global", false, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			homeFixture := fstest.MapFS{}
			if tt.globalPresent {
				if tt.globalFinds {
					homeFixture[".claude/settings.json"] = &fstest.MapFile{Data: []byte(globalHookJSON)}
				} else {
					homeFixture[".claude/settings.json"] = &fstest.MapFile{Data: []byte(`{}`)}
				}
			}
			withOpenTarget(t, map[string]fs.FS{".": findingTargetFS(), home: homeFixture})

			var stdout, stderr bytes.Buffer
			if got := run([]string{"--global-config"}, &stdout, &stderr); got != tt.want {
				t.Fatalf("run() = %d, want %d\nstdout:%s\nstderr:%s", got, tt.want, stdout.String(), stderr.String())
			}
			const absent = "no user-level agent config found\n"
			if got := stdout.String(); (got == absent) != !tt.globalPresent {
				t.Fatalf("stdout = %q, want it to equal %q exactly when no home config is present", got, absent)
			}
		})
	}
}

func TestRun_GlobalConfig_AbsentHomeConfigKeepsJSONAnArray(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{".": findingTargetFS(), home: fstest.MapFS{}})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config", "-o", "json"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	if got, want := stdout.String(), "[]\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRun_GlobalConfig_AbsentHomeConfigIsNamedInTheMDFile(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{".": findingTargetFS(), home: fstest.MapFS{}})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config", "-O", "md"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() = %d, want 0\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(mdReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
	}
	if got, want := string(data), "no user-level agent config found\n"; got != want {
		t.Fatalf("%s = %q, want %q", mdReportFilename, got, want)
	}
}

func TestRootCmd_GlobalConfigHelpStatesTheStandaloneMode(t *testing.T) {
	var code int
	flag := newRootCmd(&bytes.Buffer{}, &bytes.Buffer{}, &code).Flags().Lookup("global-config")
	if flag == nil {
		t.Fatal("Lookup(\"global-config\") = nil, want the flag registered")
	}
	want := "scan only each adapter's user-level config; cannot be combined with PATH, --scan-dir or -r"
	if flag.Usage != want {
		t.Fatalf("Usage = %q, want %q", flag.Usage, want)
	}
}

func TestRun_GlobalConfig_JSONHoldsOnlyTheHomeDocument(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{
		".":  findingTargetFS(),
		home: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(globalHookJSON)}},
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config", "-o", "json"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}

	var docs []struct {
		Path string `json:"path"`
	}
	if err := stdjson.Unmarshal(stdout.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, stdout.String())
	}
	if len(docs) != 1 || docs[0].Path != home {
		t.Fatalf("docs = %+v, want exactly one document at %q", docs, home)
	}
}

func TestRun_GlobalConfig_MDFileHoldsOnlyTheHomeDocument(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{
		".":  findingTargetFS(),
		home: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(globalHookJSON)}},
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config", "-O", "md"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(mdReportFilename)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
	}
	out := string(data)
	if got := strings.Count(out, "# agentaudit ·"); got != 1 || !strings.Contains(out, "# agentaudit · "+home) {
		t.Fatalf("%s = %q, want exactly one document, the home's", mdReportFilename, out)
	}
}

// A projects.<path> entry in ~/.claude.json is reported under .claude.json
// provenance, not under the project path it names.
func TestRun_GlobalConfig_PerProjectHomeEntryKeepsItsClaudeJSONProvenance(t *testing.T) {
	proj := "proj"
	home := t.TempDir()
	t.Setenv("HOME", home)

	homeFS := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"projects": {"` + proj + `": {"mcpServers": {"evil": {"command": "npx"}}}}
		}`)},
	}
	withOpenTarget(t, map[string]fs.FS{home: homeFS})

	var stdoutGlobal, stderrGlobal bytes.Buffer
	if got := run([]string{"--global-config"}, &stdoutGlobal, &stderrGlobal); got != 1 {
		t.Fatalf("run() = %d, want 1\nstdout:%s\nstderr:%s", got, stdoutGlobal.String(), stderrGlobal.String())
	}
	global := stdoutGlobal.String()
	if !strings.Contains(global, ".claude.json:projects."+proj+".mcpServers.evil") {
		t.Fatalf("global stdout = %q, want the evil server's rendered provenance rooted at .claude.json, not the project path", global)
	}
}

func TestRun_GlobalConfig_UnreadableClaudeJSONRendersScanIncomplete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withOpenTarget(t, map[string]fs.FS{
		".": findingTargetFS(),
		home: readFaultFS{
			m:        fstest.MapFS{".claude.json": &fstest.MapFile{}},
			failPath: ".claude.json",
		},
	})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1 (a degraded home, no findings)\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "agentaudit · "+home) {
		t.Fatalf("stdout = %q, want the home block rendered", out)
	}
	if !strings.Contains(out, "SCAN INCOMPLETE") {
		t.Fatalf("stdout = %q, want the global block to render SCAN INCOMPLETE", out)
	}
}

// Each declared plugin manifest under the home contributes a finding to the
// one global block.
func TestRun_GlobalConfig_HomePluginsShareOneBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	homeFixture := fstest.MapFS{
		".claude/plugins/one/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"one","version":"1.0.0"}`)},
		".claude/plugins/two/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"two","version":"1.0.0"}`)},
	}
	withOpenTarget(t, map[string]fs.FS{home: homeFixture})

	var stdout, stderr bytes.Buffer
	if got := run([]string{"--global-config"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() = %d, want 1 (the plugin manifests are findings)\nstdout:%s\nstderr:%s", got, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if got := strings.Count(out, "agentaudit ·"); got != 1 {
		t.Fatalf("stdout = %q, want exactly ONE block", out)
	}
	for _, want := range []string{
		"plugin one",
		"plugin two",
		".claude/plugins/one/.claude-plugin/plugin.json",
		".claude/plugins/two/.claude-plugin/plugin.json",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("global block = %q, want it to contain %q", out, want)
		}
	}
	if got := strings.Count(out, "plugin.json"); got != len(homeFixture) {
		t.Fatalf("global block = %q, want a finding from each of the %d declared plugin manifests", out, len(homeFixture))
	}
}

func withOpenError(t *testing.T, openErr error) {
	t.Helper()
	original := openTarget
	openTarget = func(string) (fs.FS, func() error, error) { return nil, nil, openErr }
	t.Cleanup(func() { openTarget = original })
}

func TestRun_GlobalConfig_UnopenableHomeIsNotReportedAsAbsent(t *testing.T) {
	tests := []struct {
		name    string
		openErr error
		want    string
		code    int
	}{
		{"permission denied", fs.ErrPermission, "user-level agent config could not be read\n", 1},
		{"not a directory", syscall.ENOTDIR, "user-level agent config could not be read\n", 1},
		{"does not exist", fs.ErrNotExist, "no user-level agent config found\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			home := t.TempDir()
			t.Setenv("HOME", home)
			withOpenError(t, &fs.PathError{Op: "open", Path: home, Err: tt.openErr})

			var stdout, stderr bytes.Buffer
			if got := run([]string{"--global-config", "-O", "md"}, &stdout, &stderr); got != tt.code {
				t.Fatalf("run() = %d, want %d\nstdout:%s\nstderr:%s", got, tt.code, stdout.String(), stderr.String())
			}
			if got := stdout.String(); got != tt.want {
				t.Fatalf("stdout = %q, want %q", got, tt.want)
			}
			data, err := os.ReadFile(mdReportFilename)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", mdReportFilename, err)
			}
			if got := string(data); got != tt.want {
				t.Fatalf("%s = %q, want %q", mdReportFilename, got, tt.want)
			}
			if !strings.Contains(stderr.String(), "warning:") || !strings.Contains(stderr.String(), home) {
				t.Fatalf("stderr = %q, want a warning naming the base %q", stderr.String(), home)
			}

			var jsonOut, jsonErr bytes.Buffer
			if got := run([]string{"--global-config", "-o", "json"}, &jsonOut, &jsonErr); got != tt.code {
				t.Fatalf("run(-o json) = %d, want %d\nstderr:%s", got, tt.code, jsonErr.String())
			}
			if got, want := jsonOut.String(), "[]\n"; got != want {
				t.Fatalf("json stdout = %q, want %q", got, want)
			}
		})
	}
}
