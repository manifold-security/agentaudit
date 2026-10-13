package hostroot

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/registry"
)

func TestRebaseRootsTheSetByThePickedFolderName(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		root    string
		refusal error
	}{
		{
			name:  "a root-relative set",
			paths: []string{".claude/settings.json", ".mcp.json", "src/main.go"},
		},
		{
			name:  "a set under one project folder",
			paths: []string{"myrepo/.claude/settings.json", "myrepo/.mcp.json"},
			root:  "myrepo",
		},
		{
			name:  "a prefixed set whose plugin manifest also matches at the top",
			paths: []string{"myrepo/.claude/settings.json", "myrepo/.claude-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:    "a set two folders above its config",
			paths:   []string{"projects/myrepo/.claude/settings.json", "projects/myrepo/.mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a set two folders above its config under a/b",
			paths:   []string{"a/b/.claude/settings.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:  "an uploaded .claude folder",
			paths: []string{".claude/settings.json", ".claude/skills/demo/SKILL.md"},
		},
		{
			name:  "an uploaded .cursor folder",
			paths: []string{".cursor/mcp.json"},
		},
		{
			name:  "an uploaded .codex folder",
			paths: []string{".codex/config.toml", ".codex/hooks.json"},
		},
		{
			name:  "an uploaded .agents folder",
			paths: []string{".agents/skills/demo/SKILL.md"},
		},
		{
			name:  "an uploaded ~/.claude folder with a vendored plugin",
			paths: []string{".claude/settings.json", ".claude/agents/a.md", ".claude/plugins/marketplaces/m/p/.claude-plugin/plugin.json", ".claude/plugins/marketplaces/m/p/hooks/hooks.json"},
		},
		{
			name:    "a .claude folder holding a .claude folder",
			paths:   []string{".claude/.claude/settings.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "a .claude folder holding a .mcp.json",
			paths:   []string{".claude/settings.json", ".claude/.mcp.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "a .claude folder holding a plugin.json",
			paths:   []string{".claude/settings.json", ".claude/plugin.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "a .cursor folder holding a .claude folder",
			paths:   []string{".cursor/mcp.json", ".cursor/.claude/settings.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "a .codex folder holding a .claude folder",
			paths:   []string{".codex/config.toml", ".codex/.claude/settings.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "an .agents folder holding a .mcp.json",
			paths:   []string{".agents/skills/x/SKILL.md", ".agents/.mcp.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:  "a .claude marker folder holding only its manifest",
			paths: []string{".claude-plugin/plugin.json"},
		},
		{
			name:  "a .cursor marker folder holding only its manifest",
			paths: []string{".cursor-plugin/plugin.json"},
		},
		{
			name:    "a marker folder holding a README",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/README.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a .mcp.json",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/.mcp.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a .codex folder",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/.codex/hooks.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding an .agents skill",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/.agents/skills/x/SKILL.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a .claude agent",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/.claude/agents/a.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a .cursor folder",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/.cursor/mcp.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a Cursor marker folder holding a .cursor folder",
			paths:   []string{".cursor-plugin/plugin.json", ".cursor-plugin/.cursor/hooks.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker-named Agent Plugin",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/mcp.json", ".claude-plugin/skills/x/SKILL.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker-named Agent Plugin with only mcp.json",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/mcp.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a Cursor marker-named Agent Plugin",
			paths:   []string{".cursor-plugin/plugin.json", ".cursor-plugin/mcp.json", ".cursor-plugin/skills/x/SKILL.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a Cursor marker-named Agent Plugin with only skills",
			paths:   []string{".cursor-plugin/plugin.json", ".cursor-plugin/skills/x/SKILL.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a nested plugin",
			paths:   []string{".claude-plugin/.claude-plugin/plugin.json", ".claude-plugin/hooks/hooks.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a Cursor marker",
			paths:   []string{".claude-plugin/.cursor-plugin/plugin.json", ".claude-plugin/hooks/hooks.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a marker folder holding a manifest, mcp.json and a nested marker",
			paths:   []string{".claude-plugin/plugin.json", ".claude-plugin/mcp.json", ".claude-plugin/.claude-plugin/plugin.json"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a Cursor marker folder holding a .codex config",
			paths:   []string{".cursor-plugin/plugin.json", ".cursor-plugin/.codex/config.toml"},
			refusal: errMarkerFolder,
		},
		{
			name:  "a casing variant of a config folder name",
			paths: []string{".Claude/settings.json"},
			root:  ".Claude",
		},
		{
			name:  "a casing variant of a marker name",
			paths: []string{".Claude-Plugin/plugin.json", ".Claude-Plugin/.mcp.json", ".Claude-Plugin/mcp.json"},
			root:  ".Claude-Plugin",
		},
		{
			name:  "a zero-width variant of a marker name",
			paths: []string{".claude-plugin\u200b/plugin.json", ".claude-plugin\u200b/mcp.json"},
			root:  ".claude-plugin\u200b",
		},
		{
			name:  "a dot-named project folder",
			paths: []string{".myrepo/.claude/settings.json"},
			root:  ".myrepo",
		},
		{
			name:  "a prefixed repo holding only a nested plugin",
			paths: []string{"myrepo/vendor/x/.claude-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:    "a prefixed repo holding a nested plugin that ships its own .mcp.json",
			paths:   []string{"myrepo/vendor/x/.claude-plugin/plugin.json", "myrepo/vendor/x/.mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:  "a root-relative repo holding only a nested plugin",
			paths: []string{"README.md", "vendor/x/.claude-plugin/plugin.json"},
		},
		{
			name:  "a prefixed skills-directory plugin",
			paths: []string{"myrepo/.claude/skills/demo/.claude-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:  "a root-relative skills-directory plugin",
			paths: []string{".claude/skills/demo/.claude-plugin/plugin.json"},
		},
		{
			name:  "a prefixed plugin whose only folder is its marker",
			paths: []string{"myrepo/.claude-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:    "a prefixed marker folder holding a .mcp.json",
			paths:   []string{"myrepo/.claude-plugin/plugin.json", "myrepo/.claude-plugin/.mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a prefixed plugin repo with a stray marker .mcp.json",
			paths:   []string{"myrepo/.claude-plugin/plugin.json", "myrepo/.claude-plugin/.mcp.json", "myrepo/hooks/hooks.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a project named like a marker",
			paths:   []string{"p/.claude-plugin/.claude/settings.json", "p/.claude-plugin/.mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a plugin repo",
			paths:   []string{"projects/repo/.claude-plugin/plugin.json", "projects/repo/.mcp.json", "projects/repo/mcp.json", "projects/repo/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:  "a monorepo with root and nested project config",
			paths: []string{"myrepo/.claude/settings.json", "myrepo/apps/web/.claude/settings.json"},
			root:  "myrepo",
		},
		{
			name:    "a monorepo with only nested project config",
			paths:   []string{"myrepo/README.md", "myrepo/apps/web/.claude/settings.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "sibling projects with no common folder",
			paths:   []string{"a/.claude/settings.json", "b/.mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a Cursor manifest inside .cursor/hooks",
			paths:   []string{"projects/repo/.cursor/hooks/.cursor-plugin/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a Claude manifest inside .cursor/hooks",
			paths:   []string{"projects/repo/.cursor/hooks/.claude-plugin/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a manifest inside .claude/skills",
			paths:   []string{"projects/repo/.claude/skills/x/.claude-plugin/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a .claude folder whose root-anchored decoy sorts last",
			paths:   []string{".claude/agents/a.md", ".claude/plugin.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:    "an .agents folder whose root-anchored decoy sorts last",
			paths:   []string{".agents/README.md", ".agents/plugin.json"},
			refusal: errAmbiguousRoot,
		},
		{
			name:  "a top-level file named like a plugin marker",
			paths: []string{".claude-plugin"},
		},
		{
			name:  "a config-less set with no common folder",
			paths: []string{"README.md", "src/main.go"},
		},
		{
			name:  "a config-less set under one folder",
			paths: []string{"myrepo/README.md", "myrepo/src/main.go"},
			root:  "myrepo",
		},
		{
			name:  "a decoy .claude below the real one",
			paths: []string{"myrepo/.claude/settings.json", "myrepo/sub/.claude/settings.json"},
			root:  "myrepo",
		},
		{
			name:    "a decoy plugin manifest beside nested config",
			paths:   []string{"myrepo/README.md", "myrepo/sub/.claude-plugin/plugin.json", "myrepo/sub/.claude/settings.json"},
			refusal: errConfigBelowRoot,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, p := range tc.paths {
				files[p] = []byte(p)
			}

			got, err := Rebase(files, registry.Adapters())

			if tc.refusal != nil {
				if !errors.Is(err, tc.refusal) {
					t.Fatalf("Rebase(%v) error = %v, want %v", tc.paths, err, tc.refusal)
				}
				return
			}
			if err != nil {
				t.Fatalf("Rebase(%v) error = %v, want nil", tc.paths, err)
			}
			assertRebased(t, files, got, tc.root)
		})
	}
}

type zedAdapter struct{}

func (zedAdapter) Agent() adapter.AgentID { return "zed" }

func (zedAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{Dir: ".zed/tasks", Recursive: true},
		{Dir: ".zed-plugin", File: "manifest.json", AnyDepth: true},
	}
}

func (zedAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

// The config-folder and marker names come from the adapters' signatures, so
// an agent this package has never heard of is kept, stripped or refused by
// its own declared locations.
func TestRebaseTakesItsFolderNamesFromTheAdapters(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		root    string
		refusal error
	}{
		{name: "its config folder", paths: []string{".zed/tasks/build.json"}},
		{name: "its marker holding only its manifest", paths: []string{".zed-plugin/manifest.json"}},
		{name: "its marker holding more", paths: []string{".zed-plugin/manifest.json", ".zed-plugin/README.md"}, refusal: errMarkerFolder},
		{name: "another agent's config folder", paths: []string{".claude/settings.json"}, root: ".claude"},
		{name: "another agent's marker", paths: []string{".claude-plugin/plugin.json", ".claude-plugin/README.md"}, root: ".claude-plugin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, p := range tc.paths {
				files[p] = []byte(p)
			}

			got, err := Rebase(files, []adapter.Adapter{zedAdapter{}})

			if tc.refusal != nil {
				if !errors.Is(err, tc.refusal) {
					t.Fatalf("Rebase(%v) error = %v, want %v", tc.paths, err, tc.refusal)
				}
				return
			}
			if err != nil {
				t.Fatalf("Rebase(%v) error = %v, want nil", tc.paths, err)
			}
			assertRebased(t, files, got, tc.root)
		})
	}
}

// A refusal names the folder it could not settle, so a reader can tell a
// picked folder that sits too high from one that is simply ambiguous.
func TestRebaseRefusalsNameTheFolderInQuestion(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{name: "below", paths: []string{"projects/myrepo/.mcp.json"}, want: `"projects/myrepo"`},
		{name: "ambiguous", paths: []string{".claude/.mcp.json"}, want: `".claude"`},
		{name: "marker", paths: []string{".cursor-plugin/plugin.json", ".cursor-plugin/.mcp.json"}, want: `".cursor-plugin"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, p := range tc.paths {
				files[p] = nil
			}

			_, err := Rebase(files, registry.Adapters())

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Rebase(%v) error = %v, want it to name %s", tc.paths, err, tc.want)
			}
		})
	}
}

// A name io/fs cannot hold is refused by name before any folder is walked
// up from it, since an absolute path's parents never reach ".".
func TestRebaseRefusesANameIOFSCannotHold(t *testing.T) {
	for _, name := range []string{"/absolute/settings.json", "myrepo/../.mcp.json", "."} {
		t.Run(name, func(t *testing.T) {
			refused := make(chan error, 1)
			go func() {
				_, err := Rebase(map[string][]byte{name: nil, "myrepo/README.md": nil}, registry.Adapters())
				refused <- err
			}()

			var err error
			select {
			case err = <-refused:
			case <-time.After(10 * time.Second):
				t.Fatalf("Rebase(%q) did not return", name)
			}
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", name)) {
				t.Fatalf("Rebase(%q) error = %v, want a refusal naming it", name, err)
			}
		})
	}
}

func assertRebased(t *testing.T, declared, got map[string][]byte, root string) {
	t.Helper()

	if len(got) != len(declared) {
		t.Fatalf("Rebase kept %d of %d declared files: %v", len(got), len(declared), slices.Sorted(maps.Keys(got)))
	}
	prefix := ""
	if root != "" {
		prefix = root + "/"
	}
	for name, data := range declared {
		rebased := strings.TrimPrefix(name, prefix)
		kept, ok := got[rebased]
		if !ok || string(kept) != string(data) {
			t.Fatalf("Rebase keys = %v, want %q rooted at %q as %q", slices.Sorted(maps.Keys(got)), name, root, rebased)
		}
	}
}
