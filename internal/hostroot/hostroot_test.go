package hostroot

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/codex"
	"github.com/manifold-security/agentaudit/internal/adapters/cursor"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/registry"
)

func TestRootRootsTheSetByThePickedFolderName(t *testing.T) {
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
			name:  "a repo holding a Codex plugin",
			paths: []string{"README.md", "plugins/x/.codex-plugin/plugin.json"},
		},
		{
			name:  "a prefixed repo holding a Codex plugin",
			paths: []string{"myrepo/README.md", "myrepo/plugins/x/.codex-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:  "a prefixed scaffold-only plugins repo",
			paths: []string{"myrepo/plugins/a/.codex-plugin/plugin.json", "myrepo/plugins/b/.codex-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:  "a root-relative scaffold-only plugins repo",
			paths: []string{"plugins/a/.codex-plugin/plugin.json", "plugins/b/.codex-plugin/plugin.json"},
			root:  "plugins",
		},
		{
			name:    "a known limit: a root-relative portable-only plugins repo",
			paths:   []string{"plugins/a/plugin.json", "plugins/b/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:  "a Codex plugin repo",
			paths: []string{"README.md", ".codex-plugin/plugin.json"},
		},
		{
			name:  "a prefixed Codex plugin repo",
			paths: []string{"myrepo/.codex-plugin/plugin.json"},
			root:  "myrepo",
		},
		{
			name:  "a Codex marker folder holding only its manifest",
			paths: []string{".codex-plugin/plugin.json"},
		},
		{
			name:    "a Codex marker folder holding more",
			paths:   []string{".codex-plugin/plugin.json", ".codex-plugin/README.md"},
			refusal: errMarkerFolder,
		},
		{
			name:    "a plugin manifest in a plain folder inside a dot-named folder",
			paths:   []string{"README.md", ".github/x/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a known limit: a repo holding a portable plugin",
			paths:   []string{"README.md", "plugins/x/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a known limit: a prefixed repo holding a portable plugin",
			paths:   []string{"myrepo/README.md", "myrepo/plugins/x/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a known limit: a repo holding a portable plugin at its top",
			paths:   []string{"README.md", "x/plugin.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a known limit: a prefixed repo holding a portable plugin at its top",
			paths:   []string{"myrepo/x/plugin.json"},
			refusal: errConfigBelowRoot,
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
			name:    "a parent pick holding a repo rooted by a bare plugin.json",
			paths:   []string{"projects/repo/plugin.json", "projects/repo/mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a grandparent pick holding a repo rooted by a bare plugin.json",
			paths:   []string{"work/projects/repo/plugin.json", "work/projects/repo/mcp.json"},
			refusal: errConfigBelowRoot,
		},
		{
			name:    "a parent pick holding a dot-named repo rooted by a bare plugin.json",
			paths:   []string{"projects/.repo/plugin.json", "projects/.repo/mcp.json"},
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
			got, err := Root(tc.paths, registry.Adapters())

			if tc.refusal != nil {
				if !errors.Is(err, tc.refusal) {
					t.Fatalf("Root(%v) error = %v, want %v", tc.paths, err, tc.refusal)
				}
				return
			}
			if err != nil {
				t.Fatalf("Root(%v) error = %v, want nil", tc.paths, err)
			}
			if got != tc.root {
				t.Fatalf("Root(%v) = %q, want %q", tc.paths, got, tc.root)
			}
		})
	}
}

type zedAdapter struct{}

func (zedAdapter) Agent() adapter.AgentID { return "zed" }

func (zedAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{Dir: ".zed/tasks", Recursive: true},
		{Dir: ".zed-plugin", File: "manifest.json", AnyDepth: true},
		{File: "manifest.json"},
	}
}

func (zedAdapter) PluginMarkers() []adapter.Signature {
	return []adapter.Signature{{Dir: ".zed-scaffold", File: "manifest.json", AnyDepth: true}}
}

func (zedAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) { return nil, nil, nil }

// The names Root looks for come from the adapters, so an agent this package
// has never heard of is kept, named as the root, or refused by its own
// declared locations.
func TestRootTakesItsFolderNamesFromTheAdapters(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		root    string
		refusal error
	}{
		{name: "its config folder", paths: []string{".zed/tasks/build.json"}},
		{name: "its marker holding only its manifest", paths: []string{".zed-plugin/manifest.json"}},
		{name: "its marker holding more", paths: []string{".zed-plugin/manifest.json", ".zed-plugin/README.md"}, refusal: errMarkerFolder},
		{name: "its declared plugin marker holding only its manifest", paths: []string{".zed-scaffold/manifest.json"}},
		{name: "its declared plugin marker below the root", paths: []string{"README.md", "plugins/x/.zed-scaffold/manifest.json"}},
		{name: "its manifest name in a dot-named folder it does not declare", paths: []string{"README.md", "plugins/x/.y/manifest.json"}, refusal: errConfigBelowRoot},
		{name: "its manifest name in a plain folder below the root", paths: []string{"README.md", "plugins/x/manifest.json"}, refusal: errConfigBelowRoot},
		{name: "its config folder holding a bare manifest", paths: []string{".zed/manifest.json"}, refusal: errAmbiguousRoot},
		{name: "another agent's config folder", paths: []string{".claude/settings.json"}, root: ".claude"},
		{name: "another agent's marker", paths: []string{".claude-plugin/plugin.json", ".claude-plugin/README.md"}, root: ".claude-plugin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Root(tc.paths, []adapter.Adapter{zedAdapter{}})

			if tc.refusal != nil {
				if !errors.Is(err, tc.refusal) {
					t.Fatalf("Root(%v) error = %v, want %v", tc.paths, err, tc.refusal)
				}
				return
			}
			if err != nil {
				t.Fatalf("Root(%v) error = %v, want nil", tc.paths, err)
			}
			if got != tc.root {
				t.Fatalf("Root(%v) = %q, want %q", tc.paths, got, tc.root)
			}
		})
	}
}

// Cursor's bare plugin.json signature refuses a Codex manifest below the
// root until the Codex adapter, which declares that manifest's marker, joins
// the set.
func TestRootTakesTheCodexPluginMarkerFromTheCodexAdapter(t *testing.T) {
	paths := []string{"README.md", "plugins/x/.codex-plugin/plugin.json"}

	if _, err := Root(paths, []adapter.Adapter{cursor.New()}); !errors.Is(err, errConfigBelowRoot) {
		t.Fatalf("Root(%v) with Cursor alone error = %v, want %v", paths, err, errConfigBelowRoot)
	}
	root, err := Root(paths, []adapter.Adapter{cursor.New(), codex.New()})
	if err != nil || root != "" {
		t.Fatalf("Root(%v) with Cursor and Codex = %q, %v, want \"\", nil", paths, root, err)
	}
}

// A refusal names the folder it could not settle, so a reader can tell a
// picked folder that sits too high from one that is simply ambiguous.
func TestRootRefusalsNameTheFolderInQuestion(t *testing.T) {
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
			_, err := Root(tc.paths, registry.Adapters())

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Root(%v) error = %v, want it to name %s", tc.paths, err, tc.want)
			}
		})
	}
}

// A name io/fs cannot hold is refused by name before any folder is walked
// up from it, since an absolute path's parents never reach ".".
func TestRootRefusesANameIOFSCannotHold(t *testing.T) {
	for _, name := range []string{"/absolute/settings.json", "myrepo/../.mcp.json", "."} {
		t.Run(name, func(t *testing.T) {
			refused := make(chan error, 1)
			go func() {
				_, err := Root([]string{name, "myrepo/README.md"}, registry.Adapters())
				refused <- err
			}()

			var err error
			select {
			case err = <-refused:
			case <-time.After(10 * time.Second):
				t.Fatalf("Root(%q) did not return", name)
			}
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", name)) {
				t.Fatalf("Root(%q) error = %v, want a refusal naming it", name, err)
			}
		})
	}
}
