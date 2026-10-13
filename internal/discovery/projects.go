package discovery

import (
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
)

// Projects walks fsys once and returns every directory carrying, at its own
// top level, an entry whose name matches a marker derived from adapters'
// Signatures(). Matching is presence-only: a file named .claude and a
// directory named .mcp.json qualify like the conventional kind. A matched
// entry that is itself a directory is not descended, which keeps a .mcp.json
// inside .claude/skills/** out of its own project; the skip needs the exact
// marker name, so .claude-plugin is still descended and a marker inside it
// still found.
//
// Failure and symlink handling are walkTree's, so a marker reached only
// through a symlinked directory is still found. Projects deliberately does
// not prune a project nested inside another — both are reported.
func Projects(fsys fs.FS, adapters []adapter.Adapter) ([]string, []adapter.Warning, error) {
	regularMarkers, anyDepthJoins := projectMarkers(adapters)

	var roots []string
	// seen keys on path, not on resolved target: two attacker-controlled paths
	// can share one target, and collapsing them would drop a real config from
	// the report. The uncollapsed blocks are asserted by
	// TestBinaryE2E_SymlinkAliasesToTheSameProjectEachRenderTheirOwnBlock.
	seen := map[string]struct{}{}

	add := func(root string) {
		if _, dup := seen[root]; dup {
			return
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}

	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		if regularMarkers[path.Base(p)] {
			add(path.Dir(p))
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		for _, join := range anyDepthJoins {
			if root, ok := anyDepthRoot(p, join); ok {
				add(root)
				if d.IsDir() {
					return fs.SkipDir
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return nil, warnings, err
	}

	sort.Strings(roots)
	return roots, warnings, nil
}

// projectMarkers derives the marker set from adapters' Signatures() rather
// than a hand-written list, so a new adapter's projects are found for free.
//
// An unanchored pluginManifestFile yields no marker. pluginManifestJoins
// refuses it for the same reason on the plugin-root side, and here it would
// also answer ahead of the anchored root an AnyDepth signature derives for
// the same file, enumerating the manifest's own directory in place of the
// plugin root that owns it.
func projectMarkers(adapters []adapter.Adapter) (map[string]bool, []string) {
	regular := map[string]bool{}
	var anyDepth []string
	seenAnyDepth := map[string]bool{}

	for _, a := range adapters {
		for _, s := range a.Signatures() {
			join := path.Join(s.Dir, s.File)
			if s.AnyDepth {
				if !seenAnyDepth[join] {
					seenAnyDepth[join] = true
					anyDepth = append(anyDepth, join)
				}
				continue
			}
			if join == pluginManifestFile {
				continue
			}
			first, _, _ := strings.Cut(join, "/")
			regular[first] = true
		}
	}
	return regular, anyDepth
}

func anyDepthRoot(p, join string) (string, bool) {
	if p == join {
		return ".", true
	}
	if strings.HasSuffix(p, "/"+join) {
		return strings.TrimSuffix(p, "/"+join), true
	}
	return "", false
}
