package discovery

import (
	"io/fs"
	"path"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
)

// Discover walks fsys once and returns every adapter-owned Source and plugin
// root found, sorted and deduplicated. Failure and symlink handling are
// walkTree's.
func Discover(fsys fs.FS, adapters []adapter.Adapter) (Result, []adapter.Warning, error) {
	var srcs []Source
	var roots []string
	seenSrc := map[Source]struct{}{}
	seenRoot := map[string]struct{}{}
	manifestJoins := pluginManifestJoins(adapters)

	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		for _, a := range adapters {
			if adapter.MatchesEntry(p, d.IsDir(), a.Signatures()) {
				s := Source{Path: p, Agent: a.Agent()}
				if _, dup := seenSrc[s]; !dup {
					seenSrc[s] = struct{}{}
					srcs = append(srcs, s)
				}
			}
		}
		for _, join := range manifestJoins {
			root, ok := anyDepthRoot(p, join)
			if !ok {
				continue
			}
			if _, dup := seenRoot[root]; !dup {
				seenRoot[root] = struct{}{}
				roots = append(roots, root)
			}
			break
		}
		return nil
	})
	if err != nil {
		return Result{}, warnings, err
	}

	sort.Slice(srcs, func(i, j int) bool {
		if srcs[i].Path != srcs[j].Path {
			return srcs[i].Path < srcs[j].Path
		}
		return srcs[i].Agent < srcs[j].Agent
	})
	sort.Strings(roots)

	return Result{Sources: srcs, PluginRoots: roots}, warnings, nil
}

// pluginManifestFile is the filename the Agent-Plugins manifest format gives a
// plugin's own descriptor; it belongs to the format, not to one adapter.
const pluginManifestFile = "plugin.json"

// pluginManifestJoins derives the manifest locations a plugin root is
// recognised by from adapters' own Signatures(), so an agent anchoring
// pluginManifestFile in a directory of its own is found without editing this
// package.
//
// A signature naming a bare directory marks a surface its adapter walks
// itself, so rooting on it would report that
// directory's parent as a plugin. A sibling manifest such as marketplace.json
// catalogues the plugin directories beside it, so its own directory is a
// catalogue rather than a plugin. And an unanchored manifest name would root
// every directory that happens to hold that file.
func pluginManifestJoins(adapters []adapter.Adapter) []string {
	var joins []string
	seen := map[string]bool{}
	for _, a := range adapters {
		for _, s := range a.Signatures() {
			if !s.AnyDepth || s.File != pluginManifestFile || s.Dir == "" {
				continue
			}
			join := path.Join(s.Dir, s.File)
			if !seen[join] {
				seen[join] = true
				joins = append(joins, join)
			}
		}
	}
	return joins
}
