package discovery

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
)

// Discover walks fsys and returns the adapter-owned Sources and plugin roots
// it finds, sorted and deduplicated, with the warnings DiscoverFunc reports.
func Discover(fsys fs.FS, adapters []adapter.Adapter) (Result, []adapter.Warning, error) {
	var warnings []adapter.Warning
	res, err := DiscoverFunc(fsys, adapters, func(w adapter.Warning) { warnings = append(warnings, w) })
	return res, warnings, err
}

// DiscoverFunc is Discover passing each warning to warn as the walk meets it.
// A capped link yields a Source for each adapter anchored at or beneath it.
func DiscoverFunc(fsys fs.FS, adapters []adapter.Adapter, warn func(adapter.Warning)) (Result, error) {
	var srcs []Source
	var roots []string
	seenSrc := map[Source]struct{}{}
	seenRoot := map[string]struct{}{}
	sigs := make([][]adapter.Signature, len(adapters))
	for i, a := range adapters {
		sigs[i] = a.Signatures()
	}
	manifestJoins := pluginManifestJoins(sigs)
	addSource := func(s Source) {
		if _, dup := seenSrc[s]; !dup {
			seenSrc[s] = struct{}{}
			srcs = append(srcs, s)
		}
	}

	_, err := walkTreeFunc(fsys, func(p string, d fs.DirEntry) error {
		for i, a := range adapters {
			if adapter.MatchesEntry(p, d.IsDir(), sigs[i]) {
				addSource(Source{Path: p, Agent: a.Agent()})
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
	}, func(w adapter.Warning) {
		if errors.Is(w.Err, errBudgetSpent) {
			for i, a := range adapters {
				if anchoredBeneath(w.File, sigs[i]) {
					addSource(Source{Path: w.File, Agent: a.Agent()})
				}
			}
		}
		warn(w)
	})
	if err != nil {
		return Result{}, err
	}

	sort.Slice(srcs, func(i, j int) bool {
		if srcs[i].Path != srcs[j].Path {
			return srcs[i].Path < srcs[j].Path
		}
		return srcs[i].Agent < srcs[j].Agent
	})
	sort.Strings(roots)

	return Result{Sources: srcs, PluginRoots: roots}, nil
}

func anchoredBeneath(link string, sigs []adapter.Signature) bool {
	for _, s := range sigs {
		if s.AnyDepth {
			continue
		}
		anchor := s.Dir
		if !s.Recursive {
			anchor = path.Join(s.Dir, s.File)
		}
		if anchor == link || strings.HasPrefix(anchor, link+"/") {
			return true
		}
	}
	return false
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
func pluginManifestJoins(sigs [][]adapter.Signature) []string {
	var joins []string
	seen := map[string]bool{}
	for _, adapterSigs := range sigs {
		for _, s := range adapterSigs {
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
