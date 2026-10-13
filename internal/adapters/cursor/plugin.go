package cursor

import (
	"io/fs"
	"path"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const pluginManifestDir = ".cursor-plugin"

const pluginManifestFile = "plugin.json"

// pluginManifestSet holds the manifests one walk found, grouped by the
// location that identifies each plugin format.
type pluginManifestSet struct {
	cursor []string
	agent  []string
}

// pluginManifests returns the plugin manifests fsys carries, sorted lexically
// within each format. A directory the walk cannot list degrades to a Warning,
// keeping the manifests found elsewhere.
//
// A marketplace index is published from a directory of this name, so the
// entry's own basename is what decides whether the walk found a plugin.
func pluginManifests(fsys fs.FS) (pluginManifestSet, []adapter.Warning, error) {
	var manifests pluginManifestSet
	var warnings []adapter.Warning

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if path.Base(p) != pluginManifestFile {
			return nil
		}
		if path.Base(path.Dir(p)) == pluginManifestDir {
			manifests.cursor = append(manifests.cursor, p)
			return nil
		}
		manifests.agent = append(manifests.agent, p)
		return nil
	})
	if err != nil {
		return pluginManifestSet{}, nil, err
	}

	sort.Strings(manifests.cursor)
	sort.Strings(manifests.agent)
	return manifests, warnings, nil
}

// pluginEntities reads the components each plugin the tree carries loads,
// whichever format declares it; which components a format loads is each
// branch's own. Degradation is per manifest, so a faulty one leaves its
// siblings read.
func pluginEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	manifests, warnings, err := pluginManifests(fsys)
	if err != nil {
		return nil, nil, err
	}

	var entities []ir.Entity
	for _, file := range manifests.cursor {
		layout, manifestWarnings := manifestLayout(fsys, file)
		warnings = append(warnings, manifestWarnings...)

		componentEntities, componentWarnings, err := pluginComponentEntities(fsys, layout)
		if err != nil {
			return nil, nil, err
		}
		entities = append(entities, componentEntities...)
		warnings = append(warnings, componentWarnings...)
	}

	for _, file := range manifests.agent {
		agentEntities, agentWarnings := agentPluginEntities(fsys, file)
		entities = append(entities, agentEntities...)
		warnings = append(warnings, agentWarnings...)
	}
	return entities, warnings, nil
}

// manifestLayout reads one Cursor manifest into the layout its components
// load from. The manifest's location has already identified the plugin root,
// so a document the scanner cannot read there degrades to a Warning, and the
// components fall back to the locations a manifest naming none leaves them
// at.
func manifestLayout(fsys fs.FS, file string) (pluginLayout, []adapter.Warning) {
	root := path.Dir(path.Dir(file))

	doc, warnings := objectDocument(fsys, file)
	if len(warnings) != 0 {
		return defaultPluginLayout(root), warnings
	}
	return pluginLayoutFrom(root, file, doc)
}
