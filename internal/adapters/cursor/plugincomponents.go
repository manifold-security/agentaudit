package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const pluginHooksFile = "hooks/hooks.json"

const pluginMCPFile = "mcp.json"

const (
	pluginSkillsKey = "skills"
	pluginAgentsKey = "agents"
)

const (
	cursorPluginRootVar = "${CURSOR_PLUGIN_ROOT}"
	claudePluginRootVar = "${CLAUDE_PLUGIN_ROOT}"
)

type componentSource struct {
	// path is empty when the manifest named a location this scanner could
	// not resolve: nothing loads for that component, because the default it
	// replaced is not a location the plugin reads.
	path   string
	inline json.RawMessage
	// declared marks a component its manifest named. Only an undeclared
	// skills location falls back to the plugin root's own SKILL.md, and only
	// a declared location that holds nothing warns;
	// TestPluginManifestSkillsFieldLeavesTheRootSkillUnread and
	// TestPluginManifestDeclaredButAbsentComponentDegrades pin the two.
	declared bool
}

type pluginLayout struct {
	root         string
	manifestFile string
	mcp          componentSource
	hooks        componentSource
	skills       componentSource
	agents       componentSource
}

func defaultPluginLayout(root string) pluginLayout {
	return pluginLayout{
		root:   root,
		mcp:    componentSource{path: path.Join(root, pluginMCPFile)},
		hooks:  componentSource{path: path.Join(root, pluginHooksFile)},
		skills: componentSource{path: path.Join(root, pluginSkillsDir)},
		agents: componentSource{path: path.Join(root, pluginAgentsDir)},
	}
}

func pluginLayoutFrom(root, file string, doc map[string]json.RawMessage) (pluginLayout, []adapter.Warning) {
	layout := defaultPluginLayout(root)
	layout.manifestFile = file

	var warnings []adapter.Warning
	resolve := func(key string, inlineAllowed bool, def componentSource) componentSource {
		source, sourceWarnings := componentSourceFrom(doc[key], key, root, file, inlineAllowed, def)
		warnings = append(warnings, sourceWarnings...)
		return source
	}

	layout.mcp = resolve(mcpServersKey, true, layout.mcp)
	layout.hooks = resolve(hooksKey, true, layout.hooks)
	layout.skills = resolve(pluginSkillsKey, false, layout.skills)
	layout.agents = resolve(pluginAgentsKey, false, layout.agents)
	return layout, warnings
}

func componentSourceFrom(raw json.RawMessage, key, root, file string, inlineAllowed bool, def componentSource) (componentSource, []adapter.Warning) {
	form := mcpjson.FormOf(raw)
	switch {
	case form == mcpjson.FormAbsent:
		return def, nil
	case form == mcpjson.FormString:
		p, err := componentPath(root, key, stringValue(raw))
		if err != nil {
			return componentSource{declared: true}, []adapter.Warning{{File: file, Err: err}}
		}
		return componentSource{path: p, declared: true}, nil
	case form == mcpjson.FormObject && inlineAllowed:
		return componentSource{inline: raw, declared: true}, nil
	}

	want := "a path string"
	if inlineAllowed {
		want = "a path string or an inline object"
	}
	return componentSource{declared: true}, []adapter.Warning{{File: file, Err: errors.New(key + ": expected " + want + ", found " + mcpjson.FormName(form))}}
}

// componentPath refuses a location outside the plugin's own directory: the
// manifest is attacker-authored, and the tree around a plugin belongs to
// whoever installed it.
func componentPath(root, key, declared string) (string, error) {
	if declared == "" {
		return "", errors.New(key + ": expected a non-empty path")
	}

	p := path.Join(root, declared)
	if strings.HasPrefix(declared, "/") || !fs.ValidPath(p) {
		return "", escapingPath(key, declared)
	}
	if root != "." && p != root && !strings.HasPrefix(p, root+"/") {
		return "", escapingPath(key, declared)
	}
	return p, nil
}

func escapingPath(key, declared string) error {
	return adapter.Unreadable(fmt.Errorf("%s: path %q escapes the plugin root", key, declared))
}

// pluginComponentEntities reads the components a plugin loads, from the
// locations its layout resolved.
//
// No read is gated on the manifest beside it yielding a plugin: a descriptor
// this scanner cannot name a plugin from would otherwise take the component
// files down with it, and a source that stops contributing without saying so
// is the defect this tool exists to catch.
func pluginComponentEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning, error) {
	entities, warnings := pluginMCPEntities(fsys, layout)

	hooks, hookWarnings, err := pluginHookEntities(fsys, layout)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, hooks...)
	warnings = append(warnings, hookWarnings...)

	markdown, markdownWarnings := pluginMarkdownEntities(fsys, layout)
	entities = append(entities, markdown...)
	warnings = append(warnings, markdownWarnings...)

	return entities, warnings, nil
}

// pluginMCPEntities reads the servers a plugin declares, from the document
// its layout names or from the manifest carrying them inline. The
// plugin-root spellings resolve before each server is built, so a reader
// checking the report against the tree finds the command where the report
// says it sits.
func pluginMCPEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning) {
	file, raw := layout.manifestFile, layout.mcp.inline
	if raw == nil {
		if layout.mcp.path == "" {
			return nil, nil
		}

		file = layout.mcp.path
		if warnings := declaredLocationWarnings(fsys, layout.mcp); len(warnings) != 0 {
			return nil, warnings
		}

		doc, warnings := objectDocument(fsys, file)
		if len(warnings) != 0 {
			return nil, warnings
		}
		raw = doc[mcpServersKey]
	}

	servers, serverWarnings := mcpjson.ServersFromRaw(raw, file, mcpServersKey)
	for name, entry := range servers {
		servers[name] = expandEntry(entry, layout.root)
	}
	return mcpjson.Entities(servers, file, mcpServersKey, transportOf), serverWarnings
}

func pluginHookEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning, error) {
	if layout.hooks.inline != nil {
		entities, warnings := inlineHookEntities(layout.manifestFile, layout.hooks.inline)
		return entities, warnings, nil
	}
	if layout.hooks.path == "" {
		return nil, nil, nil
	}
	if warnings := declaredLocationWarnings(fsys, layout.hooks); len(warnings) != 0 {
		return nil, warnings, nil
	}
	return hookEntities(fsys, layout.hooks.path)
}

// declaredLocationWarnings reports a location the manifest named that this
// scanner cannot reach. Absence is silent at a default location and loud at
// a declared one, because silence there leaves a reader unable to tell a
// plugin that ships no component from a manifest pointing at nothing.
func declaredLocationWarnings(fsys fs.FS, source componentSource) []adapter.Warning {
	if !source.declared {
		return nil
	}
	if _, err := fsguard.LinkMode(fsys, source.path); err != nil {
		return []adapter.Warning{{File: source.path, Err: err}}
	}
	return nil
}

func inlineHookEntities(file string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	var byEvent map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byEvent); err != nil {
		return nil, []adapter.Warning{{File: file, Err: fmt.Errorf("%s: %w", hooksKey, err)}}
	}

	events := make([]string, 0, len(byEvent))
	for event := range byEvent {
		events = append(events, event)
	}
	sort.Strings(events)

	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, event := range events {
		eventEntities, eventWarnings := entitiesFromEvent(file, event, byEvent[event])
		entities = append(entities, eventEntities...)
		warnings = append(warnings, eventWarnings...)
	}
	return entities, warnings
}

func expandEntry(e mcpjson.Entry, root string) mcpjson.Entry {
	out := e
	out.Command = expandPluginRoot(e.Command, root)

	if e.Args != nil {
		out.Args = make([]string, len(e.Args))
		for i, arg := range e.Args {
			out.Args[i] = expandPluginRoot(arg, root)
		}
	}
	if e.Env != nil {
		out.Env = make(map[string]string, len(e.Env))
		for k, v := range e.Env {
			out.Env[k] = expandPluginRoot(v, root)
		}
	}
	return out
}

// expandPluginRoot substitutes the plugin-root spellings Cursor resolves to
// a plugin's install path. Cursor's plugins reference lists neither the
// standard's ${PLUGIN_ROOT} nor its ${PLUGIN_DATA}, so they are absent from
// the pairs below and a value naming one travels verbatim.
// TestPluginMCPResolvesOnlyTheSpellingsCursorSubstitutes pins the
// substitution and the passthrough.
func expandPluginRoot(text, root string) string {
	// The trailing-slash pair precedes the bare one so a repository-root
	// plugin's separator collapses rather than leaving "./bin/index".
	slash := root + "/"
	if root == "." {
		slash = ""
	}
	return strings.NewReplacer(
		cursorPluginRootVar+"/", slash,
		cursorPluginRootVar, root,
		claudePluginRootVar+"/", slash,
		claudePluginRootVar, root,
	).Replace(text)
}
