package claude

import (
	"bytes"
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
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const pluginManifestDir = ".claude-plugin"

const pluginManifestFile = "plugin.json"

const pluginMCPFile = ".mcp.json"

const pluginHooksFile = "hooks/hooks.json"

const pluginBinDir = "bin"

const pluginAgentsDir = "agents"

const pluginSkillsDir = "skills"

const pluginCommandsDir = "commands"

// pluginRoots walks fsys once and returns the plugin roots, sorted lexically.
// The manifest location is a literal here while discovery derives it from
// Signatures(), so the two can drift apart and leave discovery flagging a root
// this walk never parses; TestPluginRootsAgreesWithDiscovery is what holds
// them together.
//
// A plugin nested inside another plugin root is emitted as its own root: that
// nesting is the evasion a depth-agnostic signature closes, so node_modules/**
// and vendor/** manifests are found on purpose.
//
// A per-directory walk failure degrades to a Warning, keeping every root found
// so far.
func pluginRoots(fsys fs.FS) ([]string, []adapter.Warning) {
	var roots []string
	var warnings []adapter.Warning

	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		// The basename test runs before any directory skip: a manifest path
		// that is a DIRECTORY still marks a plugin root, and an empty one
		// has no file entries for a later check to notice.
		if path.Base(p) != pluginManifestFile || path.Base(path.Dir(p)) != pluginManifestDir {
			return nil
		}
		roots = append(roots, path.Dir(path.Dir(p)))
		// Keep descending: pruning a directory-typed manifest would let a
		// hostile repo hide a valid plugin beneath a decoy named plugin.json.
		return nil
	})

	sort.Strings(roots)
	return roots, warnings
}

// pluginManifest is the decoded .claude-plugin/plugin.json. Unmapped keys are
// ignored, matching how Claude Code tolerates unknown manifest keys.
type pluginManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// MCPServers and Hooks stay json.RawMessage because each accepts string,
	// array or object form, and a wrong-typed value must degrade to a per-key
	// Warning rather than a decode failure that hides the plugin's siblings.
	MCPServers json.RawMessage `json:"mcpServers"`
	Hooks      json.RawMessage `json:"hooks"`
	// Path-valued keys: their targets are walked for markdown, so RawMessage
	// buys just the string/array dispatch.
	Agents   json.RawMessage `json:"agents"`
	Skills   json.RawMessage `json:"skills"`
	Commands json.RawMessage `json:"commands"`

	LSPServers json.RawMessage `json:"lspServers"`
}

func pluginManifestPath(root string) string {
	return path.Join(root, pluginManifestDir, pluginManifestFile)
}

// readPluginManifest reads and decodes root's manifest; any failure is a
// Warning, never fatal. checkContainment is not called here: the manifest's
// only intermediate component is .claude-plugin, which pluginRoots' fs.WalkDir
// already proved a real directory by recursing from its unfollowed DirEntry.
func readPluginManifest(fsys fs.FS, root string) (pluginManifest, *adapter.Warning) {
	manifestFile := pluginManifestPath(root)

	if err := fsguard.CheckRegular(fsys, manifestFile); err != nil {
		return pluginManifest{}, &adapter.Warning{File: manifestFile, Err: err}
	}

	data, err := fs.ReadFile(fsys, manifestFile)
	if err != nil {
		return pluginManifest{}, &adapter.Warning{File: manifestFile, Err: err}
	}

	var m pluginManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return pluginManifest{}, &adapter.Warning{File: manifestFile, Err: err}
	}

	return m, nil
}

func pluginName(m pluginManifest, root string) string {
	if m.Name != "" {
		return m.Name
	}
	return path.Base(root)
}

func pluginPresenceEntity(m pluginManifest, root, manifestFile string) ir.Plugin {
	return ir.Plugin{
		Name:     pluginName(m, root),
		Version:  m.Version,
		Location: ir.Location{File: manifestFile, Key: "name"},
	}
}

// pluginRootEntities emits one plugin root's entities. The presence entity
// is emitted even for a missing or malformed manifest.
func pluginRootEntities(fsys fs.FS, root string) ([]ir.Entity, []adapter.Warning) {
	manifestFile := pluginManifestPath(root)

	m, warning := readPluginManifest(fsys, root)

	var warnings []adapter.Warning
	if warning != nil {
		warnings = append(warnings, *warning)
	}

	plugin := pluginName(m, root)
	entities, refused := limits.Of(fsys).Admit(manifestFile, []ir.Entity{pluginPresenceEntity(m, root, manifestFile)}, nil)
	warnings = append(warnings, refused...)

	mcpEntities, mcpWarnings := pluginMCPEntities(fsys, root, manifestFile, m.MCPServers)
	entities = append(entities, mcpEntities...)
	warnings = append(warnings, mcpWarnings...)

	hookEnts, hookWarnings := pluginHookEntities(fsys, root, manifestFile, m.Hooks)
	entities = append(entities, hookEnts...)
	warnings = append(warnings, hookWarnings...)

	agentEnts, agentWarnings := pluginAgentEntities(fsys, root, manifestFile, m.Agents)
	entities = append(entities, agentEnts...)
	warnings = append(warnings, agentWarnings...)

	skillEnts, skillWarnings := pluginSkillEntities(fsys, root, manifestFile, m.Skills)
	entities = append(entities, skillEnts...)
	warnings = append(warnings, skillWarnings...)

	commandEnts, commandWarnings := pluginCommandEntities(fsys, root, manifestFile, m.Commands)
	entities = append(entities, commandEnts...)
	warnings = append(warnings, commandWarnings...)

	binEntities, binWarnings := pluginExecutableEntities(fsys, root, plugin)
	entities = append(entities, binEntities...)
	warnings = append(warnings, binWarnings...)

	lspEnts, lspWarnings := pluginLSPEntities(fsys, root, manifestFile, m.LSPServers)
	entities = append(entities, lspEnts...)
	warnings = append(warnings, lspWarnings...)

	return entities, warnings
}

// pluginExecutableEntities emits one ir.PluginExecutable per entry directly
// under <root>/bin that could run on the PATH: bin/ is a flat PATH directory,
// so a nested bin/sub/tool is not invokable. The +x bit is recorded, never an
// emission gate — it is trivially settable, so gating on it would let a chmod
// hide it.
//
// A FIFO, socket or device node carries permission bits like any other inode,
// so emitting one would report Executable on a path that cannot be executed at
// all. A symlink is kept instead: telling what it points at would mean
// following the link, and an invisible miss costs more than a visible
// duplicate.
func pluginExecutableEntities(fsys fs.FS, root, plugin string) ([]ir.Entity, []adapter.Warning) {
	binDir := path.Join(root, pluginBinDir)

	if err := checkContainment(fsys, root, binDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: binDir, Err: err}}
	}
	if err := checkRealDir(fsys, binDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		// A per-source Warning: one file named "bin" must not blind the
		// whole scan.
		return nil, []adapter.Warning{{File: binDir, Err: err}}
	}

	entries, err := fs.ReadDir(fsys, binDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: binDir, Err: err}}
	}

	var entities []ir.Entity
	for _, d := range entries {
		if t := d.Type(); !t.IsRegular() && t&fs.ModeSymlink == 0 {
			continue
		}
		p := path.Join(binDir, d.Name())
		executableValue := ""
		if executable(d) {
			executableValue = "true"
		}
		entities = append(entities, ir.PluginExecutable{
			Path:       p,
			Name:       d.Name(),
			Plugin:     plugin,
			Extension:  strings.ToLower(path.Ext(p)),
			Executable: executableValue,
			Location:   ir.Location{File: p},
		})
	}

	return limits.Of(fsys).Admit(binDir, entities, nil)
}

type pluginDoc struct {
	File string
	Data []byte
}

// resolvePluginPath joins a manifest-declared "./"-relative path onto root. A
// plugin cannot reference files outside its own directory: enforcing it here
// stops a crafted manifest from attributing an unrelated file to the plugin.
func resolvePluginPath(root, rel string) (string, bool) {
	if rel == "" || path.IsAbs(rel) {
		return "", false
	}
	p := path.Join(root, rel)
	if root == "." {
		if p == ".." || strings.HasPrefix(p, "../") {
			return "", false
		}
		return p, true
	}
	if p != root && !strings.HasPrefix(p, root+"/") {
		return "", false
	}
	return p, true
}

func resolvePluginDoc(fsys fs.FS, root, manifestFile, key, rel string) (*pluginDoc, *adapter.Warning) {
	resolved, ok := resolvePluginPath(root, rel)
	if !ok {
		return nil, &adapter.Warning{File: manifestFile, Err: adapter.Unreadable(fmt.Errorf("%s: path %q escapes the plugin root", key, rel))}
	}
	if err := checkContainment(fsys, root, resolved); err != nil {
		return nil, &adapter.Warning{File: resolved, Err: err}
	}
	if err := fsguard.CheckRegular(fsys, resolved); err != nil {
		return nil, &adapter.Warning{File: resolved, Err: err}
	}
	data, err := fs.ReadFile(fsys, resolved)
	if err != nil {
		return nil, &adapter.Warning{File: resolved, Err: err}
	}
	return &pluginDoc{File: resolved, Data: data}, nil
}

// checkContainment reports an error unless every directory component of p
// strictly between root and p's own basename is a real directory rather than a
// symlink to one. fsguard.CheckRegular and checkRealDir each classify only p's
// FINAL component, so a symlinked INTERMEDIATE component silently redirects the
// read outside the scanned repository while the final-component check still
// passes.
//
// The walk is top-down from root, which pluginRoots' fs.WalkDir reached without
// descending a symlink, and each step proves cur a real directory before
// advancing beneath it, so every check is rooted at a symlink-free path.
func checkContainment(fsys fs.FS, root, p string) error {
	// p == root has no components between the two to check, and the
	// root+"/" prefix test below would refuse the root itself, dropping
	// the surface (TestManifestAgentsKeyDotResolvesToPluginRootItself).
	if p == root {
		return nil
	}
	rel := p
	if root != "." {
		if !strings.HasPrefix(p, root+"/") {
			return adapter.Unreadable(fmt.Errorf("refusing to read %q: outside the plugin root %q", p, root))
		}
		rel = strings.TrimPrefix(p, root+"/")
	}
	parts := strings.Split(rel, "/")
	cur := root
	for _, part := range parts[:len(parts)-1] {
		cur = path.Join(cur, part)
		if err := checkRealDir(fsys, cur); err != nil {
			return err
		}
	}
	return nil
}

// pluginDocs resolves one string/array/object manifest key into the documents
// to decode; key is used verbatim in warning text so a reader can grep their
// own manifest. A missing or wrong-typed value is a per-key Warning, not an
// abort that would hide the plugin's other surfaces.
func pluginDocs(fsys fs.FS, root, manifestFile, key string, raw json.RawMessage) ([]pluginDoc, []adapter.Warning) {
	switch mcpjson.FormOf(raw) {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormString:
		var rel string
		if err := json.Unmarshal(raw, &rel); err != nil {
			return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: %w", key, err)}}
		}
		doc, warning := resolvePluginDoc(fsys, root, manifestFile, key, rel)
		if warning != nil {
			return nil, []adapter.Warning{*warning}
		}
		return []pluginDoc{*doc}, nil
	case mcpjson.FormArray:
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: %w", key, err)}}
		}
		if refusal, ok := limits.Of(fsys).Spend(manifestFile, len(elems)); !ok {
			return nil, []adapter.Warning{refusal}
		}
		var docs []pluginDoc
		var warnings []adapter.Warning
		for i, elem := range elems {
			var rel string
			// A JSON null decodes into a string without error, and the
			// empty string then reads as a path escape, sending the
			// reader after a traversal that is not there.
			if mcpjson.FormOf(elem) == mcpjson.FormAbsent {
				warnings = append(warnings, adapter.Warning{File: manifestFile, Err: fmt.Errorf("%s[%d]: null, not a string", key, i)})
				continue
			}
			if err := json.Unmarshal(elem, &rel); err != nil {
				warnings = append(warnings, adapter.Warning{File: manifestFile, Err: fmt.Errorf("%s[%d]: not a string", key, i)})
				continue
			}
			doc, warning := resolvePluginDoc(fsys, root, manifestFile, key, rel)
			if warning != nil {
				warnings = append(warnings, *warning)
				continue
			}
			docs = append(docs, *doc)
		}
		return docs, warnings
	case mcpjson.FormObject:
		return []pluginDoc{{File: manifestFile, Data: raw}}, nil
	default: // mcpjson.FormOther
		return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: not parsed, expected a string, array or object", key)}}
	}
}

// pluginDefaultDoc reads a default-location component file. A missing default
// is silent — a convention, not a declaration — unlike pluginDocs' string.
func pluginDefaultDoc(fsys fs.FS, root, file string) (*pluginDoc, *adapter.Warning) {
	if err := checkContainment(fsys, root, file); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &adapter.Warning{File: file, Err: err}
	}
	if err := fsguard.CheckRegular(fsys, file); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &adapter.Warning{File: file, Err: err}
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &adapter.Warning{File: file, Err: err}
	}
	return &pluginDoc{File: file, Data: data}, nil
}

type mcpServersWrapperProbe struct {
	MCPServers json.RawMessage `json:"mcpServers"`
}

// pluginDocObjectForm gates mcpjson.FormOf on json.Valid: FormOf classifies
// by the first non-space byte, and invalid JSON must keep its decoder's real
// parse error (TestMCPServersStringFormSurfacesRealParseErrorOnInvalidJSON).
func pluginDocObjectForm(doc pluginDoc) (stop bool, warnings []adapter.Warning) {
	if string(bytes.TrimSpace(doc.Data)) == "null" {
		return true, nil
	}
	if json.Valid(doc.Data) {
		if f := mcpjson.FormOf(doc.Data); f != mcpjson.FormObject {
			return true, []adapter.Warning{{File: doc.File, Err: errors.New("expected an object of server entries, found " + mcpjson.FormName(f))}}
		}
	}
	return false, nil
}

// mcpServersFromDoc decodes doc as either a {"mcpServers": {...}} wrapper or a
// bare server map; a top-level "mcpServers" key selects the wrapper, so a bare
// map holding a server named "mcpServers" reads as a wrapper — the safer
// reading, since it still surfaces the inner servers.
func mcpServersFromDoc(doc pluginDoc, budget *limits.Entities) (map[string]mcpjson.Entry, []adapter.Warning) {
	if stop, warnings := pluginDocObjectForm(doc); stop {
		return nil, warnings
	}

	var probe mcpServersWrapperProbe
	if err := json.Unmarshal(doc.Data, &probe); err != nil {
		return nil, []adapter.Warning{{File: doc.File, Err: err}}
	}
	if probe.MCPServers != nil {
		return mcpjson.ServersFromRaw(probe.MCPServers, doc.File, "mcpServers", budget)
	}
	return mcpjson.ServersFromRaw(doc.Data, doc.File, "", budget)
}

// pluginMCPEntities substitutes placeholders before each entity is built.
func pluginMCPEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	v := dirVars{PluginRoot: root}
	budget := limits.Of(fsys)

	var entities []ir.Entity
	var warnings []adapter.Warning

	// A plugin root of "." shares its .mcp.json with the project-root source
	// mcp.go already parses. Accepted under-report: mcp.go performs no variable
	// substitution, so that plugin keeps a literal ${CLAUDE_PLUGIN_ROOT}.
	if root != "." {
		defaultFile := path.Join(root, pluginMCPFile)
		doc, warning := pluginDefaultDoc(fsys, root, defaultFile)
		if warning != nil {
			warnings = append(warnings, *warning)
		} else if doc != nil {
			servers, docWarnings := mcpServersFromDoc(*doc, budget)
			mcpEnts, mcpWarnings := entitiesFromMCPMap(expandMCPMap(servers, v), doc.File, "mcpServers")
			mcpEnts, docWarnings = budget.Admit(doc.File, mcpEnts, append(docWarnings, mcpWarnings...))
			entities = append(entities, mcpEnts...)
			warnings = append(warnings, docWarnings...)
		}
	}

	docs, docWarnings := pluginDocs(fsys, root, manifestFile, "mcpServers", raw)
	warnings = append(warnings, docWarnings...)
	for _, doc := range docs {
		servers, sw := mcpServersFromDoc(doc, budget)
		mcpEnts, mcpWarnings := entitiesFromMCPMap(expandMCPMap(servers, v), doc.File, "mcpServers")
		mcpEnts, sw = budget.Admit(doc.File, mcpEnts, append(sw, mcpWarnings...))
		entities = append(entities, mcpEnts...)
		warnings = append(warnings, sw...)
	}

	return entities, warnings
}

func expandMCPEntry(e mcpjson.Entry, v dirVars) mcpjson.Entry {
	out := e
	out.Command = expandDirVars(e.Command, v)
	out.URL = expandDirVars(e.URL, v)
	if helper, ok := e.HeadersHelper.(string); ok {
		out.HeadersHelper = expandDirVars(helper, v)
	}

	if e.Args != nil {
		out.Args = make([]string, len(e.Args))
		for i, a := range e.Args {
			out.Args[i] = expandDirVars(a, v)
		}
	}
	if e.Env != nil {
		out.Env = make(map[string]string, len(e.Env))
		for k, val := range e.Env {
			out.Env[k] = expandDirVars(val, v)
		}
	}

	return out
}

func expandMCPMap(servers map[string]mcpjson.Entry, v dirVars) map[string]mcpjson.Entry {
	if servers == nil {
		return nil
	}
	out := make(map[string]mcpjson.Entry, len(servers))
	for name, e := range servers {
		out[name] = expandMCPEntry(e, v)
	}
	return out
}

type hooksWrapperProbe struct {
	Hooks json.RawMessage `json:"hooks"`
}

// hooksFromDoc accepts both a {"hooks": {...}} wrapper and a bare
// <Event> -> []hookGroup map, because the docs never state the manifest's
// inline shape; a top-level "hooks" key selects the wrapper.
func hooksFromDoc(doc pluginDoc) (map[string][]hookGroup, []adapter.Warning) {
	var probe hooksWrapperProbe
	if err := json.Unmarshal(doc.Data, &probe); err != nil {
		return nil, []adapter.Warning{{File: doc.File, Err: err}}
	}

	raw := doc.Data
	if probe.Hooks != nil {
		raw = probe.Hooks
	}

	var hooks map[string][]hookGroup
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return nil, []adapter.Warning{{File: doc.File, Err: err}}
	}
	return hooks, nil
}

// expandHookEntities mutates in place, safe on a freshly allocated slice.
func expandHookEntities(entities []ir.Entity, v dirVars) []ir.Entity {
	for i, e := range entities {
		h := e.(ir.Hook)
		h.Command = expandDirVars(h.Command, v)
		entities[i] = h
	}
	return entities
}

// pluginHookEntities needs no root=="." de-dup carve-out, unlike
// pluginMCPEntities: hooks/hooks.json has no project-root counterpart.
func pluginHookEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	v := dirVars{PluginRoot: root}

	var entities []ir.Entity
	var warnings []adapter.Warning

	defaultFile := path.Join(root, pluginHooksFile)
	doc, warning := pluginDefaultDoc(fsys, root, defaultFile)
	if warning != nil {
		warnings = append(warnings, *warning)
	} else if doc != nil {
		hooks, hw := hooksFromDoc(*doc)
		found, kept := limits.Of(fsys).Admit(doc.File, expandHookEntities(hookEntities(hooks, doc.File), v), hw)
		entities = append(entities, found...)
		warnings = append(warnings, kept...)
	}

	docs, docWarnings := pluginDocs(fsys, root, manifestFile, "hooks", raw)
	warnings = append(warnings, docWarnings...)
	for _, doc := range docs {
		hooks, hw := hooksFromDoc(doc)
		found, kept := limits.Of(fsys).Admit(doc.File, expandHookEntities(hookEntities(hooks, doc.File), v), hw)
		entities = append(entities, found...)
		warnings = append(warnings, kept...)
	}

	return entities, warnings
}

// pluginComponent is the descriptor each component surface shares, so their
// walks reach the filesystem through one guarded path.
type pluginComponent struct {
	key        string
	defaultDir string
	// supplements records an asymmetry Claude Code documents, not one this
	// scanner chose: a declared skills key still loads the default skills/
	// directory, while a declared agents or commands key replaces its default.
	supplements bool
	// selects mirrors the walk's own file filter, so a manifest path naming a
	// single file the surface would never load warns instead of yielding no
	// entities, which the plugin author reads as "no capabilities here".
	selects func(string) bool
	walkDir func(fs.FS, string) ([]ir.Entity, []adapter.Warning, error)
}

var (
	agentComponent = pluginComponent{
		key:        "agents",
		defaultDir: pluginAgentsDir,
		selects:    isMarkdownFile,
		walkDir:    walkPluginShippedAgentDir,
	}

	skillComponent = pluginComponent{
		key:         "skills",
		defaultDir:  pluginSkillsDir,
		supplements: true,
		selects:     isSkillFile,
		walkDir:     walkPluginShippedSkillDir,
	}

	commandComponent = pluginComponent{
		key:        "commands",
		defaultDir: pluginCommandsDir,
		selects:    isMarkdownFile,
		walkDir:    walkPluginShippedCommandDir,
	}
)

var (
	pluginShippedSkillSource   = markdownSource{matches: isSkillFile, parse: parseSkill, namesLinks: true}
	pluginShippedCommandSource = markdownSource{matches: isMarkdownFile, parse: parseCommand, namesLinks: true}
)

// walkPluginShippedSkillDir refuses a non-regular file: a plugin is third-party
// content resolved through a manifest it also wrote.
func walkPluginShippedSkillDir(fsys fs.FS, dir string) ([]ir.Entity, []adapter.Warning, error) {
	return walkMarkdownDir(fsys, dir, pluginShippedSkillSource, fsguard.CheckRegular)
}

func walkPluginShippedCommandDir(fsys fs.FS, dir string) ([]ir.Entity, []adapter.Warning, error) {
	return walkMarkdownDir(fsys, dir, pluginShippedCommandSource, fsguard.CheckRegular)
}

// walkPluginShippedAgentDir binds walkAgentDir's isPlugin flag, the plugin
// security carve-out.
func walkPluginShippedAgentDir(fsys fs.FS, dir string) ([]ir.Entity, []adapter.Warning, error) {
	return walkAgentDir(fsys, dir, pluginShippedAgent)
}

// pluginComponentPaths resolves a declared key into the paths the walk visits.
// mcpjson.FormAbsent is the caller's business: it alone can tell a
// declared-but-empty key from one that falls back to the default.
func pluginComponentPaths(root, manifestFile, key string, raw json.RawMessage, budget *limits.Entities) ([]string, []adapter.Warning) {
	switch mcpjson.FormOf(raw) {
	case mcpjson.FormString:
		var rel string
		if err := json.Unmarshal(raw, &rel); err != nil {
			return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: %w", key, err)}}
		}
		resolved, ok := resolvePluginPath(root, rel)
		if !ok {
			return nil, []adapter.Warning{{File: manifestFile, Err: adapter.Unreadable(fmt.Errorf("%s: path %q escapes the plugin root", key, rel))}}
		}
		return []string{resolved}, nil
	case mcpjson.FormArray:
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: %w", key, err)}}
		}
		if refusal, ok := budget.Spend(manifestFile, len(elems)); !ok {
			return nil, []adapter.Warning{refusal}
		}
		var paths []string
		var warnings []adapter.Warning
		for i, elem := range elems {
			if mcpjson.FormOf(elem) == mcpjson.FormAbsent {
				warnings = append(warnings, adapter.Warning{File: manifestFile, Err: fmt.Errorf("%s[%d]: null, not a string", key, i)})
				continue
			}
			var rel string
			if err := json.Unmarshal(elem, &rel); err != nil {
				warnings = append(warnings, adapter.Warning{File: manifestFile, Err: fmt.Errorf("%s[%d]: not a string", key, i)})
				continue
			}
			resolved, ok := resolvePluginPath(root, rel)
			if !ok {
				warnings = append(warnings, adapter.Warning{File: manifestFile, Err: adapter.Unreadable(fmt.Errorf("%s[%d]: path %q escapes the plugin root", key, i, rel))})
				continue
			}
			paths = append(paths, resolved)
		}
		return paths, warnings
	default: // mcpjson.FormOther (mcpjson.FormAbsent is handled by the caller)
		return nil, []adapter.Warning{{File: manifestFile, Err: fmt.Errorf("%s: not parsed, expected a string or array", key)}}
	}
}

// declaredComponentPath / defaultComponentPath name walkPluginComponentPath's
// flag. A default location is a convention, so its absence is silent; a
// declared path is the author's assertion, so its absence warns.
const (
	declaredComponentPath = true
	defaultComponentPath  = false
)

// pluginComponentEntities emits an entity reachable through both the default
// directory and a declared path under each provenance path rather than once: a
// visible duplicate is cheaper than a capability that vanishes.
func pluginComponentEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage, c pluginComponent) ([]ir.Entity, []adapter.Warning) {
	declared := mcpjson.FormOf(raw) != mcpjson.FormAbsent

	var entities []ir.Entity
	var warnings []adapter.Warning

	if !declared || c.supplements {
		entities, warnings = walkPluginComponentPath(fsys, root, path.Join(root, c.defaultDir), defaultComponentPath, c)
	}
	if !declared {
		return entities, warnings
	}

	paths, pathWarnings := pluginComponentPaths(root, manifestFile, c.key, raw, limits.Of(fsys))
	warnings = append(warnings, pathWarnings...)
	for _, p := range paths {
		es, ws := walkPluginComponentPath(fsys, root, p, declaredComponentPath, c)
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
	}
	return entities, warnings
}

func walkPluginComponentPath(fsys fs.FS, root, p string, declared bool, c pluginComponent) ([]ir.Entity, []adapter.Warning) {
	// checkRealDir guards the walk ROOT p itself, because fs.WalkDir stats its
	// root and that follows a symlink; the walk guards every entry below it.
	if err := checkContainment(fsys, root, p); err != nil {
		return nil, componentPathWarning(p, err, declared)
	}
	if err := checkRealDir(fsys, p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, componentPathWarning(p, err, declared)
		}
		// A manifest may name a single component FILE, which fs.WalkDir visits
		// as its own root. The DirEntry it synthesises for that root comes from
		// a symlink-FOLLOWING stat, so only fsguard.CheckRegular can refuse a link.
		if rerr := fsguard.CheckRegular(fsys, p); rerr != nil {
			return nil, componentPathWarning(p, err, declared)
		}
		if !c.selects(p) {
			return nil, []adapter.Warning{{File: p, Err: adapter.Unreadable(fmt.Errorf("skipping %q: the %s surface does not load this file", p, c.key))}}
		}
	}
	es, ws, err := c.walkDir(fsys, p)
	if err != nil {
		return es, append(ws, adapter.Warning{File: p, Err: err})
	}
	return es, ws
}

func pluginAgentEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	return pluginComponentEntities(fsys, root, manifestFile, raw, agentComponent)
}

// pluginSkillEntities adds the root-SKILL.md fallback, which Claude Code loads
// only when there is neither a skills/ directory nor a skills manifest key.
func pluginSkillEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	entities, warnings := pluginComponentEntities(fsys, root, manifestFile, raw, skillComponent)

	if mcpjson.FormOf(raw) != mcpjson.FormAbsent {
		return entities, warnings
	}
	if err := checkRealDir(fsys, path.Join(root, pluginSkillsDir)); !errors.Is(err, fs.ErrNotExist) {
		return entities, warnings
	}

	es, ws := walkPluginComponentPath(fsys, root, path.Join(root, skillFileName), defaultComponentPath, skillComponent)
	return append(entities, es...), append(warnings, ws...)
}

func pluginCommandEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	return pluginComponentEntities(fsys, root, manifestFile, raw, commandComponent)
}

func componentPathWarning(p string, err error, declared bool) []adapter.Warning {
	if !declared && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return []adapter.Warning{{File: p, Err: err}}
}

// checkRealDir reports an error unless p names a real directory, not a symlink
// to one. The fs.FS root itself is accepted: it is the scan boundary, not
// something a scanned repo can redirect.
func checkRealDir(fsys fs.FS, p string) error {
	if p == "." {
		return nil
	}
	mode, err := fsguard.LinkMode(fsys, p)
	if err != nil {
		return err
	}
	if !mode.IsDir() {
		return adapter.Unreadable(fmt.Errorf("refusing to walk %q: not a real directory (%s)", p, mode))
	}
	return nil
}

// pluginEntities walks the roots in sorted order so goldens are stable.
func pluginEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	roots, rootsWarnings := pluginRoots(fsys)

	var entities []ir.Entity
	warnings := append([]adapter.Warning(nil), rootsWarnings...)
	for _, root := range roots {
		rootEntities, rootWarnings := pluginRootEntities(fsys, root)
		entities = append(entities, rootEntities...)
		warnings = append(warnings, rootWarnings...)
	}

	return entities, warnings
}
