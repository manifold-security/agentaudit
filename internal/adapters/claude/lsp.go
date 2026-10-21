package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const pluginLSPFile = ".lsp.json"

const lspServersKey = "lspServers"

type lspServerEntry struct {
	Command any `json:"command"`
	Args    any `json:"args"`
}

func lspEntriesFromRaw(raw json.RawMessage, file string) (map[string]lspServerEntry, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New("expected an object of server entries, found " + mcpjson.FormName(f))}}
	}

	var rawEntries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}

	names := make([]string, 0, len(rawEntries))
	for name := range rawEntries {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make(map[string]lspServerEntry, len(rawEntries))
	var warnings []adapter.Warning
	for _, name := range names {
		if mcpjson.FormOf(rawEntries[name]) != mcpjson.FormObject {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s.%s: expected an object", lspServersKey, name)})
			continue
		}
		var entry lspServerEntry
		if err := json.Unmarshal(rawEntries[name], &entry); err != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s.%s: %w", lspServersKey, name, err)})
			continue
		}
		entries[name] = entry
	}
	return entries, warnings
}

func lspServersFromDoc(doc pluginDoc) (map[string]lspServerEntry, []adapter.Warning) {
	if stop, warnings := pluginDocObjectForm(doc); stop {
		return nil, warnings
	}
	return lspEntriesFromRaw(doc.Data, doc.File)
}

func lspValueForm(v any) string {
	switch v.(type) {
	case nil:
		return "nothing"
	case string:
		return "an empty string"
	default:
		return "a non-string value"
	}
}

func lspArgsOf(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	args := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		args = append(args, s)
	}
	return args, true
}

func expandArgsDirVars(args []string, v dirVars) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = expandDirVars(a, v)
	}
	return out
}

func lspServerEntities(entries map[string]lspServerEntry, file string, v dirVars) ([]ir.Entity, []adapter.Warning) {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, name := range names {
		entry := entries[name]
		key := lspServersKey + "." + name

		command, ok := entry.Command.(string)
		if !ok || command == "" {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s.command: expected a non-empty string, found %s", key, lspValueForm(entry.Command))})
			continue
		}

		args, argsOK := lspArgsOf(entry.Args)
		if !argsOK {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s.args: expected an array of strings", key)})
		}

		entities = append(entities, ir.LSPServer{
			Name:     name,
			Command:  expandDirVars(command, v),
			Args:     expandArgsDirVars(args, v),
			Location: ir.Location{File: file, Key: key},
		})
	}
	return entities, warnings
}

func pluginLSPEntities(fsys fs.FS, root, manifestFile string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	v := dirVars{PluginRoot: root}

	var entities []ir.Entity
	var warnings []adapter.Warning

	defaultFile := path.Join(root, pluginLSPFile)
	doc, warning := pluginDefaultDoc(fsys, root, defaultFile)
	if warning != nil {
		warnings = append(warnings, *warning)
	} else if doc != nil {
		entries, ew := lspServersFromDoc(*doc)
		es, esw := lspServerEntities(entries, doc.File, v)
		es, ew = limits.Of(fsys).Admit(doc.File, es, append(ew, esw...))
		entities = append(entities, es...)
		warnings = append(warnings, ew...)
	}

	docs, docWarnings := pluginDocs(fsys, root, manifestFile, lspServersKey, raw)
	warnings = append(warnings, docWarnings...)
	for _, doc := range docs {
		entries, ew := lspServersFromDoc(doc)
		es, esw := lspServerEntities(entries, doc.File, v)
		es, ew = limits.Of(fsys).Admit(doc.File, es, append(ew, esw...))
		entities = append(entities, es...)
		warnings = append(warnings, ew...)
	}

	return entities, warnings
}
