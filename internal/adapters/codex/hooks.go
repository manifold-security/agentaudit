package codex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

const (
	hooksKey   = "hooks"
	matcherKey = "matcher"
	typeKey    = "type"
	commandKey = "command"
	serverKey  = "server"
	toolKey    = "tool"
)

var windowsCommandKeys = []string{"commandWindows", "command_windows"}

var tomlHooksSettings = map[string]bool{"managed_dir": true, "windows_managed_dir": true}

func hooksFileEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	data, err := fsguard.ReadResolvedRegular(fsys, hooksFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: hooksFileName, Err: err}}
	}

	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: hooksFileName, Err: err}}
	}
	table, ok := doc.(map[string]any)
	if !ok {
		return nil, []adapter.Warning{{
			File: hooksFileName,
			Err:  errors.New("expected " + formName(hooksFileName, tomlconf.FormTable) + ", found " + formName(hooksFileName, tomlconf.FormOf(doc))),
		}}
	}
	entities, warnings := hookEntities(hooksFileName, table[hooksKey], nil)
	entities, warnings = limits.Of(fsys).Admit(hooksFileName, entities, warnings)
	return entities, warnings
}

func hookEntities(file string, raw any, settings map[string]bool) ([]ir.Entity, []adapter.Warning) {
	events, warnings := tableAt(file, hooksKey, raw)

	var entities []ir.Entity
	for _, event := range tableEntries(hooksKey, events) {
		if settings[event.name] {
			_, settingWarnings := stringAt(file, event.key, event.value)
			warnings = append(warnings, settingWarnings...)
			continue
		}
		groups, groupWarnings := elementsAt(file, event.key, event.value, "an array of matcher groups", "a matcher group")
		warnings = append(warnings, groupWarnings...)
		for _, group := range groups {
			found, groupWarnings := groupEntities(file, event.name, group)
			entities = append(entities, found...)
			warnings = append(warnings, groupWarnings...)
		}
	}
	return entities, warnings
}

func groupEntities(file, event string, group tableElement) ([]ir.Entity, []adapter.Warning) {
	matcher, warnings := stringAt(file, group.key+"."+matcherKey, group.table[matcherKey])

	handlersKey := group.key + "." + hooksKey
	handlers, handlerWarnings := elementsAt(file, handlersKey, group.table[hooksKey], "an array of handlers", "a handler")
	warnings = append(warnings, handlerWarnings...)

	var entities []ir.Entity
	for _, handler := range handlers {
		hooks, hookWarnings := handlerEntities(file, handler)
		warnings = append(warnings, hookWarnings...)
		for _, h := range hooks {
			h.Event = event
			h.Matcher = matcher
			entities = append(entities, h)
		}
	}
	return entities, warnings
}

// handlerEntities emits nothing for prompt and agent handlers: Codex parses
// them and runs neither.
func handlerEntities(file string, handler tableElement) ([]ir.Hook, []adapter.Warning) {
	typeKeyPath := handler.key + "." + typeKey
	switch raw := handler.table[typeKey]; raw {
	case "command":
		return commandHooks(file, handler)
	case "mcp_tool":
		return mcpToolHooks(file, handler)
	case "prompt", "agent":
		return nil, nil
	default:
		found := formName(file, tomlconf.FormOf(raw))
		if s, ok := raw.(string); ok {
			found = strconv.Quote(s)
		}
		return nil, []adapter.Warning{{
			File: file,
			Err:  errors.New(typeKeyPath + ": expected one of command, mcp_tool, prompt or agent, found " + found),
		}}
	}
}

func commandHooks(file string, handler tableElement) ([]ir.Hook, []adapter.Warning) {
	var hooks []ir.Hook
	var warnings []adapter.Warning
	for _, name := range append([]string{commandKey}, windowsCommandKeys...) {
		key := handler.key
		if name != commandKey {
			key += "." + name
		}
		command, formWarnings := stringAt(file, handler.key+"."+name, handler.table[name])
		warnings = append(warnings, formWarnings...)
		if command != "" {
			hooks = append(hooks, ir.Hook{Command: command, Location: ir.Location{File: file, Key: key}})
		}
	}
	if len(hooks) == 0 && len(warnings) == 0 {
		warnings = append(warnings, adapter.Warning{
			File: file,
			Err:  errors.New(handler.key + ": expected a command string, found none"),
		})
	}
	return hooks, warnings
}

func mcpToolHooks(file string, handler tableElement) ([]ir.Hook, []adapter.Warning) {
	server, warnings := requiredStringAt(file, handler.key+"."+serverKey, handler.table[serverKey])
	tool, toolWarnings := requiredStringAt(file, handler.key+"."+toolKey, handler.table[toolKey])
	warnings = append(warnings, toolWarnings...)
	if len(warnings) != 0 {
		return nil, warnings
	}
	return []ir.Hook{{
		MCPServer: server,
		MCPTool:   tool,
		Location:  ir.Location{File: file, Key: handler.key},
	}}, nil
}

func requiredStringAt(file, key string, v any) (string, []adapter.Warning) {
	s, warnings := stringAt(file, key, v)
	if s != "" || len(warnings) != 0 {
		return s, warnings
	}
	found := "none"
	if v != nil {
		found = "an empty string"
	}
	return "", []adapter.Warning{{File: file, Err: errors.New(key + ": expected a non-empty string, found " + found)}}
}

type tableElement struct {
	key   string
	table map[string]any
}

func elementsAt(file, key string, v any, plural, element string) ([]tableElement, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return nil, nil
	case tomlconf.FormArray:
	default:
		return nil, []adapter.Warning{warnAt(file, key, plural, f)}
	}

	var elements []tableElement
	var warnings []adapter.Warning
	for i, raw := range v.([]any) {
		elementKey := fmt.Sprintf("%s[%d]", key, i)
		table, ok := raw.(map[string]any)
		if !ok {
			warnings = append(warnings, warnAt(file, elementKey, element, tomlconf.FormOf(raw)))
			continue
		}
		elements = append(elements, tableElement{key: elementKey, table: table})
	}
	return elements, warnings
}
