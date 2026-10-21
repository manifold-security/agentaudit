package codex

import (
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

func warnAt(file, key, wanted string, found tomlconf.Form) adapter.Warning {
	return adapter.Warning{
		File: file,
		Err:  errors.New(key + ": expected " + wanted + ", found " + formName(file, found)),
	}
}

func formName(file string, f tomlconf.Form) string {
	if f == tomlconf.FormTable && path.Ext(file) == ".json" {
		return "an object"
	}
	return tomlconf.FormName(f)
}

func stringAt(file, key string, v any) (string, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return "", nil
	case tomlconf.FormString:
		return v.(string), nil
	default:
		return "", []adapter.Warning{warnAt(file, key, "a string", f)}
	}
}

func boolAt(file, key string, v any) (value, present bool, warnings []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return false, false, nil
	case tomlconf.FormBool:
		return v.(bool), true, nil
	default:
		return false, false, []adapter.Warning{warnAt(file, key, "a boolean", f)}
	}
}

func tableAt(file, key string, v any) (map[string]any, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return nil, nil
	case tomlconf.FormTable:
		return v.(map[string]any), nil
	default:
		return nil, []adapter.Warning{warnAt(file, key, formName(file, tomlconf.FormTable), f)}
	}
}

type tableEntry struct {
	key   string
	name  string
	value any
}

// tableEntries walks table in a fixed order, so the entities and warnings a
// document yields do not vary with the decoder's map iteration.
func tableEntries(key string, table map[string]any) []tableEntry {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]tableEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, tableEntry{
			key:   key + "." + name,
			name:  name,
			value: table[name],
		})
	}
	return entries
}

type listElement struct {
	key   string
	value string
}

func stringListAt(file, key string, v any, plural, element string) ([]listElement, []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return nil, nil
	case tomlconf.FormArray:
	default:
		return nil, []adapter.Warning{warnAt(file, key, "an array of "+plural, f)}
	}

	var elements []listElement
	var warnings []adapter.Warning
	for i, raw := range v.([]any) {
		elementKey := fmt.Sprintf("%s[%d]", key, i)
		f := tomlconf.FormOf(raw)
		if f != tomlconf.FormString {
			warnings = append(warnings, warnAt(file, elementKey, element, f))
			continue
		}
		elements = append(elements, listElement{key: elementKey, value: raw.(string)})
	}
	return elements, warnings
}
