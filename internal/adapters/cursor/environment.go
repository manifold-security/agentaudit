package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const environmentFileName = ".cursor/environment.json"

const (
	terminalsKey = "terminals"
	buildKey     = "build"
)

var commandKeys = []string{"install", "start"}

// buildKeys are the documented ways a build names its Dockerfile. Each names
// code that runs before the agent does.
var buildKeys = []string{"dockerfile", "dockerfileContents"}

// terminalEntry is one terminals entry. Its description is prose shown to the
// agent, which ir.Provisioner has no field for.
type terminalEntry struct {
	Name    string `json:"name"`
	Command string `json:"command"`
}

// environmentEntities reads the commands Cursor runs to build and boot a
// background agent's environment, degrading per key and per entry.
func environmentEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, environmentFileName)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	var entities []ir.Entity
	for _, key := range commandKeys {
		keyEntities, keyWarnings := entitiesFromStringKey(key, doc[key])
		entities = append(entities, keyEntities...)
		warnings = append(warnings, keyWarnings...)
	}

	terminals, terminalWarnings := entitiesFromTerminals(doc[terminalsKey])
	entities = append(entities, terminals...)
	warnings = append(warnings, terminalWarnings...)

	build, buildWarnings := entitiesFromBuild(doc[buildKey])
	entities = append(entities, build...)
	warnings = append(warnings, buildWarnings...)

	return entities, warnings, nil
}

func entitiesFromStringKey(key string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormString:
		return []ir.Entity{environmentProvisioner(key, "", stringValue(raw), key)}, nil
	default:
		return nil, []adapter.Warning{{File: environmentFileName, Err: errors.New(key + ": expected a string, found " + mcpjson.FormName(f))}}
	}
}

// entitiesFromTerminals reads the entries Cursor runs alongside the agent.
// One entry may stand in for the array, so both forms resolve to the same
// phase and the provenance says which one declared the entry.
func entitiesFromTerminals(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
		return entitiesFromTerminal(terminalsKey, raw)
	case mcpjson.FormArray:
		return entitiesFromTerminalArray(raw)
	default:
		return nil, []adapter.Warning{{File: environmentFileName, Err: errors.New(terminalsKey + ": expected an array of entries or one entry, found " + mcpjson.FormName(f))}}
	}
}

func entitiesFromTerminalArray(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, []adapter.Warning{{File: environmentFileName, Err: fmt.Errorf("%s: %w", terminalsKey, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for i, rawEntry := range rawEntries {
		entryEntities, entryWarnings := entitiesFromTerminal(fmt.Sprintf("%s[%d]", terminalsKey, i), rawEntry)
		entities = append(entities, entryEntities...)
		warnings = append(warnings, entryWarnings...)
	}
	return entities, warnings
}

func entitiesFromTerminal(entryKey string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	if f := mcpjson.FormOf(raw); f != mcpjson.FormObject {
		return nil, []adapter.Warning{{File: environmentFileName, Err: errors.New(entryKey + ": expected an object, found " + mcpjson.FormName(f))}}
	}

	var entry terminalEntry
	if err := decodeEntry(entryKey, raw, &entry); err != nil {
		return nil, []adapter.Warning{{File: environmentFileName, Err: err}}
	}
	return []ir.Entity{environmentProvisioner(terminalsKey, entry.Name, entry.Command, entryKey+"."+commandField)}, nil
}

func entitiesFromBuild(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: environmentFileName, Err: errors.New(buildKey + ": expected an object, found " + mcpjson.FormName(f))}}
	}

	var build map[string]json.RawMessage
	if err := json.Unmarshal(raw, &build); err != nil {
		return nil, []adapter.Warning{{File: environmentFileName, Err: fmt.Errorf("%s: %w", buildKey, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, key := range buildKeys {
		keyEntities, keyWarnings := entitiesFromStringKey(buildKey+"."+key, build[key])
		entities = append(entities, keyEntities...)
		warnings = append(warnings, keyWarnings...)
	}
	return entities, warnings
}

func environmentProvisioner(phase, name, command, key string) ir.Entity {
	return ir.Provisioner{
		Phase:    phase,
		Name:     name,
		Command:  command,
		Location: ir.Location{File: environmentFileName, Key: key},
	}
}
