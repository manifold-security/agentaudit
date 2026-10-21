package cursor

import (
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const worktreesFileName = ".cursor/worktrees.json"

// setupKeys are the documented worktree setup keys.
//
// Cursor picks one of them by host platform, and this reads all of them: a
// repository can commit a payload for a platform the scanning host will never
// run, and reporting only the key that matches the host would leave the
// others unseen.
var setupKeys = []string{
	"setup-worktree-unix",
	"setup-worktree-windows",
	"setup-worktree",
}

// worktreeEntities reads the commands Cursor runs to prepare a newly created
// worktree, degrading per key and per command.
func worktreeEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, worktreesFileName)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	var entities []ir.Entity
	for _, key := range setupKeys {
		keyEntities, keyWarnings := entitiesFromSetupKey(key, doc[key])
		entities = append(entities, keyEntities...)
		warnings = append(warnings, keyWarnings...)
	}
	entities, warnings = limits.Of(fsys).Admit(worktreesFileName, entities, warnings)
	return entities, warnings, nil
}

// entitiesFromSetupKey reads a key declaring shell commands or a script
// path. The path stays at the bare key while a sequence indexes its elements,
// so the provenance tells a reader which of the two forms declared the value.
func entitiesFromSetupKey(key string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormString:
		return []ir.Entity{provisioner(key, stringValue(raw), key)}, nil
	case mcpjson.FormArray:
		return entitiesFromCommandSequence(key, raw)
	default:
		return nil, []adapter.Warning{{File: worktreesFileName, Err: errors.New(key + ": expected an array of commands or a script path, found " + mcpjson.FormName(f))}}
	}
}

func entitiesFromCommandSequence(key string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	commands, warnings := listElements(worktreesFileName, key, raw, "a shell command string")

	var entities []ir.Entity
	for _, c := range commands {
		entities = append(entities, provisioner(key, c.value, c.key))
	}
	return entities, warnings
}

func provisioner(phase, command, key string) ir.Entity {
	return ir.Provisioner{
		Phase:    phase,
		Command:  command,
		Location: ir.Location{File: worktreesFileName, Key: key},
	}
}
