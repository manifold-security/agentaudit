package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const permissionsFileName = ".cursor/permissions.json"

const (
	terminalAllowlistKey = "terminalAllowlist"
	mcpAllowlistKey      = "mcpAllowlist"
	autoRunKey           = "autoRun"
	autoReviewKey        = "autoReview"
)

// allowlist is one key of permissions.json paired with what Cursor
// rewrites that key's entries into.
type allowlist struct {
	// key is the top-level name carrying the array.
	key string
	// tool is the permission type an entry of key becomes.
	tool string
	// plural names what the array holds; element names one of them.
	plural  string
	element string
}

var allowlists = []allowlist{
	{key: terminalAllowlistKey, tool: "Shell", plural: "commands", element: "a command"},
	{key: mcpAllowlistKey, tool: "Mcp", plural: "entries", element: "a server:tool entry"},
}

// instructionSettings are read by exact name: Cursor reaches them as
// properties of the auto-run block rather than through the case-insensitive
// lookup its top-level names get.
var instructionSettings = []string{"allow_instructions", "block_instructions"}

// permissionEntities reads the allowlists and the auto-run prose Cursor
// keeps in permissions.json, degrading per key and per entry.
//
// The file carries no deny channel: the provider Cursor reads it through is
// constructed with an empty one.
func permissionEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	doc, warnings := jsoncObjectDocument(fsys, permissionsFileName)
	if len(warnings) != 0 {
		return nil, warnings
	}

	var entities []ir.Entity
	for _, list := range allowlists {
		for _, key := range foldedKeys(doc, list.key) {
			listEntities, listWarnings := entitiesFromAllowlist(key, doc[key], list)
			entities = append(entities, listEntities...)
			warnings = append(warnings, listWarnings...)
		}
	}

	for _, key := range autoRunKeys(doc) {
		blockEntities, blockWarnings := entitiesFromAutoRun(key, doc[key])
		entities = append(entities, blockEntities...)
		warnings = append(warnings, blockWarnings...)
	}
	return entities, warnings
}

// foldedKeys returns doc's top-level names equal to name under Cursor's
// case-insensitive lookup. The order is fixed: map iteration would otherwise
// place two spellings of one name differently from run to run.
func foldedKeys(doc map[string]json.RawMessage, name string) []string {
	var keys []string
	for key := range doc {
		if strings.EqualFold(key, name) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// autoRunKeys returns the block Cursor resolves the auto-run prose from.
// autoReview is an alias it tries first, so a document carrying both is
// read through autoReview alone.
func autoRunKeys(doc map[string]json.RawMessage) []string {
	if keys := foldedKeys(doc, autoReviewKey); len(keys) != 0 {
		return keys
	}
	return foldedKeys(doc, autoRunKey)
}

func entitiesFromAllowlist(key string, raw json.RawMessage, list allowlist) ([]ir.Entity, []adapter.Warning) {
	elements, warnings := stringList(permissionsFileName, key, raw, list.plural, list.element)

	var entities []ir.Entity
	for _, e := range elements {
		entities = append(entities, ir.ToolPermission{
			Tool:     list.tool,
			Argument: e.value,
			Location: ir.Location{File: permissionsFileName, Key: e.key},
		})
	}
	return entities, warnings
}

func entitiesFromAutoRun(key string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: permissionsFileName, Err: errors.New(key + ": expected an object, found " + mcpjson.FormName(f))}}
	}

	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, []adapter.Warning{{File: permissionsFileName, Err: fmt.Errorf("%s: %w", key, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, setting := range instructionSettings {
		elements, listWarnings := stringList(permissionsFileName, key+"."+setting, block[setting], "instructions", "an instruction")
		warnings = append(warnings, listWarnings...)
		for _, e := range elements {
			entities = append(entities, ir.InstructionText{
				Setting:  setting,
				Text:     e.value,
				Location: ir.Location{File: permissionsFileName, Key: e.key},
			})
		}
	}
	return entities, warnings
}
