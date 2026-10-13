package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const cliFileName = ".cursor/cli.json"

const (
	permissionsKey     = "permissions"
	permissionAllowKey = "allow"
	permissionDenyKey  = "deny"
)

// cliEntities reads the permissions Cursor's project CLI configuration grants,
// degrading per key and per entry.
//
// Cursor resolves a deny entry that repeats an allow entry's tool and
// argument as a denial, so that pair grants nothing and surfaces as nothing.
// A deny entry is never a capability of its own.
func cliEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, cliFileName)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	entities, permissionWarnings := entitiesFromPermissions(cliFileName, doc[permissionsKey])
	return entities, permissionWarnings, nil
}

func entitiesFromPermissions(file string, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New(permissionsKey + ": expected an object, found " + mcpjson.FormName(f))}}
	}

	var permissions map[string]json.RawMessage
	if err := json.Unmarshal(raw, &permissions); err != nil {
		return nil, []adapter.Warning{{File: file, Err: fmt.Errorf("%s: %w", permissionsKey, err)}}
	}
	return entitiesFromPermissionLists(file, permissions[permissionAllowKey], permissions[permissionDenyKey])
}

func entitiesFromPermissionLists(file string, allow, deny json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	key := permissionsKey + "." + permissionAllowKey
	entries, warnings := stringList(file, key, allow, "permissions", "a permission string")
	withheld, denyWarnings := deniedPermissions(file, deny)

	var entities []ir.Entity
	for _, e := range entries {
		tool, argument := splitPermission(e.value)
		if _, denied := withheld[permissionPair{tool: tool, argument: argument}]; denied {
			continue
		}
		entities = append(entities, ir.ToolPermission{
			Tool:     tool,
			Argument: argument,
			Location: ir.Location{File: file, Key: e.key},
		})
	}
	return entities, append(warnings, denyWarnings...)
}

type permissionPair struct {
	tool     string
	argument string
}

func deniedPermissions(file string, raw json.RawMessage) (map[permissionPair]struct{}, []adapter.Warning) {
	key := permissionsKey + "." + permissionDenyKey
	entries, warnings := stringList(file, key, raw, "permissions", "a permission string")

	withheld := make(map[permissionPair]struct{}, len(entries))
	for _, e := range entries {
		tool, argument := splitPermission(e.value)
		withheld[permissionPair{tool: tool, argument: argument}] = struct{}{}
	}
	return withheld, warnings
}

// splitPermission separates the tool a typed entry names from the argument
// scoping it. An entry that names no tool, or spells no argument, surfaces
// whole as the tool: dropping one the decomposition cannot read would hide a
// grant.
func splitPermission(entry string) (tool, argument string) {
	open := strings.Index(entry, "(")
	if open <= 0 || !strings.HasSuffix(entry, ")") {
		return entry, ""
	}
	return entry[:open], entry[open+1 : len(entry)-1]
}
