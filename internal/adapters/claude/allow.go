package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const permissionsAllowKey = "permissions.allow"

func allowEntities(p *permissions, file string) ([]ir.Entity, []adapter.Warning) {
	if p == nil {
		return nil, nil
	}

	switch f := mcpjson.FormOf(p.Allow); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormArray:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New(permissionsAllowKey + ": expected an array of permission rules, found " + mcpjson.FormName(f))}}
	}

	var rules []json.RawMessage
	_ = json.Unmarshal(p.Allow, &rules)

	var entities []ir.Entity
	var warnings []adapter.Warning
	for i, raw := range rules {
		key := fmt.Sprintf("%s[%d]", permissionsAllowKey, i)
		var rule string
		if f := mcpjson.FormOf(raw); f != mcpjson.FormString {
			warnings = append(warnings, adapter.Warning{File: file, Err: errors.New(key + ": expected a permission rule string, found " + mcpjson.FormName(f))})
			continue
		}
		_ = json.Unmarshal(raw, &rule)

		tool, argument := splitPermissionRule(rule)
		entities = append(entities, ir.ToolPermission{
			Tool:     tool,
			Argument: argument,
			Location: ir.Location{File: file, Key: key},
		})
	}
	return entities, warnings
}

func splitPermissionRule(rule string) (tool, argument string) {
	open := strings.Index(rule, "(")
	if open <= 0 || !strings.HasSuffix(rule, ")") {
		return rule, ""
	}
	return rule[:open], rule[open+1 : len(rule)-1]
}
