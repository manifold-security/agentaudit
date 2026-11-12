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

const (
	permissionsAllowKey = "permissions.allow"
	permissionsDenyKey  = "permissions.deny"
	permissionsAskKey   = "permissions.ask"
)

func allowEntities(p *permissions, file string) ([]ir.Entity, []adapter.Warning) {
	if p == nil {
		return nil, nil
	}

	allowed, warnings := ruleStrings(p.Allow, permissionsAllowKey, file)
	denied, deniedWarnings := ruleStrings(p.Deny, permissionsDenyKey, file)
	asked, askedWarnings := ruleStrings(p.Ask, permissionsAskKey, file)
	warnings = append(warnings, deniedWarnings...)
	warnings = append(warnings, askedWarnings...)

	denyAsk := map[string]bool{}
	for _, item := range append(denied, asked...) {
		denyAsk[item.rule] = true
	}

	var entities []ir.Entity
	for _, item := range allowed {
		if coveredByDenyOrAsk(item.rule, denyAsk) {
			continue
		}

		tool, argument := splitPermissionRule(item.rule)
		if argument == "*" {
			argument = ""
		}
		entities = append(entities, ir.ToolPermission{
			Tool:     tool,
			Argument: argument,
			Location: ir.Location{File: file, Key: fmt.Sprintf("%s[%d]", permissionsAllowKey, item.index)},
		})
	}
	return entities, warnings
}

type ruleItem struct {
	index int
	rule  string
}

func ruleStrings(list json.RawMessage, key, file string) ([]ruleItem, []adapter.Warning) {
	switch f := mcpjson.FormOf(list); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormArray:
	default:
		return nil, []adapter.Warning{{File: file, Err: errors.New(key + ": expected an array of permission rules, found " + mcpjson.FormName(f))}}
	}

	var elements []json.RawMessage
	_ = json.Unmarshal(list, &elements)

	var items []ruleItem
	var warnings []adapter.Warning
	for i, raw := range elements {
		if f := mcpjson.FormOf(raw); f != mcpjson.FormString {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s[%d]: expected a permission rule string, found %s", key, i, mcpjson.FormName(f))})
			continue
		}
		var rule string
		_ = json.Unmarshal(raw, &rule)
		items = append(items, ruleItem{index: i, rule: rule})
	}
	return items, warnings
}

func splitPermissionRule(rule string) (tool, argument string) {
	open := strings.Index(rule, "(")
	if open <= 0 || !strings.HasSuffix(rule, ")") {
		return rule, ""
	}
	return rule[:open], rule[open+1 : len(rule)-1]
}

func coveredByDenyOrAsk(rule string, denyAsk map[string]bool) bool {
	tool, _ := splitPermissionRule(rule)
	return denyAsk[tool] || denyAsk[tool+"(*)"] || denyAsk[rule]
}
