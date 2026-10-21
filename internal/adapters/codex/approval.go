package codex

import (
	"errors"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

const (
	approvalPolicyKey = "approval_policy"
	granularKey       = "granular"
)

// approvalEntities reads a policy Codex spells either as one token or as a
// table of per-category toggles. The two forms declare different things: the
// table replaces the blanket prompt rather than setting it.
func approvalEntities(doc map[string]any) ([]ir.Entity, []adapter.Warning) {
	raw, declared := doc[approvalPolicyKey]
	if !declared {
		return nil, nil
	}

	if mode, ok := raw.(string); ok {
		return []ir.Entity{ir.PermissionMode{
			Mode:     mode,
			Source:   approvalPolicyKey,
			Location: ir.Location{File: configFileName, Key: approvalPolicyKey},
		}}, nil
	}

	table, ok := raw.(map[string]any)
	if !ok {
		return nil, []adapter.Warning{warnAt(configFileName, approvalPolicyKey, "a string or a table", tomlconf.FormOf(raw))}
	}
	if _, ok := table[granularKey]; !ok {
		return nil, []adapter.Warning{{
			File: configFileName,
			Err:  errors.New(approvalPolicyKey + ": expected a table declaring " + granularKey + ", found none"),
		}}
	}
	return []ir.Entity{ir.PermissionMode{
		Mode:     granularKey,
		Source:   approvalPolicyKey,
		Location: ir.Location{File: configFileName, Key: approvalPolicyKey + "." + granularKey},
	}}, nil
}
