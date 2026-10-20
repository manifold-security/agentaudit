package cursor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const sandboxFileName = ".cursor/sandbox.json"

const (
	sandboxTypeKey   = "type"
	networkPolicyKey = "networkPolicy"
	egressDefaultKey = "default"
	egressAllowKey   = "allow"
)

const (
	accessReadwrite = "readwrite"
	accessReadonly  = "readonly"

	// modeSandboxOff is the sandbox type that grants rather than confines.
	modeSandboxOff = "insecure_none"

	// egressAllowed opens the network to whatever no pattern matched.
	// Cursor's own fallback is the denial, so this value is a widening.
	egressAllowed = "allow"
)

// pathGrant is one documented key opening paths outside the workspace,
// paired with the access those paths are opened under.
type pathGrant struct {
	key    string
	access string
}

var pathGrants = []pathGrant{
	{"additionalReadwritePaths", accessReadwrite},
	{"additionalReadonlyPaths", accessReadonly},
}

// sandboxEntities reads the grants Cursor's sandbox configuration makes,
// degrading per key and per entry.
//
// The keys that narrow what the agent may reach are read by nothing here.
func sandboxEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, sandboxFileName)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	entities, modeWarnings := entitiesFromSandboxType(doc[sandboxTypeKey])
	warnings = append(warnings, modeWarnings...)

	for _, grant := range pathGrants {
		grantEntities, grantWarnings := entitiesFromPathGrant(grant, doc[grant.key])
		entities = append(entities, grantEntities...)
		warnings = append(warnings, grantWarnings...)
	}

	policy, policyWarnings := entitiesFromNetworkPolicy(doc[networkPolicyKey])
	entities = append(entities, policy...)
	warnings = append(warnings, policyWarnings...)

	entities, warnings = limits.Of(fsys).Admit(sandboxFileName, entities, warnings)
	return entities, warnings, nil
}

func entitiesFromSandboxType(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormString:
	default:
		return nil, []adapter.Warning{{File: sandboxFileName, Err: errors.New(sandboxTypeKey + ": expected a string, found " + mcpjson.FormName(f))}}
	}

	mode := stringValue(raw)
	if mode != modeSandboxOff {
		return nil, nil
	}
	return []ir.Entity{ir.Sandbox{
		Mode:     mode,
		Location: ir.Location{File: sandboxFileName, Key: sandboxTypeKey},
	}}, nil
}

// entitiesFromPathGrant fans out one entity per listed path, so a report
// names each granted location on a line of its own.
func entitiesFromPathGrant(grant pathGrant, raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	paths, warnings := stringList(sandboxFileName, grant.key, raw, "paths", "a path string")

	var entities []ir.Entity
	for _, p := range paths {
		entities = append(entities, ir.Sandbox{
			Path:     p.value,
			Access:   grant.access,
			Location: ir.Location{File: sandboxFileName, Key: p.key},
		})
	}
	return entities, warnings
}

func entitiesFromNetworkPolicy(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormObject:
	default:
		return nil, []adapter.Warning{{File: sandboxFileName, Err: errors.New(networkPolicyKey + ": expected an object, found " + mcpjson.FormName(f))}}
	}

	var policy map[string]json.RawMessage
	if err := json.Unmarshal(raw, &policy); err != nil {
		return nil, []adapter.Warning{{File: sandboxFileName, Err: fmt.Errorf("%s: %w", networkPolicyKey, err)}}
	}

	entities, warnings := entitiesFromEgressDefault(policy[egressDefaultKey])
	allowed, allowWarnings := entitiesFromAllowList(policy[egressAllowKey])
	return append(entities, allowed...), append(warnings, allowWarnings...)
}

func entitiesFromEgressDefault(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	key := networkPolicyKey + "." + egressDefaultKey

	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormString:
	default:
		return nil, []adapter.Warning{{File: sandboxFileName, Err: errors.New(key + ": expected a string, found " + mcpjson.FormName(f))}}
	}

	action := stringValue(raw)
	if action != egressAllowed {
		return nil, nil
	}
	return []ir.Entity{ir.NetworkPolicy{
		Default:  action,
		Location: ir.Location{File: sandboxFileName, Key: key},
	}}, nil
}

// entitiesFromAllowList fans out one entity per pattern. Deny beats allow in
// Cursor's own matching, which is what makes the sibling deny list a
// restriction.
func entitiesFromAllowList(raw json.RawMessage) ([]ir.Entity, []adapter.Warning) {
	patterns, warnings := stringList(sandboxFileName, networkPolicyKey+"."+egressAllowKey, raw, "patterns", "a pattern string")

	var entities []ir.Entity
	for _, p := range patterns {
		entities = append(entities, ir.NetworkPolicy{
			Pattern:  p.value,
			Location: ir.Location{File: sandboxFileName, Key: p.key},
		})
	}
	return entities, warnings
}
