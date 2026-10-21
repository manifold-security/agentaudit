package codex

import (
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const (
	sandboxModeKey    = "sandbox_mode"
	workspaceWriteKey = "sandbox_workspace_write"
	writableRootsKey  = "writable_roots"
	networkAccessKey  = "network_access"
)

// sandboxModes are the confinement levels Codex documents.
// permissionEntities reads this set rather than the presence of the key.
var sandboxModes = []string{"read-only", "workspace-write", "danger-full-access"}

const accessReadwrite = "readwrite"

// networkGranted is the value network_access carries where it opens the
// sandbox to outbound traffic, spelled as the document spells it.
const networkGranted = "true"

// sandboxEntities reads no exclusion key: exclude_tmpdir_env_var and
// exclude_slash_tmp each remove a location from the writable set, and a
// restriction is not a capability.
func sandboxEntities(doc map[string]any) ([]ir.Entity, []adapter.Warning) {
	entities, warnings := entitiesFromSandboxMode(doc[sandboxModeKey])

	workspace, tableWarnings := tableAt(configFileName, workspaceWriteKey, doc[workspaceWriteKey])
	warnings = append(warnings, tableWarnings...)

	roots, rootWarnings := entitiesFromWritableRoots(workspace[writableRootsKey])
	entities = append(entities, roots...)
	warnings = append(warnings, rootWarnings...)

	network, networkWarnings := entitiesFromNetworkAccess(workspace[networkAccessKey])
	entities = append(entities, network...)
	warnings = append(warnings, networkWarnings...)

	return entities, warnings
}

func entitiesFromSandboxMode(v any) ([]ir.Entity, []adapter.Warning) {
	mode, warnings := stringAt(configFileName, sandboxModeKey, v)
	if mode == "" {
		return nil, warnings
	}
	return []ir.Entity{ir.Sandbox{
		Mode:     mode,
		Location: ir.Location{File: configFileName, Key: sandboxModeKey},
	}}, warnings
}

func entitiesFromWritableRoots(v any) ([]ir.Entity, []adapter.Warning) {
	key := workspaceWriteKey + "." + writableRootsKey
	roots, warnings := stringListAt(configFileName, key, v, "paths", "a path string")

	var entities []ir.Entity
	for _, root := range roots {
		entities = append(entities, ir.Sandbox{
			Path:     root.value,
			Access:   accessReadwrite,
			Location: ir.Location{File: configFileName, Key: root.key},
		})
	}
	return entities, warnings
}

func entitiesFromNetworkAccess(v any) ([]ir.Entity, []adapter.Warning) {
	key := workspaceWriteKey + "." + networkAccessKey
	granted, present, warnings := boolAt(configFileName, key, v)
	if !present || !granted {
		return nil, warnings
	}
	return []ir.Entity{ir.NetworkPolicy{
		Default:  networkGranted,
		Location: ir.Location{File: configFileName, Key: key},
	}}, warnings
}
