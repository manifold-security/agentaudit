package codex

import (
	"slices"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

const (
	defaultPermissionsKey = "default_permissions"
	permissionsKey        = "permissions"
	extendsKey            = "extends"
	workspaceRootsKey     = "workspace_roots"
	filesystemKey         = "filesystem"
	networkKey            = "network"
	enabledKey            = "enabled"
	domainsKey            = "domains"
	unixSocketsKey        = "unix_sockets"
	globScanDepthKey      = "glob_scan_max_depth"
)

const baselineScope = ":minimal"

// workspaceRootsScope is the filesystem key whose value is a table of grants
// rather than a grant of its own.
const workspaceRootsScope = ":workspace_roots"

const (
	accessWorkspaceRoot = "workspace_root"
	allowVerdict        = "allow"
	denyVerdict         = "deny"
)

// egressGranted is what a profile's egress policy carries: the network table
// grants by key rather than by a value naming a fallback action.
const egressGranted = enabledKey

// permissionEntities reports the grants a profile declares. A top-level
// sandbox_mode naming one of the modes Codex documents withholds every one
// of them, the default_permissions selection included: absent a managed
// profile allowlist, Codex applies the older sandbox settings and leaves the
// profile unapplied, so a grant written there alone declares no capability.
// The traversal below still runs, because a key that did not decode is a
// fact about the scan rather than about the posture Codex ends up with.
func permissionEntities(doc map[string]any) ([]ir.Entity, []adapter.Warning) {
	entities, warnings := entitiesFromDefaultPermissions(doc[defaultPermissionsKey])

	profiles, tableWarnings := tableAt(configFileName, permissionsKey, doc[permissionsKey])
	warnings = append(warnings, tableWarnings...)

	for _, profile := range tableEntries(permissionsKey, profiles) {
		table, formWarnings := tableAt(configFileName, profile.key, profile.value)
		warnings = append(warnings, formWarnings...)

		grants, grantWarnings := profileEntities(profile.key, table)
		entities = append(entities, grants...)
		warnings = append(warnings, grantWarnings...)
	}

	mode, _ := doc[sandboxModeKey].(string)
	if slices.Contains(sandboxModes, mode) {
		return nil, warnings
	}
	return entities, warnings
}

func entitiesFromDefaultPermissions(v any) ([]ir.Entity, []adapter.Warning) {
	profile, warnings := stringAt(configFileName, defaultPermissionsKey, v)
	if profile == "" {
		return nil, warnings
	}
	return []ir.Entity{ir.PermissionMode{
		Mode:     profile,
		Source:   defaultPermissionsKey,
		Location: ir.Location{File: configFileName, Key: defaultPermissionsKey},
	}}, warnings
}

func profileEntities(key string, profile map[string]any) ([]ir.Entity, []adapter.Warning) {
	entities, warnings := entitiesFromExtends(key+"."+extendsKey, profile[extendsKey])

	roots, rootWarnings := tableAt(configFileName, key+"."+workspaceRootsKey, profile[workspaceRootsKey])
	warnings = append(warnings, rootWarnings...)
	rootEntities, rootGrantWarnings := entitiesFromWorkspaceRoots(key+"."+workspaceRootsKey, roots)
	entities = append(entities, rootEntities...)
	warnings = append(warnings, rootGrantWarnings...)

	filesystem, filesystemWarnings := tableAt(configFileName, key+"."+filesystemKey, profile[filesystemKey])
	warnings = append(warnings, filesystemWarnings...)
	filesystemEntities, filesystemGrantWarnings := entitiesFromFilesystem(key+"."+filesystemKey, filesystem)
	entities = append(entities, filesystemEntities...)
	warnings = append(warnings, filesystemGrantWarnings...)

	network, networkWarnings := tableAt(configFileName, key+"."+networkKey, profile[networkKey])
	warnings = append(warnings, networkWarnings...)
	networkEntities, networkGrantWarnings := entitiesFromProfileNetwork(key+"."+networkKey, network)
	entities = append(entities, networkEntities...)
	warnings = append(warnings, networkGrantWarnings...)

	return entities, warnings
}

func entitiesFromExtends(key string, v any) ([]ir.Entity, []adapter.Warning) {
	base, warnings := stringAt(configFileName, key, v)
	if base == "" {
		return nil, warnings
	}
	return []ir.Entity{ir.PermissionMode{
		Mode:     base,
		Source:   extendsKey,
		Location: ir.Location{File: configFileName, Key: key},
	}}, warnings
}

func entitiesFromWorkspaceRoots(key string, roots map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, root := range tableEntries(key, roots) {
		granted, present, formWarnings := boolAt(configFileName, root.key, root.value)
		warnings = append(warnings, formWarnings...)
		if !present || !granted {
			continue
		}
		entities = append(entities, ir.Sandbox{
			Path:     root.name,
			Access:   accessWorkspaceRoot,
			Location: ir.Location{File: configFileName, Key: root.key},
		})
	}
	return entities, warnings
}

// entitiesFromFilesystem reads no denial and no scan bound: neither widens
// what the profile reaches.
func entitiesFromFilesystem(key string, filesystem map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, entry := range tableEntries(key, filesystem) {
		if entry.name == globScanDepthKey || entry.name == baselineScope {
			continue
		}
		if entry.name == workspaceRootsScope {
			scoped, formWarnings := tableAt(configFileName, entry.key, entry.value)
			warnings = append(warnings, formWarnings...)
			scopedEntities, scopedWarnings := entitiesFromFilesystem(entry.key, scoped)
			entities = append(entities, scopedEntities...)
			warnings = append(warnings, scopedWarnings...)
			continue
		}

		level, formWarnings := stringAt(configFileName, entry.key, entry.value)
		warnings = append(warnings, formWarnings...)
		if level == "" || level == denyVerdict {
			continue
		}
		entities = append(entities, ir.Sandbox{
			Path:     entry.name,
			Access:   level,
			Location: ir.Location{File: configFileName, Key: entry.key},
		})
	}
	return entities, warnings
}

func entitiesFromProfileNetwork(key string, network map[string]any) ([]ir.Entity, []adapter.Warning) {
	granted, present, warnings := boolAt(configFileName, key+"."+enabledKey, network[enabledKey])

	var entities []ir.Entity
	if present && granted {
		entities = append(entities, ir.NetworkPolicy{
			Default:  egressGranted,
			Location: ir.Location{File: configFileName, Key: key + "." + enabledKey},
		})
	}

	domains, domainWarnings := tableAt(configFileName, key+"."+domainsKey, network[domainsKey])
	warnings = append(warnings, domainWarnings...)
	domainEntities, domainVerdictWarnings := entitiesFromDomains(key+"."+domainsKey, domains)
	entities = append(entities, domainEntities...)
	warnings = append(warnings, domainVerdictWarnings...)

	sockets, socketWarnings := tableAt(configFileName, key+"."+unixSocketsKey, network[unixSocketsKey])
	warnings = append(warnings, socketWarnings...)
	socketEntities, socketVerdictWarnings := entitiesFromUnixSockets(key+"."+unixSocketsKey, sockets)
	entities = append(entities, socketEntities...)
	warnings = append(warnings, socketVerdictWarnings...)

	guards, guardWarnings := entitiesFromNetworkGuards(key, network)
	entities = append(entities, guards...)
	warnings = append(warnings, guardWarnings...)

	return entities, warnings
}

// entitiesFromDomains keeps the allowed patterns alone: ir.NetworkPolicy
// carries a pattern with no verdict beside it, so a denied host reaching a
// finding would read as a reachable one.
func entitiesFromDomains(key string, domains map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, domain := range tableEntries(key, domains) {
		verdict, formWarnings := stringAt(configFileName, domain.key, domain.value)
		warnings = append(warnings, formWarnings...)
		if verdict != allowVerdict {
			continue
		}
		entities = append(entities, ir.NetworkPolicy{
			Pattern:  domain.name,
			Location: ir.Location{File: configFileName, Key: domain.key},
		})
	}
	return entities, warnings
}

// entitiesFromUnixSockets keeps the admitted sockets alone, for the reason
// entitiesFromDomains gives: ir.Sandbox carries the socket path with no
// verdict beside it.
func entitiesFromUnixSockets(key string, sockets map[string]any) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, socket := range tableEntries(key, sockets) {
		admitted, present, formWarnings := admissionAt(socket.key, socket.value)
		warnings = append(warnings, formWarnings...)
		if !present || !admitted {
			continue
		}
		entities = append(entities, ir.Sandbox{
			SocketPath: socket.name,
			Location:   ir.Location{File: configFileName, Key: socket.key},
		})
	}
	return entities, warnings
}

func admissionAt(key string, v any) (admitted, present bool, warnings []adapter.Warning) {
	switch f := tomlconf.FormOf(v); f {
	case tomlconf.FormAbsent:
		return false, false, nil
	case tomlconf.FormString:
		return v.(string) == allowVerdict, true, nil
	default:
		return false, false, []adapter.Warning{warnAt(configFileName, key, "a string", f)}
	}
}
