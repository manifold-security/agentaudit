package cursor

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// Parse reads every Cursor surface this adapter owns a parser for. A source
// that is malformed, or that the scanner refuses to open, degrades to a
// Warning so its siblings still parse.
func (Adapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	var entities []ir.Entity
	var warnings []adapter.Warning

	mcp, mcpWarnings, err := mcpEntities(fsys, mcpFileName)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, mcp...)
	warnings = append(warnings, mcpWarnings...)

	hooks, hookWarnings, err := hookEntities(fsys, hooksFileName)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, hooks...)
	warnings = append(warnings, hookWarnings...)

	hookPayloads, hookPayloadWarnings := payloadEntities(fsys, hooksPayloadDir, payloadOriginHook)
	entities = append(entities, hookPayloads...)
	warnings = append(warnings, hookPayloadWarnings...)

	worktrees, worktreeWarnings, err := worktreeEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, worktrees...)
	warnings = append(warnings, worktreeWarnings...)

	environment, environmentWarnings, err := environmentEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, environment...)
	warnings = append(warnings, environmentWarnings...)

	sandbox, sandboxWarnings, err := sandboxEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, sandbox...)
	warnings = append(warnings, sandboxWarnings...)

	cli, cliWarnings, err := cliEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, cli...)
	warnings = append(warnings, cliWarnings...)

	permissions, permissionWarnings := permissionEntities(fsys)
	entities = append(entities, permissions...)
	warnings = append(warnings, permissionWarnings...)

	skills, skillWarnings := skillEntities(fsys)
	entities = append(entities, skills...)
	warnings = append(warnings, skillWarnings...)

	subagents, subagentWarnings := projectSubagentEntities(fsys)
	entities = append(entities, subagents...)
	warnings = append(warnings, subagentWarnings...)

	plugins, pluginWarnings, err := pluginEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, plugins...)
	warnings = append(warnings, pluginWarnings...)

	return entities, warnings, nil
}
