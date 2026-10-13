package codex

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/tomlconf"
)

// Parse reads the locations Signatures declares. A malformed key degrades to
// a Warning so its siblings still reach the report; a document the decoder
// stopped on degrades whole, named by its file, and leaves the other sources'
// entities in the report.
func (Adapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	entities, warnings := configEntities(fsys)

	hooks, hookWarnings := hooksFileEntities(fsys)
	entities = append(entities, hooks...)
	warnings = append(warnings, hookWarnings...)

	skills, skillWarnings := skillEntities(fsys)
	entities = append(entities, skills...)
	warnings = append(warnings, skillWarnings...)

	return entities, warnings, nil
}

func configEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	doc, warnings := tomlconf.Document(fsys, configFileName)
	if len(warnings) != 0 {
		return nil, warnings
	}

	entities, sandboxWarnings := sandboxEntities(doc)
	warnings = append(warnings, sandboxWarnings...)

	approvals, approvalWarnings := approvalEntities(doc)
	entities = append(entities, approvals...)
	warnings = append(warnings, approvalWarnings...)

	permissions, permissionWarnings := permissionEntities(doc)
	entities = append(entities, permissions...)
	warnings = append(warnings, permissionWarnings...)

	network, networkWarnings := networkEntities(doc)
	entities = append(entities, network...)
	warnings = append(warnings, networkWarnings...)

	servers, serverWarnings := mcpEntities(doc)
	entities = append(entities, servers...)
	warnings = append(warnings, serverWarnings...)

	hooks, hookWarnings := hookEntities(configFileName, doc[hooksKey], tomlHooksSettings)
	entities = append(entities, hooks...)
	warnings = append(warnings, hookWarnings...)

	return entities, warnings
}
