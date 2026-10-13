package cursor

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// cliGlobalFileName is the CLI configuration Cursor keeps under a home
// basename of its own, distinct from the project file's.
const cliGlobalFileName = ".cursor/cli-config.json"

// ParseGlobal reads the permissions key of cliGlobalFileName and nothing
// else, which TestParseGlobalUnreadKeysStayOut enforces.
func (Adapter) ParseGlobal(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	doc, warnings := objectDocument(fsys, cliGlobalFileName)
	if len(warnings) != 0 {
		return nil, warnings, nil
	}

	entities, permissionWarnings := entitiesFromPermissions(cliGlobalFileName, doc[permissionsKey])
	return entities, permissionWarnings, nil
}
