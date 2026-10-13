package cursor

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// agentPluginSchemaPrefix opens the $schema of an Agent Plugins manifest,
// leaving the specification version free: pinning the identifier one version
// publishes would drop a manifest written against the next one.
const agentPluginSchemaPrefix = "https://agent-plugins.org/"

const pluginSchemaKey = "$schema"

// agentPluginEntities reads the skills and MCP servers an Agent Plugins
// manifest activates. A hooks file or an agents directory beside them
// belongs to no loader this format defines, so a finding drawn from one
// would name a capability that cannot fire.
func agentPluginEntities(fsys fs.FS, file string) ([]ir.Entity, []adapter.Warning) {
	warnings, claimed := agentPluginManifest(fsys, file)
	if !claimed {
		return nil, warnings
	}

	layout := defaultPluginLayout(path.Dir(file))
	entities, mcpWarnings := pluginMCPEntities(fsys, layout)
	warnings = append(warnings, mcpWarnings...)

	skills, skillWarnings := pluginSkillEntities(fsys, layout)
	entities = append(entities, skills...)
	warnings = append(warnings, skillWarnings...)

	return entities, warnings
}

// agentPluginManifest reads file, reporting whether its document claims the
// Agent Plugins standard. plugin.json is a name many tools put at a
// repository root, and the $schema key is the whole claim, so a document
// that makes none is one of theirs. The components beside an unresolved
// manifest stay unread: reading them would attribute someone else's files to
// Cursor.
func agentPluginManifest(fsys fs.FS, file string) ([]adapter.Warning, bool) {
	data, err := fsguard.ReadResolvedRegular(fsys, file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		return []adapter.Warning{{File: file, Err: err}}, false
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		// A shape carrying no $schema is still an answer.
		if json.Valid(data) {
			return nil, false
		}
		return []adapter.Warning{{File: file, Err: err}}, false
	}
	return nil, strings.HasPrefix(stringValue(doc[pluginSchemaKey]), agentPluginSchemaPrefix)
}
