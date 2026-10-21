package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const claudeJSONFileName = ".claude.json"

// claudeJSONFile is the decoded shape of ~/.claude.json. Fields stay raw so a
// wrong-typed value degrades to a Warning for that key, or that project,
// alone rather than failing the whole document's unmarshal.
type claudeJSONFile struct {
	MCPServers json.RawMessage            `json:"mcpServers"`
	Projects   map[string]json.RawMessage `json:"projects"`
}

type claudeJSONProject struct {
	MCPServers            json.RawMessage `json:"mcpServers"`
	EnabledMcpjsonServers json.RawMessage `json:"enabledMcpjsonServers"`
}

// ParseGlobal decodes .claude.json into IR entities.
func (Adapter) ParseGlobal(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	data, err := fsguard.ReadResolvedRegular(fsys, claudeJSONFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, []adapter.Warning{{File: claudeJSONFileName, Err: err}}, nil
	}

	if json.Valid(data) {
		if f := mcpjson.FormOf(data); f != mcpjson.FormObject && f != mcpjson.FormAbsent {
			return nil, []adapter.Warning{{File: claudeJSONFileName, Err: errors.New("expected an object, found " + mcpjson.FormName(f))}}, nil
		}
	}

	var doc claudeJSONFile
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: claudeJSONFileName, Err: err}}, nil
	}

	var entities []ir.Entity
	var warnings []adapter.Warning

	budget := limits.Of(fsys)
	servers, serverWarnings := mcpjson.ServersFromRaw(doc.MCPServers, claudeJSONFileName, "mcpServers", budget)
	warnings = append(warnings, serverWarnings...)
	mcpEnts, mcpWarnings := entitiesFromMCPMap(servers, claudeJSONFileName, "mcpServers")
	entities = append(entities, mcpEnts...)
	warnings = append(warnings, mcpWarnings...)

	projectKeys := make([]string, 0, len(doc.Projects))
	for p := range doc.Projects {
		projectKeys = append(projectKeys, p)
	}
	sort.Strings(projectKeys)

	for _, p := range projectKeys {
		projEntities, projWarnings := projectEntities(doc.Projects[p], p, budget)
		entities = append(entities, projEntities...)
		warnings = append(warnings, projWarnings...)
	}

	entities, warnings = budget.Admit(claudeJSONFileName, entities, warnings)
	return entities, warnings, nil
}

func projectEntities(raw json.RawMessage, p string, budget *limits.Entities) ([]ir.Entity, []adapter.Warning) {
	var proj claudeJSONProject
	if err := json.Unmarshal(raw, &proj); err != nil {
		return nil, []adapter.Warning{{File: claudeJSONFileName, Err: fmt.Errorf("projects.%s: %w", p, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning

	mcpKey := "projects." + p + ".mcpServers"
	servers, serverWarnings := mcpjson.ServersFromRaw(proj.MCPServers, claudeJSONFileName, mcpKey, budget)
	warnings = append(warnings, serverWarnings...)
	mcpEnts, mcpWarnings := entitiesFromMCPMap(servers, claudeJSONFileName, mcpKey)
	entities = append(entities, mcpEnts...)
	warnings = append(warnings, mcpWarnings...)

	approvalKey := "projects." + p + ".enabledMcpjsonServers"
	names, approvalWarnings := enabledMcpjsonServersFromRaw(proj.EnabledMcpjsonServers, approvalKey)
	warnings = append(warnings, approvalWarnings...)
	for i, name := range names {
		entities = append(entities, ir.MCPApproval{
			Setting:  "enabledMcpjsonServers",
			Value:    name,
			Location: ir.Location{File: claudeJSONFileName, Key: fmt.Sprintf("%s[%d]", approvalKey, i)},
		})
	}

	return entities, warnings
}

func enabledMcpjsonServersFromRaw(raw json.RawMessage, key string) ([]string, []adapter.Warning) {
	switch f := mcpjson.FormOf(raw); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormArray:
	default:
		return nil, []adapter.Warning{{File: claudeJSONFileName, Err: errors.New(key + ": expected an array, found " + mcpjson.FormName(f))}}
	}

	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, []adapter.Warning{{File: claudeJSONFileName, Err: fmt.Errorf("%s: %w", key, err)}}
	}
	return names, nil
}
