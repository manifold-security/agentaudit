package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// settingsFileNames are read independently. Neither file overrides the other.
var settingsFileNames = []string{"settings.json", "settings.local.json"}

// settings is the decoded shape of one .claude/settings*.json file. Scalar and
// struct fields are pointers so a present-but-empty value stays
// distinguishable from an absent key.
type settings struct {
	Hooks               map[string][]hookGroup `json:"hooks"`
	StatusLine          *statusLine            `json:"statusLine"`
	APIKeyHelper        *string                `json:"apiKeyHelper"`
	AWSAuthRefresh      *string                `json:"awsAuthRefresh"`
	AWSCredentialExport *string                `json:"awsCredentialExport"`
	Env                 map[string]string      `json:"env"`
	Sandbox             *sandbox               `json:"sandbox"`
	Permissions         *permissions           `json:"permissions"`

	// Top-level keys, unlike defaultMode, which nests under permissions:
	// https://code.claude.com/docs/en/settings
	EnableAllProjectMcpServers *bool    `json:"enableAllProjectMcpServers"`
	EnabledMcpjsonServers      []string `json:"enabledMcpjsonServers"`
}

type permissions struct {
	DefaultMode *string `json:"defaultMode"`
}

// hookGroup is one matcher block within hooks.<Event>. It carries json and
// yaml tags so frontmatter.go's yaml decode reuses this exact struct for
// subagent/skill hooks; each decoder reads its own tags and ignores the other.
type hookGroup struct {
	Matcher string    `json:"matcher" yaml:"matcher"`
	Hooks   []hookCmd `json:"hooks"   yaml:"hooks"`
}

type hookCmd struct {
	Type    string `json:"type"    yaml:"type"`
	Command string `json:"command" yaml:"command"`
}

type statusLine struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// sandbox mirrors the vendor's documented shape:
// https://code.claude.com/docs/en/settings-reference#sandbox-network
type sandbox struct {
	Network *sandboxNetwork `json:"network"`
}

type sandboxNetwork struct {
	AllowUnixSockets []string `json:"allowUnixSockets"`
}

// Parse reads the project-scoped Claude Code config sources in fsys into
// located IR entities. A missing source is skipped; a malformed or unreadable
// settings file appends an adapter.Warning and the loop moves on, so the other
// settings file still contributes.
func (Adapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	var entities []ir.Entity
	var warnings []adapter.Warning

	for _, name := range settingsFileNames {
		file := path.Join(".claude", name)

		data, err := fsguard.ReadResolvedRegular(fsys, file)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			warnings = append(warnings, adapter.Warning{File: file, Err: err})
			continue
		}

		var s settings
		if err := json.Unmarshal(data, &s); err != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: err})
			continue
		}

		entities = append(entities, entitiesFromSettings(s, file)...)
	}

	mcp, mcpWarnings, err := mcpEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, mcp...)
	warnings = append(warnings, mcpWarnings...)

	agents, agentWarnings, err := agentEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, agents...)
	warnings = append(warnings, agentWarnings...)

	skills, skillWarnings, err := skillEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, skills...)
	warnings = append(warnings, skillWarnings...)

	payloads, payloadWarnings, err := payloadEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, payloads...)
	warnings = append(warnings, payloadWarnings...)

	commands, commandWarnings, err := commandEntities(fsys)
	if err != nil {
		return nil, nil, err
	}
	entities = append(entities, commands...)
	warnings = append(warnings, commandWarnings...)

	plugins, pluginWarnings := pluginEntities(fsys)
	entities = append(entities, plugins...)
	warnings = append(warnings, pluginWarnings...)

	return entities, warnings, nil
}

func entitiesFromSettings(s settings, file string) []ir.Entity {
	var entities []ir.Entity

	entities = append(entities, hookEntities(s.Hooks, file)...)

	if s.StatusLine != nil {
		entities = append(entities, ir.StatusLine{
			Command:  s.StatusLine.Command,
			Type:     s.StatusLine.Type,
			Location: ir.Location{File: file, Key: "statusLine.command"},
		})
	}

	entities = append(entities, credentialHelperEntities(s, file)...)
	entities = append(entities, envEntities(s.Env, file)...)

	if s.Sandbox != nil && s.Sandbox.Network != nil {
		entities = append(entities, sandboxEntities(s.Sandbox.Network.AllowUnixSockets, file)...)
	}

	if s.Permissions != nil && s.Permissions.DefaultMode != nil {
		entities = append(entities, ir.PermissionMode{
			Mode:     *s.Permissions.DefaultMode,
			Source:   "permissions.defaultMode",
			Location: ir.Location{File: file, Key: "permissions.defaultMode"},
		})
	}

	entities = append(entities, mcpApprovalEntities(s, file)...)

	return entities
}

// mcpApprovalEntities emits ir.MCPApproval for the top-level MCP
// auto-approval settings, carrying raw values: judging permissiveness is the
// rule engine's job, not the adapter's.
func mcpApprovalEntities(s settings, file string) []ir.Entity {
	var entities []ir.Entity

	if s.EnableAllProjectMcpServers != nil {
		entities = append(entities, ir.MCPApproval{
			Setting:  "enableAllProjectMcpServers",
			Value:    strconv.FormatBool(*s.EnableAllProjectMcpServers),
			Location: ir.Location{File: file, Key: "enableAllProjectMcpServers"},
		})
	}

	for i, name := range s.EnabledMcpjsonServers {
		entities = append(entities, ir.MCPApproval{
			Setting:  "enabledMcpjsonServers",
			Value:    name,
			Location: ir.Location{File: file, Key: fmt.Sprintf("enabledMcpjsonServers[%d]", i)},
		})
	}

	return entities
}

// hookEntities fans out hooks.<Event>[<mi>].hooks[<ci>] into one ir.Hook per
// command, sorted by event name: Go map iteration order is randomized.
func hookEntities(hooks map[string][]hookGroup, file string) []ir.Entity {
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		events = append(events, event)
	}
	sort.Strings(events)

	var entities []ir.Entity
	for _, event := range events {
		for mi, group := range hooks[event] {
			for ci, cmd := range group.Hooks {
				entities = append(entities, ir.Hook{
					Event:   event,
					Matcher: group.Matcher,
					Command: cmd.Command,
					Location: ir.Location{
						File: file,
						Key:  fmt.Sprintf("hooks.%s[%d].hooks[%d]", event, mi, ci),
					},
				})
			}
		}
	}
	return entities
}

func credentialHelperEntities(s settings, file string) []ir.Entity {
	var entities []ir.Entity

	if s.APIKeyHelper != nil {
		entities = append(entities, ir.CredentialHelper{
			Variant:  ir.VariantAPIKeyHelper,
			Command:  *s.APIKeyHelper,
			Location: ir.Location{File: file, Key: "apiKeyHelper"},
		})
	}
	if s.AWSAuthRefresh != nil {
		entities = append(entities, ir.CredentialHelper{
			Variant:  ir.VariantAWSAuthRefresh,
			Command:  *s.AWSAuthRefresh,
			Location: ir.Location{File: file, Key: "awsAuthRefresh"},
		})
	}
	if s.AWSCredentialExport != nil {
		entities = append(entities, ir.CredentialHelper{
			Variant:  ir.VariantAWSCredentialExport,
			Command:  *s.AWSCredentialExport,
			Location: ir.Location{File: file, Key: "awsCredentialExport"},
		})
	}

	return entities
}

func envEntities(env map[string]string, file string) []ir.Entity {
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)

	entities := make([]ir.Entity, 0, len(names))
	for _, name := range names {
		entities = append(entities, ir.EnvVar{
			Name:     name,
			Value:    env[name],
			Location: ir.Location{File: file, Key: "env." + name},
		})
	}
	return entities
}

func sandboxEntities(sockets []string, file string) []ir.Entity {
	entities := make([]ir.Entity, 0, len(sockets))
	for i, sock := range sockets {
		entities = append(entities, ir.Sandbox{
			SocketPath: sock,
			Location:   ir.Location{File: file, Key: fmt.Sprintf("sandbox.network.allowUnixSockets[%d]", i)},
		})
	}
	return entities
}
