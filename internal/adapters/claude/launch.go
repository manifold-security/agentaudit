package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const launchFileName = ".claude/launch.json"

const configurationsKey = "configurations"

type launchDoc struct {
	Configurations json.RawMessage `json:"configurations"`
}

// launchConfiguration leaves port and autoPort undeclared, so a value of the
// wrong type cannot fault an entry.
type launchConfiguration struct {
	Name              string            `json:"name"`
	RuntimeExecutable string            `json:"runtimeExecutable"`
	RuntimeArgs       []string          `json:"runtimeArgs"`
	Program           string            `json:"program"`
	Args              []string          `json:"args"`
	Cwd               string            `json:"cwd"`
	Env               map[string]string `json:"env"`
	URL               string            `json:"url"`
}

func previewServerEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	data, err := fsguard.ReadResolvedRegular(fsys, launchFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: launchFileName, Err: err}}
	}

	if json.Valid(data) {
		if f := mcpjson.FormOf(data); f != mcpjson.FormObject && f != mcpjson.FormAbsent {
			return nil, []adapter.Warning{{File: launchFileName, Err: errors.New("expected an object, found " + mcpjson.FormName(f))}}
		}
	}

	var doc launchDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, []adapter.Warning{{File: launchFileName, Err: err}}
	}

	switch f := mcpjson.FormOf(doc.Configurations); f {
	case mcpjson.FormAbsent:
		return nil, nil
	case mcpjson.FormArray:
	default:
		return nil, []adapter.Warning{{File: launchFileName, Err: errors.New(configurationsKey + ": expected an array of configurations, found " + mcpjson.FormName(f))}}
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(doc.Configurations, &raw); err != nil {
		return nil, []adapter.Warning{{File: launchFileName, Err: fmt.Errorf("%s: %w", configurationsKey, err)}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for i, item := range raw {
		key := fmt.Sprintf("%s[%d]", configurationsKey, i)
		if f := mcpjson.FormOf(item); f != mcpjson.FormObject {
			warnings = append(warnings, adapter.Warning{File: launchFileName, Err: errors.New(key + ": expected an object, found " + mcpjson.FormName(f))})
			continue
		}
		var c launchConfiguration
		if err := json.Unmarshal(item, &c); err != nil {
			warnings = append(warnings, adapter.Warning{File: launchFileName, Err: fmt.Errorf("%s: %w", key, err)})
			continue
		}
		entities = append(entities, previewServerOf(c, ir.Location{File: launchFileName, Key: key}))
	}
	return limits.Of(fsys).Admit(launchFileName, entities, warnings)
}

func previewServerOf(c launchConfiguration, loc ir.Location) ir.PreviewServer {
	p := ir.PreviewServer{Name: c.Name, Cwd: c.Cwd, Env: c.Env, URL: c.URL, Location: loc}
	switch {
	case c.RuntimeExecutable != "" || len(c.RuntimeArgs) > 0:
		p.Command, p.Args = c.RuntimeExecutable, c.RuntimeArgs
		p.Program, p.ProgramArgs = c.Program, c.Args
	case c.Program != "":
		// https://code.claude.com/docs/en/desktop: a program runs under node.
		p.Command, p.Args = "node", append([]string{c.Program}, c.Args...)
	default:
		p.Args = c.Args
	}
	return p
}
