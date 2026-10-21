package cursor

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

const projectAgentsDir = ".cursor/agents"

const frontmatterReadonlyKey = "readonly"

// The values PermissionMode carries for a Cursor subagent.
// frontmatterReadonly decides which one a file gets: Cursor restricts the
// subagent only where the raw value lower-cases to the literal true, so a
// readonly of yes, or a true carrying a trailing comment, reads to a human
// as restricted and leaves the subagent write-enabled.
const (
	subagentReadonly     = "readonly"
	subagentWriteEnabled = "write-enabled"
)

const maxAgentDepth = 10

// unwalkedAgentDirs names the directories Cursor's own walk declines.
//
// Declining where the vendor declines is silent: nothing there contributed,
// so a degradation signal would be raised over a scan that missed nothing.
// A refusal this scanner makes and Cursor does not still warns.
var unwalkedAgentDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	"__pycache__":  true,
	".cache":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".nuxt":        true,
}

var agentNameSeparators = regexp.MustCompile(`[\s_]+`)

func projectSubagentEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	if err := fsguard.CheckRealDir(fsys, projectAgentsDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: projectAgentsDir, Err: err}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning

	_ = fs.WalkDir(fsys, projectAgentsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if d.IsDir() {
			if unwalkedAgentDirs[d.Name()] || agentDirDepth(p) > maxAgentDepth {
				return fs.SkipDir
			}
			return nil
		}
		if cerr := fsguard.CheckEntryType(fsys, p, d.Type(), fsguard.CheckRegular); cerr != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: cerr})
			return nil
		}
		if !agentFileExtensions[strings.ToLower(path.Ext(d.Name()))] {
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: rerr})
			return nil
		}

		es, ws := projectSubagentFrom(data, p)
		es, ws = limits.Of(fsys).Admit(p, es, ws)
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
		return nil
	})

	return entities, warnings
}

func agentDirDepth(p string) int {
	return strings.Count(p, "/") - strings.Count(projectAgentsDir, "/")
}

func projectSubagentFrom(data []byte, file string) ([]ir.Entity, []adapter.Warning) {
	name, found, err := frontmatterName(data)
	if err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}
	if !found {
		return nil, []adapter.Warning{{File: file, Err: errUnnamedComponent}}
	}
	if name == "" {
		name = agentNameFromFile(file)
	}
	if name == "" {
		return nil, []adapter.Warning{{File: file, Err: errUnnamedComponent}}
	}

	block, _, _ := splitFrontmatter(data)
	mode := subagentWriteEnabled
	if frontmatterReadonly(block) {
		mode = subagentReadonly
	}
	return []ir.Entity{ir.Subagent{
		Name:           name,
		PermissionMode: mode,
		Location:       ir.Location{File: file, Key: frontmatterNameKey},
	}}, nil
}

func agentNameFromFile(file string) string {
	base := path.Base(file)
	return agentNameSeparators.ReplaceAllString(strings.TrimSuffix(base, path.Ext(base)), "-")
}

func frontmatterReadonly(block []byte) bool {
	var value string
	for _, line := range strings.Split(string(block), "\n") {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) == frontmatterReadonlyKey {
			value = strings.TrimSpace(line[colon+1:])
		}
	}
	return strings.ToLower(value) == "true"
}
