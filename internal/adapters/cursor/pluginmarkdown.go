package cursor

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/yamlconf"
)

const (
	pluginSkillsDir = "skills"
	pluginAgentsDir = "agents"
	skillFileName   = "SKILL.md"
	skillScriptsDir = "scripts"
)

const payloadOriginSkill = "skill"

const frontmatterFence = "---"

const frontmatterNameKey = "name"

var agentFileExtensions = map[string]bool{".md": true, ".mdc": true, ".markdown": true}

// errUnnamedComponent is what a markdown component that names nothing
// degrades to, whether a skill or a subagent declared it.
var errUnnamedComponent = errors.New(frontmatterNameKey + ": expected a non-empty string")

func pluginMarkdownEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning) {
	entities, warnings := pluginSkillEntities(fsys, layout)

	agents, agentWarnings := pluginAgentEntities(fsys, layout)
	return append(entities, agents...), append(warnings, agentWarnings...)
}

// pluginSkillEntities reads the plugin's skills. A skills root is what makes
// a plugin a multi-skill one; a plugin whose manifest names no skills
// location and carries no such root declares its one skill in a SKILL.md at
// its own root instead.
//
// A root this scanner could not read must not fall through to that second
// form, or the SKILL.md below gets reported as the plugin's one skill over a
// skills root nothing read.
func pluginSkillEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning) {
	dir := layout.skills.path
	if dir == "" {
		return nil, nil
	}

	err := fsguard.CheckRealDir(fsys, dir)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !layout.skills.declared:
		return rootSkillEntities(fsys, layout.root)
	case err != nil:
		return nil, []adapter.Warning{{File: dir, Err: err}}
	}
	return walkSkills(fsys, dir)
}

// rootSkillEntities reads the SKILL.md a single-skill plugin puts beside its
// manifest, and the scripts bundled at that same root. The plugin root is the
// skill's own directory in this form, so the scripts sitting there are the
// ones that skill bundles.
//
// A root declaring no SKILL.md is left alone.
func rootSkillEntities(fsys fs.FS, root string) ([]ir.Entity, []adapter.Warning) {
	listing, err := fs.ReadDir(fsys, root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: root, Err: err}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	present := false
	for _, e := range listing {
		if !strings.EqualFold(e.Name(), skillFileName) {
			continue
		}
		es, ws, ok := rootSkillFile(fsys, path.Join(root, e.Name()))
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
		present = present || ok
	}
	if !present {
		return nil, nil
	}

	payloads, payloadWarnings := skillPayloadEntities(fsys, root)
	return append(entities, payloads...), append(warnings, payloadWarnings...)
}

// rootSkillFile reads the plugin root's own SKILL.md, reporting whether the
// root holds one at all. An entry this scanner refuses to read still answers
// that question, so a link planted there cannot take the bundled scripts down
// with it.
func rootSkillFile(fsys fs.FS, file string) ([]ir.Entity, []adapter.Warning, bool) {
	if err := fsguard.CheckRegular(fsys, file); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, false
		}
		return nil, []adapter.Warning{{File: file, Err: err}}, true
	}
	data, err := fs.ReadFile(fsys, file)
	if err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}, true
	}
	entities, warnings := skillFrom(data, file)
	entities, warnings = limits.Of(fsys).Admit(file, entities, warnings)
	return entities, warnings, true
}

// walkSkills reads each SKILL.md beneath dir and the scripts bundled beside
// it. Depth carries no meaning here: a directory between dir and a SKILL.md
// organises the tree rather than declaring a skill of its own, which
// TestPluginSkillsSurfaceBelowAnIntermediateDirectory pins.
func walkSkills(fsys fs.FS, dir string) ([]ir.Entity, []adapter.Warning) {
	var entities []ir.Entity
	var warnings []adapter.Warning

	_ = fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(path.Base(p), skillFileName) {
			if d.Type()&fs.ModeSymlink != 0 && fsguard.LinkMayHideEntries(fsys, p) && !inSkillScripts(fsys, dir, p) {
				warnings = append(warnings, adapter.Warning{File: p, Err: fsguard.IrregularRefusal(p, d.Type())})
			}
			return nil
		}

		skill, skillWarnings := readSkillFile(fsys, p, d)
		entities = append(entities, skill...)
		warnings = append(warnings, skillWarnings...)

		payloads, payloadWarnings := skillPayloadEntities(fsys, path.Dir(p))
		entities = append(entities, payloads...)
		warnings = append(warnings, payloadWarnings...)
		return nil
	})

	return entities, warnings
}

func inSkillScripts(fsys fs.FS, root, p string) bool {
	for q := p; q != root && q != "."; q = path.Dir(q) {
		if !strings.EqualFold(path.Base(q), skillScriptsDir) {
			continue
		}
		entries, err := fs.ReadDir(fsys, path.Dir(q))
		if err == nil && slices.ContainsFunc(entries, isSkillFileEntry) {
			return true
		}
	}
	return false
}

func isSkillFileEntry(e fs.DirEntry) bool {
	return !e.IsDir() && strings.EqualFold(e.Name(), skillFileName)
}

func skillPayloadEntities(fsys fs.FS, skillDir string) ([]ir.Entity, []adapter.Warning) {
	entries, err := fs.ReadDir(fsys, skillDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: skillDir, Err: err}}
	}
	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, e := range entries {
		if !strings.EqualFold(e.Name(), skillScriptsDir) {
			continue
		}
		es, ws := payloadEntities(fsys, path.Join(skillDir, e.Name()), payloadOriginSkill)
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
	}
	return entities, warnings
}

// readSkillFile classifies p before opening it, so a link the plugin planted
// at a skill's location is refused on its own type bits rather than followed
// out of the tree.
func readSkillFile(fsys fs.FS, p string, d fs.DirEntry) ([]ir.Entity, []adapter.Warning) {
	if err := fsguard.CheckEntryType(fsys, p, d.Type(), fsguard.CheckRegular); err != nil {
		return nil, []adapter.Warning{{File: p, Err: err}}
	}
	data, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, []adapter.Warning{{File: p, Err: err}}
	}
	entities, warnings := skillFrom(data, p)
	entities, warnings = limits.Of(fsys).Admit(p, entities, warnings)
	return entities, warnings
}

func skillFrom(data []byte, file string) ([]ir.Entity, []adapter.Warning) {
	name, _, err := frontmatterName(data)
	if err == nil && name == "" {
		err = errUnnamedComponent
	}
	if err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}
	return []ir.Entity{ir.Skill{
		Name:     name,
		Location: ir.Location{File: file, Key: frontmatterNameKey},
	}}, nil
}

// payloadEntities reads the files a payload directory holds. Membership of
// the directory is the whole classification: the extension and the execute
// bit are reported, not required.
func payloadEntities(fsys fs.FS, dir, origin string) ([]ir.Entity, []adapter.Warning) {
	if err := fsguard.CheckRealDir(fsys, dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: dir, Err: err}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning

	_ = fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			warnings = append(warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if cerr := fsguard.CheckEntryType(fsys, p, d.Type(), fsguard.CheckRegular); cerr != nil {
			warnings = append(warnings, adapter.Warning{File: p, Err: cerr})
			return nil
		}

		payload := []ir.Entity{ir.BundledPayload{
			Path:       p,
			Extension:  strings.ToLower(path.Ext(p)),
			Executable: executableValue(d),
			Origin:     origin,
			Location:   ir.Location{File: p},
		}}
		payload, refused := limits.Of(fsys).Admit(p, payload, nil)
		entities = append(entities, payload...)
		warnings = append(warnings, refused...)
		return nil
	})

	return entities, warnings
}

// executableValue reads the entry's execute bit for the report to show. The
// directory the file sits in is what declares the file executable code, so
// the bit adds detail rather than deciding anything.
func executableValue(d fs.DirEntry) string {
	info, err := d.Info()
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		return ""
	}
	return "true"
}

func pluginAgentEntities(fsys fs.FS, layout pluginLayout) ([]ir.Entity, []adapter.Warning) {
	dir := layout.agents.path
	if dir == "" {
		return nil, nil
	}

	if err := fsguard.CheckRealDir(fsys, dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) && !layout.agents.declared {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: dir, Err: err}}
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, []adapter.Warning{{File: dir, Err: err}}
	}

	var entities []ir.Entity
	var warnings []adapter.Warning
	for _, d := range entries {
		if d.IsDir() || !agentFileExtensions[strings.ToLower(path.Ext(d.Name()))] {
			continue
		}

		file := path.Join(dir, d.Name())
		if cerr := fsguard.CheckEntryType(fsys, file, d.Type(), fsguard.CheckRegular); cerr != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: cerr})
			continue
		}
		data, rerr := fs.ReadFile(fsys, file)
		if rerr != nil {
			warnings = append(warnings, adapter.Warning{File: file, Err: rerr})
			continue
		}

		es, ws := agentFrom(data, file)
		es, ws = limits.Of(fsys).Admit(file, es, ws)
		entities = append(entities, es...)
		warnings = append(warnings, ws...)
	}
	return entities, warnings
}

// agentFrom builds the subagent an agent file declares. A file with no fence
// at all is prose the plugin ships beside its agents, which loses nothing by
// being skipped.
func agentFrom(data []byte, file string) ([]ir.Entity, []adapter.Warning) {
	name, found, err := frontmatterName(data)
	if !found {
		return nil, nil
	}
	if err == nil && name == "" {
		err = errUnnamedComponent
	}
	if err != nil {
		return nil, []adapter.Warning{{File: file, Err: err}}
	}
	return []ir.Entity{ir.Subagent{
		Name:     name,
		Location: ir.Location{File: file, Key: frontmatterNameKey},
	}}, nil
}

// frontmatterName reads the name a component's leading YAML block declares.
func frontmatterName(data []byte) (name string, found bool, err error) {
	block, found, terminated := splitFrontmatter(data)
	if !found {
		return "", false, nil
	}
	if !terminated {
		return "", true, errors.New("frontmatter: unterminated \"" + frontmatterFence + "\" fence")
	}

	var fm struct {
		Name string `yaml:"name"`
	}
	if uerr := yamlconf.Unmarshal(block, &fm); uerr != nil {
		return "", true, fmt.Errorf("frontmatter: %w", uerr)
	}
	return fm.Name, true, nil
}

// splitFrontmatter separates data's leading YAML block from the body below
// it. !found is a plain markdown document; found without terminated is a
// fence the file never closes.
func splitFrontmatter(data []byte) (block []byte, found, terminated bool) {
	lines := strings.Split(string(data), "\n")
	if strings.TrimRight(lines[0], "\r") != frontmatterFence {
		return nil, false, false
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimRight(lines[i], "\r") == frontmatterFence {
			return []byte(strings.Join(lines[1:i], "\n")), true, true
		}
	}
	return nil, true, false
}
