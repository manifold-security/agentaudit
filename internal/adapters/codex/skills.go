package codex

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

const (
	skillsRoot         = ".agents/skills"
	skillFileName      = "SKILL.md"
	skillScriptsDir    = "scripts"
	payloadOriginSkill = "skill"
)

func skillEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	if err := fsguard.CheckRealDir(fsys, skillsRoot); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: skillsRoot, Err: err}}
	}

	w := skillWalk{fsys: fsys}
	w.dir(skillsRoot)
	return w.entities, w.warnings
}

type skillWalk struct {
	fsys     fs.FS
	entities []ir.Entity
	warnings []adapter.Warning
}

func (w *skillWalk) dir(dir string) {
	entries, err := fs.ReadDir(w.fsys, dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		w.warnings = append(w.warnings, adapter.Warning{File: dir, Err: err})
	}

	// The whole listing decides whether dir is a skill before any entry is
	// handled, since a spelling such as SCRIPTS sorts ahead of SKILL.md.
	skill := slices.ContainsFunc(entries, func(e fs.DirEntry) bool {
		return w.anchors(dir, e)
	})

	for _, e := range entries {
		p := path.Join(dir, e.Name())
		switch {
		case skill && strings.EqualFold(e.Name(), skillScriptsDir):
			payloads, payloadWarnings := payloadEntities(w.fsys, p)
			w.entities = append(w.entities, payloads...)
			w.warnings = append(w.warnings, payloadWarnings...)
		case e.IsDir():
			w.dir(p)
		case e.Type()&fs.ModeSymlink != 0 && fsguard.LinkMayHideEntries(w.fsys, p):
			w.warnings = append(w.warnings, adapter.Warning{File: p, Err: fsguard.IrregularRefusal(p, e.Type())})
		}
	}
}

func (w *skillWalk) anchors(dir string, e fs.DirEntry) bool {
	if e.IsDir() || !strings.EqualFold(e.Name(), skillFileName) {
		return false
	}
	return e.Type()&fs.ModeSymlink == 0 || !fsguard.LinkMayHideEntries(w.fsys, path.Join(dir, e.Name()))
}

func payloadEntities(fsys fs.FS, dir string) ([]ir.Entity, []adapter.Warning) {
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
			if !errors.Is(err, fs.ErrNotExist) {
				warnings = append(warnings, adapter.Warning{File: p, Err: err})
			}
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
			Origin:     payloadOriginSkill,
			Location:   ir.Location{File: p},
		}}
		payload, refused := limits.Of(fsys).Admit(p, payload, nil)
		entities = append(entities, payload...)
		warnings = append(warnings, refused...)
		return nil
	})

	return entities, warnings
}

func executableValue(d fs.DirEntry) string {
	info, err := d.Info()
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		return ""
	}
	return "true"
}
