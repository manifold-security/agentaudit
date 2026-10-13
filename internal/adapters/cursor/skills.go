package cursor

import (
	"errors"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/fsguard"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const projectSkillsDir = ".cursor/skills"

// skillEntities reads the skills a project declares under Cursor's own
// skills root, together with the scripts each of them bundles.
//
// The root is classified before the walk for the reason fsguard.CheckRealDir
// gives. A project declaring no such root is the common case, so an absent
// one costs nothing and says nothing.
func skillEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning) {
	if err := fsguard.CheckRealDir(fsys, projectSkillsDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []adapter.Warning{{File: projectSkillsDir, Err: err}}
	}
	return walkSkills(fsys, projectSkillsDir)
}
