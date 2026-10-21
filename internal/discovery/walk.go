package discovery

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
)

// symlinkResolutionBudget bounds the symlinked-directory resolutions ONE
// walkTree call performs. A containment root's symlink-hop limit bounds path
// DEPTH, not BREADTH: mutually symlinked directories make total resolutions
// grow as branching_factor^hop_limit however strict that limit is, so the
// count is bounded on its own terms, for os.DirFS and os.Root callers alike.
const symlinkResolutionBudget = 40

type resolutionBudget struct {
	remaining int
}

// walkTree walks fsys from "." once, calling visit for every entry. A
// symlink entry is resolved with fs.Stat before visit runs: a target
// resolving in-tree to a directory costs one symlinkResolutionBudget unit,
// and its own contents are visited under the symlink's own path; a
// non-directory target is visited unfollowed at no cost. A target fs.Stat
// cannot resolve, or a directory target once the budget is spent, is
// visited unfollowed with a Warning.
//
// A failure below the root degrades to an adapter.Warning and the walk
// continues, so one unreadable sibling never blinds the rest of the scan; a
// failure at "." itself stays fatal. visit may return fs.SkipDir to stop
// descending a directory entry — resolved or real — without affecting its
// siblings. The returned int counts the budget units consumed.
func walkTree(fsys fs.FS, visit func(p string, d fs.DirEntry) error) ([]adapter.Warning, int, error) {
	var warnings []adapter.Warning
	budget := &resolutionBudget{remaining: symlinkResolutionBudget}
	err := walkFrom(fsys, ".", visit, &warnings, budget, true, true)
	return warnings, symlinkResolutionBudget - budget.remaining, err
}

func walkFrom(fsys fs.FS, root string, visit func(p string, d fs.DirEntry) error, warnings *[]adapter.Warning, budget *resolutionBudget, visitRoot, fatalAtRoot bool) error {
	return fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root && fatalAtRoot {
				return err
			}
			*warnings = append(*warnings, adapter.Warning{File: p, Err: err})
			return nil
		}
		if p == root && !visitRoot {
			return nil
		}

		if d.Type()&fs.ModeSymlink == 0 {
			return visit(p, d)
		}

		info, statErr := fs.Stat(fsys, p)
		if statErr != nil {
			*warnings = append(*warnings, adapter.Warning{File: p, Err: statErr})
			return visit(p, d)
		}
		if !info.IsDir() {
			return visit(p, d)
		}

		if budget.remaining <= 0 {
			*warnings = append(*warnings, adapter.Warning{File: p, Err: adapter.Unreadable(fmt.Errorf("skipping %q: symlink resolution budget exhausted", p))})
			return visit(p, d)
		}
		budget.remaining--

		resolved := fs.FileInfoToDirEntry(info)
		if verr := visit(p, resolved); verr != nil {
			if errors.Is(verr, fs.SkipDir) {
				// fs.WalkDir sees a symlink entry as a non-directory, so
				// fs.SkipDir returned to it would skip this directory's
				// REMAINING SIBLINGS, not just this entry's descent.
				return nil
			}
			return verr
		}
		return walkFrom(fsys, p, visit, warnings, budget, false, false)
	})
}
