package discovery

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
)

// symlinkResolutionBudget bounds the symlinked-directory resolutions ONE
// walkTreeFunc call performs. A containment root's symlink-hop limit bounds
// path DEPTH, not BREADTH: mutually symlinked directories make total
// resolutions grow as branching_factor^hop_limit however strict that limit
// is, so the count is bounded on its own terms, for os.DirFS and os.Root
// callers alike.
const symlinkResolutionBudget = 40

// symlinkVisitFloor is the least the visit cap allows, so a small tree that
// aliases one config directory a few times is walked whole.
const symlinkVisitFloor = 10000

var errBudgetSpent = errors.New("symlink resolution budget exhausted")

type resolutionBudget struct {
	remaining int
	visits    int
	counted   bool
}

func (b *resolutionBudget) spent(fsys fs.FS) bool {
	if b.visits <= 0 && !b.counted {
		b.counted = true
		b.visits = max(listedEntries(fsys)-symlinkVisitFloor, 0)
	}
	return b.visits <= 0
}

// walkTreeFunc walks fsys from ".", calling visit for each entry it reaches
// and warn for each Warning it raises. A symlink entry is resolved with
// fs.Stat before visit runs: a target resolving in-tree to a directory costs
// one symlinkResolutionBudget unit, and its own contents are visited under
// the symlink's own path; a non-directory target is visited unfollowed at no
// cost. A target fs.Stat cannot resolve, or a directory target once the
// budget is spent, is visited unfollowed with a Warning.
//
// Counting resolutions alone still lets a walk revisit the tree up to
// symlinkResolutionBudget times, because each one re-walks its whole target:
// a directory linking to itself would be re-walked once per resolution. So
// the entries visited beneath resolved links are capped too, at
// symlinkVisitFloor or, once that is spent, at the entries fsys lists
// without following any if those are more. Reaching the cap stops the walk
// beneath links, each stopped descent with a Warning naming its link, and
// refuses later directory targets as an exhausted symlinkResolutionBudget
// does.
//
// A failure below the root degrades to an adapter.Warning and the walk
// continues, so one unreadable sibling never blinds the rest of the scan; a
// failure at "." itself stays fatal. visit may return fs.SkipDir to stop
// descending a directory entry — resolved or real — without affecting its
// siblings. The returned int counts the resolutions performed.
func walkTreeFunc(fsys fs.FS, visit func(p string, d fs.DirEntry) error, warn func(adapter.Warning)) (int, error) {
	budget := &resolutionBudget{remaining: symlinkResolutionBudget, visits: symlinkVisitFloor}
	err := walkFrom(fsys, ".", visit, warn, budget, false)
	return symlinkResolutionBudget - budget.remaining, err
}

func walkTree(fsys fs.FS, visit func(p string, d fs.DirEntry) error) ([]adapter.Warning, int, error) {
	var warnings []adapter.Warning
	resolutions, err := walkTreeFunc(fsys, visit, func(w adapter.Warning) { warnings = append(warnings, w) })
	return warnings, resolutions, err
}

func walkFrom(fsys fs.FS, root string, visit func(p string, d fs.DirEntry) error, warn func(adapter.Warning), budget *resolutionBudget, beneathLink bool) error {
	return fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if beneathLink && p != root {
			if budget.spent(fsys) {
				warn(budgetRefusal(root))
				return fs.SkipAll
			}
			budget.visits--
		}
		if err != nil {
			if p == root && !beneathLink {
				return err
			}
			warn(adapter.Warning{File: p, Err: err})
			return nil
		}
		if p == root && beneathLink {
			return nil
		}

		if d.Type()&fs.ModeSymlink == 0 {
			return visit(p, d)
		}

		info, statErr := fs.Stat(fsys, p)
		if statErr != nil {
			warn(adapter.Warning{File: p, Err: statErr})
			return visit(p, d)
		}
		if !info.IsDir() {
			return visit(p, d)
		}

		if budget.remaining <= 0 || budget.spent(fsys) {
			warn(budgetRefusal(p))
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
		return walkFrom(fsys, p, visit, warn, budget, true)
	})
}

func budgetRefusal(p string) adapter.Warning {
	return adapter.Warning{File: p, Err: adapter.Unreadable(fmt.Errorf("skipping %q: %w", p, errBudgetSpent))}
}

func listedEntries(fsys fs.FS) int {
	n := 0
	_ = fs.WalkDir(fsys, ".", func(_ string, _ fs.DirEntry, err error) error {
		if err == nil {
			n++
		}
		return nil
	})
	return n
}
