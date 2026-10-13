package fsguard

import (
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/manifold-security/agentaudit/adapter"
)

// CheckRegular reports an error unless p names a regular file.
//
// Lexical containment is not enough: the CLI scans a real filesystem, so a
// symlink at a textually-contained path resolves at the OS level to whatever
// it points at, including files outside the scanned repository, and reading it
// would surface that content as findings. Refusing the link outright costs
// nothing where the location is expected to hold a real file in the tree it
// was found in.
//
// The mode comes from LinkMode, so a link is judged on its own bits.
func CheckRegular(fsys fs.FS, p string) error {
	mode, err := LinkMode(fsys, p)
	if err != nil {
		return err
	}
	if !mode.IsRegular() {
		return IrregularRefusal(p, mode)
	}
	return nil
}

// CheckResolvedRegular admits p when p is a regular file or a symlink
// resolving to one, and refuses it otherwise.
//
// It is CheckRegular's counterpart, not a reuse: that guard refuses a link
// outright, this one resolves it to its target. Which of the two a read takes
// is the call site's decision, not a property of the path it is handed.
//
// Resolution demands a real fs.StatFS rather than fs.Stat, which falls back
// to Open on an FS lacking one. Without fs.StatFS the link is refused on its
// own mode.
func CheckResolvedRegular(fsys fs.FS, p string) error {
	mode, err := LinkMode(fsys, p)
	if err != nil {
		return err
	}
	if mode.IsRegular() {
		return nil
	}
	if mode&fs.ModeSymlink != 0 {
		if sf, ok := fsys.(fs.StatFS); ok {
			// A dangling link, or one os.Root rejects as leaving the root,
			// falls through to the refusal rather than surfacing
			// fs.ErrNotExist: a caller that routes not-exist to silence would
			// report a clean scan of a file nothing read.
			if info, serr := sf.Stat(p); serr == nil && info.Mode().IsRegular() {
				return nil
			}
		}
	}
	return IrregularRefusal(p, mode)
}

// CheckRealDir reports an error unless p names a real directory rather than a
// link to one. fs.WalkDir stats its own root through a symlink-following
// stat, so without this a link planted at a walk root sends the walk
// elsewhere and every entity it yields carries a Location under p, a path the
// scan never read.
//
// The fs.FS root itself is accepted: it is the scan boundary, not something a
// scanned repository can redirect.
func CheckRealDir(fsys fs.FS, p string) error {
	if p == "." {
		return nil
	}
	mode, err := LinkMode(fsys, p)
	if err != nil {
		return err
	}
	if !mode.IsDir() {
		return adapter.Unreadable(fmt.Errorf("refusing to walk %q: not a real directory (%s)", p, mode))
	}
	return nil
}

// CheckEntryType answers from the DirEntry type a walk already holds wherever
// it can, because check costs an Lstat or a listing of p's parent — quadratic
// over a directory when every entry pays it. Only a link, which carries no
// verdict of its own, is put through check.
func CheckEntryType(fsys fs.FS, p string, t fs.FileMode, check func(fs.FS, string) error) error {
	switch {
	case t.IsRegular():
		return nil
	case t&fs.ModeSymlink != 0:
		return check(fsys, p)
	default:
		return IrregularRefusal(p, t)
	}
}

// IrregularRefusal names the entry's own mode, which for a symlink stays the
// link's whatever its target resolved to.
func IrregularRefusal(p string, mode fs.FileMode) error {
	return adapter.Unreadable(fmt.Errorf("refusing to read %q: not a regular file (%s)", p, mode))
}

// ResolvedMode reports the mode of what p resolves to, asking fs.StatFS
// alone; without one it fails with errors.ErrUnsupported.
func ResolvedMode(fsys fs.FS, p string) (fs.FileMode, error) {
	sf, ok := fsys.(fs.StatFS)
	if !ok {
		return 0, &fs.PathError{Op: "stat", Path: p, Err: errors.ErrUnsupported}
	}
	info, err := sf.Stat(p)
	if err != nil {
		return 0, err
	}
	return info.Mode(), nil
}

// LinkMayHideEntries reports whether the link at p resolves to a directory,
// or cannot be resolved for any reason but absence.
func LinkMayHideEntries(fsys fs.FS, p string) bool {
	mode, err := ResolvedMode(fsys, p)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return mode.IsDir()
}

// ReadResolvedRegular classifies p before opening it. An absent p still fails
// as fs.ErrNotExist, which is what a caller's silent branch reads.
func ReadResolvedRegular(fsys fs.FS, p string) ([]byte, error) {
	if err := CheckResolvedRegular(fsys, p); err != nil {
		return nil, err
	}
	return fs.ReadFile(fsys, p)
}

// LinkMode reports p's OWN type bits, never its referent's, and never opens p.
// Both properties are load-bearing: fs.Stat answers for the link's target
// instead of the link, and an open is the stall this package exists to avoid.
//
// fs.Lstat is reached only behind the fs.ReadLinkFS assertion, because it
// falls back to fs.Stat without one, admitting exactly what this refuses.
func LinkMode(fsys fs.FS, p string) (fs.FileMode, error) {
	if _, ok := fsys.(fs.ReadLinkFS); ok {
		info, err := fs.Lstat(fsys, p)
		if err != nil {
			return 0, notExistAsOpen(err, p)
		}
		return info.Mode().Type(), nil
	}
	entries, err := fs.ReadDir(fsys, path.Dir(p))
	if err != nil {
		return 0, err
	}
	base := path.Base(p)
	for _, d := range entries {
		if d.Name() == base {
			return d.Type(), nil
		}
	}
	return 0, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}

// notExistAsOpen keeps an absent p reported as the fs.ReadFile error the guard
// stands in for, so a dangling path names itself rather than the classifier.
func notExistAsOpen(err error, p string) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	return err
}
