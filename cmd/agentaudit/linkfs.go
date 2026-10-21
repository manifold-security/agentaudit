package main

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// linkRewriteBudget bounds one chain of absolute rewrites, so a cycle
// spelled absolutely degrades into the relative spelling's block shape.
const linkRewriteBudget = 8

var errRewriteBudget = errors.New("symlink rewrite budget exhausted")

// fs.GlobFS and fs.SubFS are left out because os.Root's own fs.FS carries
// neither.
var _ interface {
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.ReadLinkFS
} = linkFS{}

// linkFS re-expresses an absolutely spelled symlink target relative to the
// scanned root and retries through parent — os.Root refuses any absolute
// target, so a dotfile manager's .claude would read as an empty surface.
// parent stays the only containment authority: a rewritten path is
// re-entered through it, never a fresh os.OpenRoot, because an in-root
// spelling reached through an escaping ancestor passes any lexical test.
// Re-entry makes a defect here a missed scan rather than a leak;
// TestLinkFS_RefusedTargetsStayRefused holds it closed.
type linkFS struct {
	parent fs.FS
	roots  []string
}

func newLinkFS(parent fs.FS, target string) linkFS {
	abs, err := filepath.Abs(target)
	if err != nil {
		return linkFS{parent: parent}
	}
	abs = filepath.Clean(abs)
	roots := []string{abs}

	// A home reached through a symlink is opened under a spelling the link
	// text beneath it need not share; carrying both lets either one rebase.
	if evaluated, err := filepath.EvalSymlinks(abs); err == nil && evaluated != abs {
		roots = append(roots, filepath.Clean(evaluated))
	}
	return linkFS{parent: parent, roots: roots}
}

// rebase answers faithfulness, not containment: a match means the link text
// is spelled inside the root, and parent alone decides whether anything is
// really there. Comparison is byte-exact — case sensitivity is a property
// of the mount, not of the platform, so folding would rebase root/X onto
// root/x, a different file carrying the link's provenance.
func (l linkFS) rebase(target string) (string, bool) {
	if !filepath.IsAbs(target) {
		return "", false
	}
	clean := filepath.Clean(target)
	for _, root := range l.roots {
		if clean == root {
			return ".", true
		}
		if strings.HasPrefix(clean, root+string(filepath.Separator)) {
			rel := path.Clean(filepath.ToSlash(clean[len(root)+1:]))
			return rel, fs.ValidPath(rel)
		}
	}
	return "", false
}

func joinRest(head string, rest []string) string {
	if len(rest) == 0 {
		return head
	}
	return path.Join(append([]string{head}, rest...)...)
}

func (l linkFS) resolve(name string, budget int) (string, error) {
	cur := "."
	parts := strings.Split(name, "/")
	for i, part := range parts {
		next := path.Join(cur, part)

		info, err := fs.Lstat(l.parent, next)
		if err != nil {
			return joinRest(next, parts[i+1:]), nil
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		target, err := fs.ReadLink(l.parent, next)
		if err != nil || !filepath.IsAbs(target) {
			cur = next
			continue
		}
		rel, ok := l.rebase(target)
		if !ok {
			return joinRest(next, parts[i+1:]), nil
		}
		if budget == 0 {
			return "", errRewriteBudget
		}
		budget--
		if cur, err = l.resolve(rel, budget); err != nil {
			return "", err
		}
	}
	return cur, nil
}

// rewrite returns the path to retry name at. Handing back name unchanged is
// what leaves the original error intact: os.Root's refusal is a bare error
// string with no errors.Is target to classify it by.
func (l linkFS) rewrite(name string) (string, error) {
	if len(l.roots) == 0 || !fs.ValidPath(name) {
		return name, nil
	}
	resolved, err := l.resolve(name, linkRewriteBudget)
	if err != nil {
		return "", &fs.PathError{Op: "resolvelink", Path: name, Err: err}
	}
	return resolved, nil
}

// rewriteAncestors leaves name's last component alone, so Lstat and ReadLink
// keep reporting the leaf's own type bits — the FIFO guard's contract.
func (l linkFS) rewriteAncestors(name string) (string, error) {
	if len(l.roots) == 0 || name == "." || !fs.ValidPath(name) {
		return name, nil
	}
	resolved, err := l.resolve(path.Dir(name), linkRewriteBudget)
	if err != nil {
		return "", &fs.PathError{Op: "resolvelink", Path: name, Err: err}
	}
	return path.Join(resolved, path.Base(name)), nil
}

// atCallerPath restores the spelling the caller asked for: errors.As reaches
// a wrapped *fs.PathError where a type assertion would not.
func atCallerPath(err error, name string) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		pathErr.Path = name
	}
	return err
}

// retryAt resolves only after op has failed, which keeps a tree holding no
// absolute symlink untouched (TestLinkFS_TransparentWithoutAnAbsoluteSymlink).
// The rewritten path's own result then decides the answer: an absent file
// behind a resolved link has to read as absent, or the report counts an
// unreadable source where a config is merely missing.
func retryAt[T any](name string, rewrite func(string) (string, error), op func(string) (T, error)) (T, error) {
	value, err := op(name)
	if err == nil {
		return value, nil
	}
	// os.Root spends a fixed budget of symlink hops and refuses an absolute
	// target rather than following one, so a budget failure means the walk
	// spent that budget on relative hops. resolve travels the same root and
	// gives up at the same component, making the attempt a traversal that
	// cannot change the answer. The escape refusal carries no errno.
	if errors.Is(err, syscall.ELOOP) {
		return value, err
	}
	resolved, resolveErr := rewrite(name)
	if resolveErr != nil {
		var zero T
		return zero, resolveErr
	}
	if resolved == name {
		return value, err
	}
	retried, retryErr := op(resolved)
	return retried, atCallerPath(retryErr, name)
}

func (l linkFS) Open(name string) (fs.File, error) {
	return retryAt(name, l.rewrite, l.parent.Open)
}

func (l linkFS) Stat(name string) (fs.FileInfo, error) {
	return retryAt(name, l.rewrite, func(n string) (fs.FileInfo, error) { return fs.Stat(l.parent, n) })
}

func (l linkFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return retryAt(name, l.rewrite, func(n string) ([]fs.DirEntry, error) { return fs.ReadDir(l.parent, n) })
}

func (l linkFS) ReadFile(name string) ([]byte, error) {
	return retryAt(name, l.rewrite, func(n string) ([]byte, error) { return fs.ReadFile(l.parent, n) })
}

func (l linkFS) Lstat(name string) (fs.FileInfo, error) {
	return retryAt(name, l.rewriteAncestors, func(n string) (fs.FileInfo, error) { return fs.Lstat(l.parent, n) })
}

func (l linkFS) ReadLink(name string) (string, error) {
	return retryAt(name, l.rewriteAncestors, func(n string) (string, error) { return fs.ReadLink(l.parent, n) })
}
