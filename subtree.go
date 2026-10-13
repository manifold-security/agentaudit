package agentaudit

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
)

var _ interface {
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.ReadLinkFS
	fs.GlobFS
	fs.SubFS
} = subtreeFS{}

// subtree returns fsys rooted at dir, preserving the optional interfaces
// fs.Sub drops. fs.Sub's result carries no fs.StatFS, so fs.Stat falls back
// to Open, and opening a symlink whose target is a FIFO blocks until a
// writer appears — hanging the scan of any project that contains one.
func subtree(fsys fs.FS, dir string) (fs.FS, error) {
	if !fs.ValidPath(dir) {
		return nil, &fs.PathError{Op: "sub", Path: dir, Err: fs.ErrInvalid}
	}
	if dir == "." {
		return fsys, nil
	}
	return subtreeFS{parent: fsys, dir: dir}, nil
}

type subtreeFS struct {
	parent fs.FS
	dir    string
}

func (s subtreeFS) full(op, name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	return path.Join(s.dir, name), nil
}

func (s subtreeFS) shorten(name string) (string, bool) {
	if name == s.dir {
		return ".", true
	}
	if len(name) > len(s.dir)+1 && name[:len(s.dir)] == s.dir && name[len(s.dir)] == '/' {
		return name[len(s.dir)+1:], true
	}
	return "", false
}

// fixErr rewrites a parent-namespace path in err back into this subtree's,
// so a warning names the path its caller asked for
// (TestSubtreeFSFixErrShortensRootFault). Only pathErr.Path changes, since
// a fmt.Errorf wrapper froze its own message text at construction.
func (s subtreeFS) fixErr(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		if short, ok := s.shorten(pathErr.Path); ok {
			pathErr.Path = short
		}
	}
	return err
}

func (s subtreeFS) Open(name string) (fs.File, error) {
	full, err := s.full("open", name)
	if err != nil {
		return nil, err
	}
	f, err := s.parent.Open(full)
	return f, s.fixErr(err)
}

func (s subtreeFS) Stat(name string) (fs.FileInfo, error) {
	full, err := s.full("stat", name)
	if err != nil {
		return nil, err
	}
	info, err := fs.Stat(s.parent, full)
	return info, s.fixErr(err)
}

func (s subtreeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	full, err := s.full("readdir", name)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(s.parent, full)
	return entries, s.fixErr(err)
}

func (s subtreeFS) ReadFile(name string) ([]byte, error) {
	full, err := s.full("readfile", name)
	if err != nil {
		return nil, err
	}
	data, err := fs.ReadFile(s.parent, full)
	return data, s.fixErr(err)
}

func (s subtreeFS) Lstat(name string) (fs.FileInfo, error) {
	full, err := s.full("lstat", name)
	if err != nil {
		return nil, err
	}
	info, err := fs.Lstat(s.parent, full)
	return info, s.fixErr(err)
}

func (s subtreeFS) ReadLink(name string) (string, error) {
	full, err := s.full("readlink", name)
	if err != nil {
		return "", err
	}
	target, err := fs.ReadLink(s.parent, full)
	return target, s.fixErr(err)
}

func (s subtreeFS) Glob(pattern string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	if pattern == "." {
		return []string{"."}, nil
	}
	list, err := fs.Glob(s.parent, s.dir+"/"+pattern)
	for i, name := range list {
		short, ok := s.shorten(name)
		if !ok {
			return nil, fmt.Errorf("subtree: glob result %q not under %q", name, s.dir)
		}
		list[i] = short
	}
	return list, s.fixErr(err)
}

func (s subtreeFS) Sub(dir string) (fs.FS, error) {
	full, err := s.full("sub", dir)
	if err != nil {
		return nil, err
	}
	return subtree(s.parent, full)
}
