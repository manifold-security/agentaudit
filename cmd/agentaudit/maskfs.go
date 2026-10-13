package main

import (
	"errors"
	"io/fs"
	"path"
	"strings"
)

// A dropped forwarder becomes a build failure here rather than a capability
// silently lost at a call site: a decorator missing StatFS makes fs.Stat
// fall back to Open, and opening a symlink whose target is a FIFO then
// blocks forever.
var _ interface {
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.ReadLinkFS
	fs.GlobFS
	fs.SubFS
} = maskFS{}

type maskFS struct {
	parent fs.FS
	allow  map[string]bool
}

// admit returns fs.ErrNotExist rather than a refusal for a path outside the
// declared global config, matching agentaudit.go's isGenuineReadFailure
// exclusion: such a path is not a source the scan failed to read.
func (m maskFS) admit(name string) error {
	if !fs.ValidPath(name) {
		return &fs.PathError{Op: "mask", Path: name, Err: fs.ErrInvalid}
	}
	if m.admits(name) {
		return nil
	}
	return &fs.PathError{Op: "mask", Path: name, Err: fs.ErrNotExist}
}

// admits reports whether name is at or below a declared prefix, or is an
// ancestor on the way to one: a walk cannot reach the prefix without
// listing that ancestor, whose other children stay denied. Comparisons
// land on path-segment boundaries, so ".claude-evil" cannot ride in on
// ".claude" nor "settings.json.bak" on "settings.json".
func (m maskFS) admits(name string) bool {
	if name == "." {
		return true
	}
	for prefix := range m.allow {
		if name == prefix || strings.HasPrefix(name, prefix+"/") || strings.HasPrefix(prefix, name+"/") {
			return true
		}
	}
	return false
}

func (m maskFS) covers(dir string) bool {
	for prefix := range m.allow {
		if dir == prefix || strings.HasPrefix(dir, prefix+"/") {
			return true
		}
	}
	return false
}

func (m maskFS) rebase(dir string) map[string]bool {
	rebased := map[string]bool{}
	for prefix := range m.allow {
		if strings.HasPrefix(prefix, dir+"/") {
			rebased[prefix[len(dir)+1:]] = true
		}
	}
	return rebased
}

func (m maskFS) Open(name string) (fs.File, error) {
	if err := m.admit(name); err != nil {
		return nil, err
	}
	return m.parent.Open(name)
}

func (m maskFS) Stat(name string) (fs.FileInfo, error) {
	if err := m.admit(name); err != nil {
		return nil, err
	}
	return fs.Stat(m.parent, name)
}

func (m maskFS) ReadFile(name string) ([]byte, error) {
	if err := m.admit(name); err != nil {
		return nil, err
	}
	return fs.ReadFile(m.parent, name)
}

func (m maskFS) Lstat(name string) (fs.FileInfo, error) {
	if err := m.admit(name); err != nil {
		return nil, err
	}
	return fs.Lstat(m.parent, name)
}

func (m maskFS) ReadLink(name string) (string, error) {
	if err := m.admit(name); err != nil {
		return "", err
	}
	return fs.ReadLink(m.parent, name)
}

func (m maskFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := m.admit(name); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(m.parent, name)
	if err != nil {
		return nil, err
	}
	filtered := make([]fs.DirEntry, 0, len(entries))
	for _, e := range entries {
		if m.admits(path.Join(name, e.Name())) {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

func (m maskFS) Glob(pattern string) ([]string, error) {
	if !fs.ValidPath(pattern) {
		return nil, &fs.PathError{Op: "glob", Path: pattern, Err: fs.ErrInvalid}
	}
	first, _, _ := strings.Cut(pattern, "/")
	if !strings.ContainsAny(first, "*?[") && !m.admits(first) {
		return nil, nil
	}
	all, err := fs.Glob(m.parent, pattern)
	if err != nil {
		return nil, err
	}
	filtered := make([]string, 0, len(all))
	for _, name := range all {
		if m.admit(name) == nil {
			filtered = append(filtered, name)
		}
	}
	return filtered, nil
}

// Sub keeps the mask on the subtree it hands back: the parent's raw subtree
// would let a caller read exactly the siblings an ancestor is admitted only
// as a waypoint to. Below a declared prefix a mask could deny nothing.
func (m maskFS) Sub(dir string) (fs.FS, error) {
	if err := m.admit(dir); err != nil {
		return nil, err
	}
	sub, ok := m.parent.(fs.SubFS)
	if !ok {
		return nil, &fs.PathError{Op: "sub", Path: dir, Err: errors.ErrUnsupported}
	}
	child, err := sub.Sub(dir)
	if err != nil || m.covers(dir) {
		return child, err
	}
	if dir == "." {
		return maskFS{parent: child, allow: m.allow}, nil
	}
	return maskFS{parent: child, allow: m.rebase(dir)}, nil
}
