// Package treefs holds a repository tree in memory as an fs.FS: every path
// of a listing, and whichever blobs have arrived. Before Seal, an unheld
// file reads as empty and an unheld link as absent, and either path is
// recorded for Missing; after Seal both fail, so a scan counts the path as
// unreadable rather than absent.
//
// Symlinks resolve inside the tree with os.Root's hop budget: a resolution
// that follows more than 8 links fails, as does one through a target that
// is absolute or leaves the tree.
//
// A source that already holds every blob calls New, then Seal, then scans,
// skipping agentaudit's Scanner.Select.
package treefs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// Entry is one path of a tree listing.
type Entry struct {
	Path string
	Mode fs.FileMode
}

type node struct {
	mode     fs.FileMode
	path     string
	children []string
}

type edge struct {
	dir  *node
	name string
}

// FS serves a tree listing, reading each file's content and each symlink's
// target through the blob function New was given.
type FS struct {
	root *node
	kids map[edge]*node
	blob func(path string) ([]byte, bool)

	mu      sync.Mutex
	missing map[string]struct{}
	sealed  bool
}

var _ interface {
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
	fs.ReadLinkFS
} = (*FS)(nil)

// New builds a tree from entries, implying parent directories, and refuses
// an invalid, duplicate or conflicting entry. blob returns false if unheld.
func New(entries []Entry, blob func(path string) ([]byte, bool)) (*FS, error) {
	t := &FS{
		root:    &node{mode: fs.ModeDir | 0o755, path: "."},
		kids:    make(map[edge]*node, len(entries)),
		blob:    blob,
		missing: map[string]struct{}{},
	}
	nodes := map[string]*node{".": t.root}
	listed := make(map[string]bool, len(entries))
	for _, e := range entries {
		if len(e.Path) > maxPath {
			return nil, fmt.Errorf("treefs: path %q... is %d bytes, over %d", e.Path[:32], len(e.Path), maxPath)
		}
		if e.Path == "." || strings.IndexByte(e.Path, 0) >= 0 || !fs.ValidPath(e.Path) {
			return nil, fmt.Errorf("treefs: invalid path %q", e.Path)
		}
		if bits.OnesCount32(uint32(e.Mode&fs.ModeType)) > 1 {
			return nil, fmt.Errorf("treefs: %q has an unsupported file type (%v)", e.Path, e.Mode)
		}
		if listed[e.Path] {
			return nil, fmt.Errorf("treefs: duplicate path %q", e.Path)
		}
		listed[e.Path] = true
		if implied, ok := nodes[e.Path]; ok {
			if !e.Mode.IsDir() {
				return nil, fmt.Errorf("treefs: %q is not a directory but has entries below it", e.Path)
			}
			implied.mode = e.Mode
			continue
		}
		child := &node{mode: e.Mode, path: e.Path}
		nodes[e.Path] = child
		for {
			dir, name := ".", child.path
			if i := strings.LastIndexByte(child.path, '/'); i >= 0 {
				dir, name = child.path[:i], child.path[i+1:]
			}
			parent, ok := nodes[dir]
			if !ok {
				parent = &node{mode: fs.ModeDir | 0o755, path: dir}
				nodes[dir] = parent
			} else if !parent.mode.IsDir() {
				return nil, fmt.Errorf("treefs: %q is not a directory but has entries below it", dir)
			}
			parent.children = append(parent.children, name)
			t.kids[edge{parent, name}] = child
			if ok {
				break
			}
			child = parent
		}
	}
	for _, n := range nodes {
		slices.Sort(n.children)
	}
	return t, nil
}

// Seal makes a later read of a blob the tree does not hold fail.
func (t *FS) Seal() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sealed = true
}

// Missing returns, sorted, the paths of the unheld blobs read since the
// previous call, and forgets them.
func (t *FS) Missing() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.missing))
	for p := range t.missing {
		out = append(out, p)
	}
	slices.Sort(out)
	clear(t.missing)
	return out
}

func (t *FS) need(p string) (sealed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.missing[p] = struct{}{}
	return t.sealed
}

func (t *FS) unheld(p string) error {
	if t.need(p) {
		return errWithheld
	}
	return fs.ErrNotExist
}

const (
	maxSymlinks = 8
	maxSteps    = 255
	maxRestarts = 8
	maxPath     = 4095
)

func (t *FS) resolve(op, name string, follow bool) (string, *node, error) {
	fail := func(err error) (string, *node, error) {
		return "", nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	if !fs.ValidPath(name) || strings.IndexByte(name, 0) >= 0 {
		return fail(fs.ErrInvalid)
	}
	resolved := []*node{t.root}
	pending := strings.Split(name, "/")
	links, steps, restarts := 0, 0, 0
	overBudget := func(n int) bool {
		steps += n
		return steps > maxSteps && restarts > maxRestarts
	}
	for len(pending) > 0 {
		seg := pending[0]
		pending = pending[1:]
		switch {
		case seg == "" || seg == "." && !onlySlashes(pending):
			continue
		case seg == ".":
			if overBudget(1) {
				return fail(errNameTooLong)
			}
			continue
		case seg == "..":
			if overBudget(1) {
				return fail(errNameTooLong)
			}
			restarts++
			up := 1
			for len(pending) > 0 && (pending[0] == ".." || pending[0] == "" || pending[0] == "." && !onlySlashes(pending[1:])) {
				if pending[0] == ".." {
					up++
				}
				pending = pending[1:]
			}
			if up >= len(resolved) {
				return fail(errEscapes)
			}
			resolved = resolved[:len(resolved)-up]
			// os.Root restarts from the root after .., re-walking the prefix.
			rewalk := len(resolved) - 1
			if rewalk == 0 && onlySlashes(pending) {
				rewalk = 1
			}
			if overBudget(rewalk) {
				return fail(errNameTooLong)
			}
			continue
		}
		if overBudget(1) {
			return fail(errNameTooLong)
		}
		n, ok := t.kids[edge{resolved[len(resolved)-1], seg}]
		if !ok {
			return fail(fs.ErrNotExist)
		}
		last := len(pending) == 0
		if n.mode&fs.ModeSymlink != 0 && (follow || !last) {
			target, ok := t.blob(n.path)
			if !ok {
				return fail(t.unheld(n.path))
			}
			links++
			if links > maxSymlinks {
				return fail(errTooManyLinks)
			}
			if len(target) > maxPath {
				return fail(errNameTooLong)
			}
			if len(target) == 0 || bytes.IndexByte(target, 0) >= 0 {
				return fail(fs.ErrInvalid)
			}
			if path.IsAbs(string(target)) {
				return fail(errEscapes)
			}
			pending = append(strings.Split(string(target), "/"), pending...)
			continue
		}
		if !last && !n.mode.IsDir() {
			return fail(errNotDir)
		}
		resolved = append(resolved, n)
	}
	n := resolved[len(resolved)-1]
	return n.path, n, nil
}

func onlySlashes(segs []string) bool {
	for _, s := range segs {
		if s != "" {
			return false
		}
	}
	return true
}

func (t *FS) Open(name string) (fs.File, error) {
	canon, n, err := t.resolve("open", name, true)
	if err != nil {
		return nil, err
	}
	info := fileInfo{name: path.Base(name), n: n}
	if n.mode.IsDir() {
		return &dirFile{t: t, canon: canon, info: info}, nil
	}
	data, ok := t.blob(canon)
	if !ok && t.need(canon) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errWithheld}
	}
	info.size = int64(len(data))
	return &file{info: info, r: bytes.NewReader(data)}, nil
}

func (t *FS) ReadFile(name string) ([]byte, error) {
	f, err := t.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, isDir := f.(*dirFile); isDir {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errIsDir}
	}
	return io.ReadAll(f)
}

func (t *FS) Stat(name string) (fs.FileInfo, error) {
	_, n, err := t.resolve("stat", name, true)
	if err != nil {
		return nil, err
	}
	return fileInfo{name: path.Base(name), n: n}, nil
}

func (t *FS) Lstat(name string) (fs.FileInfo, error) {
	_, n, err := t.resolve("lstat", name, false)
	if err != nil {
		return nil, err
	}
	return fileInfo{name: path.Base(name), n: n}, nil
}

func (t *FS) ReadLink(name string) (string, error) {
	canon, n, err := t.resolve("readlink", name, false)
	if err != nil {
		return "", err
	}
	if n.mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	target, ok := t.blob(canon)
	if !ok {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: t.unheld(canon)}
	}
	return string(target), nil
}

func (t *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	_, n, err := t.resolve("readdir", name, true)
	if err != nil {
		return nil, err
	}
	if !n.mode.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errNotDir}
	}
	return t.entries(n), nil
}

func (t *FS) entries(n *node) []fs.DirEntry {
	out := make([]fs.DirEntry, len(n.children))
	for i, c := range n.children {
		out[i] = fs.FileInfoToDirEntry(fileInfo{name: c, n: t.kids[edge{n, c}]})
	}
	return out
}

var (
	errEscapes      = errors.New("path escapes from the tree")
	errTooManyLinks = errors.New("too many levels of symbolic links")
	errNameTooLong  = errors.New("file name too long")
	errWithheld     = errors.New("blob withheld")
	errIsDir        = errors.New("is a directory")
	errNotDir       = errors.New("not a directory")
)

type fileInfo struct {
	name string
	n    *node
	size int64
}

func (fi fileInfo) Name() string       { return fi.name }
func (fi fileInfo) Size() int64        { return fi.size }
func (fi fileInfo) Mode() fs.FileMode  { return fi.n.mode }
func (fi fileInfo) ModTime() time.Time { return time.Time{} }
func (fi fileInfo) IsDir() bool        { return fi.n.mode.IsDir() }
func (fi fileInfo) Sys() any           { return nil }

type file struct {
	info fileInfo
	r    *bytes.Reader
}

func (f *file) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *file) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *file) Close() error               { return nil }

type dirFile struct {
	t     *FS
	canon string
	info  fileInfo
	off   int
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.canon, Err: errIsDir}
}
func (d *dirFile) Close() error { return nil }

func (d *dirFile) ReadDir(count int) ([]fs.DirEntry, error) {
	all := d.t.entries(d.info.n)
	rest := all[d.off:]
	if count <= 0 {
		d.off = len(all)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	count = min(count, len(rest))
	d.off += count
	return rest[:count], nil
}
