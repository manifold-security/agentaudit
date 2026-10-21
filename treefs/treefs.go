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
	"math"
	"math/bits"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Entry is one path of a tree listing.
type Entry struct {
	Path string
	Mode fs.FileMode
}

// Kid is one entry of a directory handed to Builder.Children.
type Kid struct {
	Name string
	Mode fs.FileMode
	// ID is the value FS's blob function receives for this entry.
	ID uint32
}

// node keeps a directory's entries at indexes kidStart to
// kidStart+kidCount, sorted by name; kidStart is zero until it has them,
// index zero being the root's.
type node struct {
	name     string
	mode     fs.FileMode
	id       uint32
	parent   int32
	kidStart int32
	kidCount int32
}

const (
	chunkBits = 12
	chunkSize = 1 << chunkBits
	arenaSize = 64 << 10
)

// FS serves a tree listing, reading each file's content and each symlink's
// target through the blob function it was built with.
type FS struct {
	chunks [][]node
	size   int32
	read   func(n *node) ([]byte, bool)

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

func (t *FS) at(i int) *node { return &t.chunks[i>>chunkBits][i&(chunkSize-1)] }

func (t *FS) count() int { return int(t.size) }

func (t *FS) add(n node) {
	if last := len(t.chunks) - 1; len(t.chunks[last]) == chunkSize {
		t.chunks = append(t.chunks, make([]node, 0, chunkSize))
	}
	last := &t.chunks[len(t.chunks)-1]
	*last = append(*last, n)
	t.size++
}

func (t *FS) lookup(dir *node, name string) (*node, bool) {
	lo, end := int(dir.kidStart), int(dir.kidStart)+int(dir.kidCount)
	for hi := end; lo < hi; {
		mid := lo + (hi-lo)/2
		if t.at(mid).name < name {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < end && t.at(lo).name == name {
		return t.at(lo), true
	}
	return nil, false
}

func (t *FS) pathOf(n *node) string {
	if n.parent < 0 {
		return "."
	}
	buf := make([]byte, t.pathLen(n))
	end := len(buf)
	for m := n; m.parent >= 0; m = t.at(int(m.parent)) {
		end -= copy(buf[end-len(m.name):end], m.name)
		if end > 0 {
			end--
			buf[end] = '/'
		}
	}
	return string(buf)
}

func (t *FS) pathLen(n *node) int {
	size := -1
	for m := n; m.parent >= 0; m = t.at(int(m.parent)) {
		size += len(m.name) + 1
	}
	return max(size, 0)
}

// Builder lays a tree out one directory at a time.
type Builder struct {
	t     *FS
	arena strings.Builder
}

// NewBuilder returns a Builder holding the root directory alone, at index 0.
func NewBuilder() *Builder {
	t := &FS{chunks: [][]node{make([]node, 0, chunkSize)}, missing: map[string]struct{}{}}
	t.add(node{name: ".", mode: fs.ModeDir | 0o755, parent: -1})
	return &Builder{t: t}
}

// Children gives the directory at index dir its entries, which must be
// sorted by name; kids[k] lands at index first+k.
func (b *Builder) Children(dir int, kids []Kid) (first int, err error) {
	t := b.t
	switch {
	case t == nil:
		return 0, errors.New("treefs: the layout has ended")
	case dir < 0 || dir >= t.count():
		return 0, fmt.Errorf("treefs: no entry at index %d", dir)
	case len(kids) > math.MaxInt32-t.count():
		return 0, fmt.Errorf("treefs: more than %d entries", math.MaxInt32)
	}
	d := t.at(dir)
	switch {
	case !d.mode.IsDir():
		return 0, fmt.Errorf("treefs: %q is not a directory but has entries below it", t.pathOf(d))
	case d.kidStart != 0:
		return 0, fmt.Errorf("treefs: %q already has its entries", t.pathOf(d))
	}
	prefix := 0
	if dir != 0 {
		prefix = t.pathLen(d) + 1
	}
	join := func(name string) string {
		if dir == 0 {
			return name
		}
		return t.pathOf(d) + "/" + name
	}
	for k, kid := range kids {
		if n := prefix + len(kid.Name); n > maxPath {
			p := join(kid.Name)
			return 0, fmt.Errorf("treefs: path %q... is %d bytes, over %d", p[:32], n, maxPath)
		}
		if kid.Name == "" || kid.Name == "." || kid.Name == ".." || strings.ContainsAny(kid.Name, "/\x00") || !utf8.ValidString(kid.Name) {
			return 0, fmt.Errorf("treefs: invalid path %q", join(kid.Name))
		}
		if bits.OnesCount32(uint32(kid.Mode&fs.ModeType)) > 1 {
			return 0, fmt.Errorf("treefs: %q has an unsupported file type (%v)", join(kid.Name), kid.Mode)
		}
		if k == 0 {
			continue
		}
		switch strings.Compare(kids[k-1].Name, kid.Name) {
		case 0:
			return 0, fmt.Errorf("treefs: duplicate path %q", join(kid.Name))
		case 1:
			return 0, fmt.Errorf("treefs: %q is not sorted by name", join(kid.Name))
		}
	}
	start := t.size
	for _, kid := range kids {
		t.add(node{name: b.intern(kid.Name), mode: kid.Mode, id: kid.ID, parent: int32(dir)})
	}
	d.kidStart, d.kidCount = start, t.size-start
	return int(start), nil
}

// intern copies name into the arena, so the caller's string, and whatever
// larger string holds it, is not kept alive.
func (b *Builder) intern(name string) string {
	if b.arena.Cap()-b.arena.Len() < len(name) {
		b.arena = strings.Builder{}
		b.arena.Grow(max(arenaSize, len(name)))
	}
	start := b.arena.Len()
	b.arena.WriteString(name)
	return b.arena.String()[start:]
}

// FS returns the tree and ends the layout, or nil once it has ended; blob
// returns false if the ID's blob is unheld.
func (b *Builder) FS(blob func(id uint32) ([]byte, bool)) *FS {
	t := b.end()
	if t == nil {
		return nil
	}
	t.read = func(n *node) ([]byte, bool) { return blob(n.id) }
	return t
}

func (b *Builder) end() *FS {
	t := b.t
	b.t = nil
	return t
}

type pathNode struct {
	mode     fs.FileMode
	path     string
	children []string
}

// New builds a tree from entries, implying parent directories, and refuses
// an invalid, duplicate or conflicting entry. blob returns false if unheld.
func New(entries []Entry, blob func(path string) ([]byte, bool)) (*FS, error) {
	root := &pathNode{mode: fs.ModeDir | 0o755, path: "."}
	nodes := map[string]*pathNode{".": root}
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
		child := &pathNode{mode: e.Mode, path: e.Path}
		nodes[e.Path] = child
		for {
			dir, name := ".", child.path
			if i := strings.LastIndexByte(child.path, '/'); i >= 0 {
				dir, name = child.path[:i], child.path[i+1:]
			}
			parent, ok := nodes[dir]
			if !ok {
				parent = &pathNode{mode: fs.ModeDir | 0o755, path: dir}
				nodes[dir] = parent
			} else if !parent.mode.IsDir() {
				return nil, fmt.Errorf("treefs: %q is not a directory but has entries below it", dir)
			}
			parent.children = append(parent.children, name)
			if ok {
				break
			}
			child = parent
		}
	}
	b := NewBuilder()
	type pending struct {
		at int
		n  *pathNode
	}
	queue := []pending{{0, root}}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		slices.Sort(dir.n.children)
		kids := make([]Kid, len(dir.n.children))
		below := make([]*pathNode, len(kids))
		for i, name := range dir.n.children {
			p := name
			if dir.n.path != "." {
				p = dir.n.path + "/" + name
			}
			below[i] = nodes[p]
			kids[i] = Kid{Name: name, Mode: below[i].mode}
		}
		first, err := b.Children(dir.at, kids)
		if err != nil {
			return nil, err
		}
		for i, kid := range kids {
			if kid.Mode.IsDir() {
				queue = append(queue, pending{first + i, below[i]})
			}
		}
	}
	t := b.end()
	t.read = func(n *node) ([]byte, bool) { return blob(t.pathOf(n)) }
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

func (t *FS) resolve(op, name string, follow bool) (*node, error) {
	fail := func(err error) (*node, error) {
		return nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	if !fs.ValidPath(name) || strings.IndexByte(name, 0) >= 0 {
		return fail(fs.ErrInvalid)
	}
	resolved := []*node{t.at(0)}
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
		n, ok := t.lookup(resolved[len(resolved)-1], seg)
		if !ok {
			return fail(fs.ErrNotExist)
		}
		last := len(pending) == 0
		if n.mode&fs.ModeSymlink != 0 && (follow || !last) {
			target, ok := t.read(n)
			if !ok {
				return fail(t.unheld(t.pathOf(n)))
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
	return resolved[len(resolved)-1], nil
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
	n, err := t.resolve("open", name, true)
	if err != nil {
		return nil, err
	}
	info := fileInfo{name: path.Base(name), n: n}
	if n.mode.IsDir() {
		return &dirFile{t: t, info: info}, nil
	}
	data, ok := t.read(n)
	if !ok && t.need(t.pathOf(n)) {
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
	n, err := t.resolve("stat", name, true)
	if err != nil {
		return nil, err
	}
	return fileInfo{name: path.Base(name), n: n}, nil
}

func (t *FS) Lstat(name string) (fs.FileInfo, error) {
	n, err := t.resolve("lstat", name, false)
	if err != nil {
		return nil, err
	}
	return fileInfo{name: path.Base(name), n: n}, nil
}

func (t *FS) ReadLink(name string) (string, error) {
	n, err := t.resolve("readlink", name, false)
	if err != nil {
		return "", err
	}
	if n.mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	target, ok := t.read(n)
	if !ok {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: t.unheld(t.pathOf(n))}
	}
	return string(target), nil
}

func (t *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	n, err := t.resolve("readdir", name, true)
	if err != nil {
		return nil, err
	}
	if !n.mode.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errNotDir}
	}
	return t.entries(n), nil
}

func (t *FS) entries(n *node) []fs.DirEntry {
	out := make([]fs.DirEntry, n.kidCount)
	for i := range out {
		c := t.at(int(n.kidStart) + i)
		out[i] = fs.FileInfoToDirEntry(fileInfo{name: c.name, n: c})
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
	t    *FS
	info fileInfo
	off  int
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.t.pathOf(d.info.n), Err: errIsDir}
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
