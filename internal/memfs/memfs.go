// Package memfs builds a read-only io/fs.FS from a flat set of
// path-to-bytes pairs, for a host that has no filesystem of its own to open.
//
// A host declares files; the enclosing directories are synthesized here.
// fs.WalkDir descends a name its enclosing ReadDir reported as a directory,
// so an unsynthesized parent hides its whole subtree from the scan and the
// report reads as clean. Mode bits are not part of the input either: a file
// carries no type bit and no execute bit, and a synthesized directory carries
// fs.ModeDir.
package memfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"time"
)

// fs.ReadLinkFS is absent by construction: a flat path-to-bytes set declares
// no link for fs.ReadLink to resolve.
var _ interface {
	fs.StatFS
	fs.ReadDirFS
	fs.ReadFileFS
} = (*FS)(nil)

var (
	errNotDir = errors.New("not a directory")
	errIsDir  = errors.New("is a directory")
)

// FS is a read-only in-memory filesystem over one immutable set of files.
type FS struct {
	files map[string][]byte
	dirs  map[string][]string
}

// New builds an FS from files, keyed by slash-separated unrooted paths as
// fs.ValidPath defines them. It refuses the whole set rather than skipping an
// entry: a dropped path would contribute bytes no walk can reach, which the
// scan cannot tell from a tree that never held the file.
func New(files map[string][]byte) (*FS, error) {
	names := slices.Sorted(maps.Keys(files))

	fsys := &FS{files: make(map[string][]byte, len(files))}
	for _, name := range names {
		if !fs.ValidPath(name) || name == "." {
			return nil, fmt.Errorf("memfs: refusing %q: not an unrooted slash-separated path", name)
		}
		fsys.files[name] = files[name]
	}

	children := map[string]map[string]bool{".": {}}
	for _, name := range names {
		dir := "."
		for rest := name; ; {
			segment, tail, nested := strings.Cut(rest, "/")
			if children[dir] == nil {
				children[dir] = map[string]bool{}
			}
			children[dir][segment] = true
			if !nested {
				break
			}
			dir = path.Join(dir, segment)
			if _, conflict := fsys.files[dir]; conflict {
				return nil, fmt.Errorf("memfs: refusing %q: %q is both a file and a directory", name, dir)
			}
			rest = tail
		}
	}

	fsys.dirs = make(map[string][]string, len(children))
	for dir, set := range children {
		fsys.dirs[dir] = slices.Sorted(maps.Keys(set))
	}
	return fsys, nil
}

func (m *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := m.files[name]; ok {
		return &openFile{info: infoOf(name, len(data), false), reader: bytes.NewReader(data)}, nil
	}
	if children, ok := m.dirs[name]; ok {
		return &openDir{name: name, info: infoOf(name, 0, true), entries: m.entriesOf(name, children)}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (m *FS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := m.files[name]; ok {
		return infoOf(name, len(data), false), nil
	}
	if _, ok := m.dirs[name]; ok {
		return infoOf(name, 0, true), nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (m *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	children, ok := m.dirs[name]
	if !ok {
		if _, isFile := m.files[name]; isFile {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: errNotDir}
		}
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	return m.entriesOf(name, children), nil
}

// ReadFile returns a copy, so a caller writing to a result cannot change
// what a later read of the same name reports.
func (m *FS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrInvalid}
	}
	data, ok := m.files[name]
	if !ok {
		if _, isDir := m.dirs[name]; isDir {
			return nil, &fs.PathError{Op: "readfile", Path: name, Err: errIsDir}
		}
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrNotExist}
	}
	return bytes.Clone(data), nil
}

// entriesOf builds dir's entries in the sorted order fs.ReadDirFS promises;
// children is already sorted by New.
func (m *FS) entriesOf(dir string, children []string) []fs.DirEntry {
	entries := make([]fs.DirEntry, 0, len(children))
	for _, child := range children {
		full := path.Join(dir, child)
		if data, ok := m.files[full]; ok {
			entries = append(entries, fs.FileInfoToDirEntry(infoOf(full, len(data), false)))
			continue
		}
		entries = append(entries, fs.FileInfoToDirEntry(infoOf(full, 0, true)))
	}
	return entries
}

func infoOf(name string, size int, dir bool) fileInfo {
	return fileInfo{name: path.Base(name), size: int64(size), dir: dir}
}

type fileInfo struct {
	name string
	size int64
	dir  bool
}

func (i fileInfo) Name() string { return i.name }
func (i fileInfo) Size() int64  { return i.size }

func (i fileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}

func (i fileInfo) ModTime() time.Time { return time.Time{} }
func (i fileInfo) IsDir() bool        { return i.dir }
func (i fileInfo) Sys() any           { return nil }

type openFile struct {
	info   fileInfo
	reader *bytes.Reader
}

func (f *openFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *openFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *openFile) Close() error               { return nil }

type openDir struct {
	name    string
	info    fileInfo
	entries []fs.DirEntry
	offset  int
}

func (d *openDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *openDir) Close() error               { return nil }

func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errIsDir}
}

func (d *openDir) ReadDir(n int) ([]fs.DirEntry, error) {
	remaining := d.entries[d.offset:]
	if n <= 0 {
		d.offset = len(d.entries)
		return slices.Clone(remaining), nil
	}
	if len(remaining) == 0 {
		return nil, io.EOF
	}
	if n > len(remaining) {
		n = len(remaining)
	}
	d.offset += n
	return slices.Clone(remaining[:n]), nil
}
