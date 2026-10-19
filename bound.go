package agentaudit

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/manifold-security/agentaudit/finding"
)

var (
	_ fs.ReadDirFS  = boundFS{}
	_ fs.ReadFileFS = boundFS{}
	_ fs.StatFS     = boundStatFS{}
	_ fs.ReadLinkFS = boundLinkFS{}
	_ fs.StatFS     = boundStatLinkFS{}
	_ fs.ReadLinkFS = boundStatLinkFS{}
)

// WithMaxFileSize makes a scan refuse a file once a read of it passes n
// bytes, counting the file in UnreadableSources; n <= 0 sets no cap.
func WithMaxFileSize(n int64) Option {
	return func(s *Scanner) { s.maxFileSize = n }
}

// ScanContext is Scan bounded by ctx: once ctx is done the scan fails with
// ctx.Err(), discards what it found and warns nothing more.
func (s *Scanner) ScanContext(ctx context.Context, fsys fs.FS) (finding.Report, error) {
	emit := s.emitFunc()
	sink := newWarnSink(func(w error) {
		if ctx.Err() == nil {
			emit(w)
		}
	})
	rep, err := s.scanFS(bound(ctx, fsys, s.maxFileSize), sink, projectPass{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return finding.Report{}, ctxErr
	}
	return rep, err
}

// bound mirrors fsys's fs.StatFS and fs.ReadLinkFS: fsguard picks its arm by
// asserting them, so offering one fsys lacks changes what a link resolves to.
func bound(ctx context.Context, fsys fs.FS, limit int64) fs.FS {
	if ctx.Done() == nil && limit <= 0 {
		return fsys
	}
	b := boundFS{ctx: ctx, fsys: fsys, limit: limit}
	_, stat := fsys.(fs.StatFS)
	_, link := fsys.(fs.ReadLinkFS)
	switch {
	case stat && link:
		return boundStatLinkFS{b}
	case stat:
		return boundStatFS{b}
	case link:
		return boundLinkFS{b}
	}
	return b
}

type boundFS struct {
	ctx   context.Context
	fsys  fs.FS
	limit int64
}

func (b boundFS) done(op, name string) error {
	if err := b.ctx.Err(); err != nil {
		return &fs.PathError{Op: op, Path: name, Err: err}
	}
	return nil
}

func (b boundFS) Open(name string) (fs.File, error) {
	if err := b.done("open", name); err != nil {
		return nil, err
	}
	f, err := b.fsys.Open(name)
	if err != nil || b.limit <= 0 {
		return f, err
	}
	c := &cappedFile{File: f, name: name, limit: b.limit}
	if dir, ok := f.(fs.ReadDirFile); ok {
		return cappedDirFile{c, dir}, nil
	}
	return c, nil
}

func (b boundFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := b.done("readdir", name); err != nil {
		return nil, err
	}
	return fs.ReadDir(b.fsys, name)
}

func (b boundFS) ReadFile(name string) ([]byte, error) {
	if b.limit <= 0 {
		if err := b.done("readfile", name); err != nil {
			return nil, err
		}
		return fs.ReadFile(b.fsys, name)
	}
	f, err := b.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (b boundFS) stat(name string) (fs.FileInfo, error) {
	if err := b.done("stat", name); err != nil {
		return nil, err
	}
	return fs.Stat(b.fsys, name)
}

func (b boundFS) lstat(name string) (fs.FileInfo, error) {
	if err := b.done("lstat", name); err != nil {
		return nil, err
	}
	return fs.Lstat(b.fsys, name)
}

func (b boundFS) readLink(name string) (string, error) {
	if err := b.done("readlink", name); err != nil {
		return "", err
	}
	return fs.ReadLink(b.fsys, name)
}

type boundStatFS struct{ boundFS }

func (b boundStatFS) Stat(name string) (fs.FileInfo, error) { return b.stat(name) }

type boundLinkFS struct{ boundFS }

func (b boundLinkFS) Lstat(name string) (fs.FileInfo, error) { return b.lstat(name) }

func (b boundLinkFS) ReadLink(name string) (string, error) { return b.readLink(name) }

type boundStatLinkFS struct{ boundFS }

func (b boundStatLinkFS) Stat(name string) (fs.FileInfo, error) { return b.stat(name) }

func (b boundStatLinkFS) Lstat(name string) (fs.FileInfo, error) { return b.lstat(name) }

func (b boundStatLinkFS) ReadLink(name string) (string, error) { return b.readLink(name) }

type cappedFile struct {
	fs.File
	name  string
	limit int64
	read  int64
}

func (f *cappedFile) Read(p []byte) (int, error) {
	if f.read > f.limit {
		return 0, f.overCap()
	}
	if room := f.limit - f.read; int64(len(p)) > room {
		p = p[:room+1]
	}
	n, err := f.File.Read(p)
	f.read += int64(n)
	if f.read > f.limit {
		return n - 1, f.overCap()
	}
	return n, err
}

func (f *cappedFile) overCap() error {
	return &fs.PathError{Op: "read", Path: f.name, Err: fmt.Errorf("larger than %d bytes", f.limit)}
}

type cappedDirFile struct {
	*cappedFile
	dir fs.ReadDirFile
}

func (f cappedDirFile) ReadDir(n int) ([]fs.DirEntry, error) { return f.dir.ReadDir(n) }
