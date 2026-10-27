package agentaudit

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/limits"
)

var (
	_ fs.ReadDirFS   = boundFS{}
	_ fs.ReadFileFS  = boundFS{}
	_ limits.Carrier = boundFS{}
	_ fs.StatFS      = boundStatFS{}
	_ fs.ReadLinkFS  = boundLinkFS{}
	_ fs.StatFS      = boundStatLinkFS{}
	_ fs.ReadLinkFS  = boundStatLinkFS{}
)

// WithMaxFileSize refuses a file once a read of it passes n bytes, counting
// it in UnreadableSources. New sets 512 KiB; n <= 0 sets no cap.
func WithMaxFileSize(n int64) Option {
	return func(s *Scanner) { s.maxFileSize = n }
}

// WithMaxReadBytes caps one scan call's total reads at n bytes, refusing every
// read past it as unreadable. New sets 64 MiB; n <= 0 sets no cap.
func WithMaxReadBytes(n int64) Option {
	return func(s *Scanner) { s.maxReadBytes = n }
}

// WithMaxEntities refuses, whole and as unparsed, a file that would take one
// adapter's parse past n items. New sets 10,000; n <= 0 sets no cap.
func WithMaxEntities(n int) Option {
	return func(s *Scanner) { s.maxEntities = n }
}

// ScanContext is Scan bounded by ctx: once ctx is done the scan fails with
// ctx.Err(), discards what it found and warns nothing more.
func (s *Scanner) ScanContext(ctx context.Context, fsys fs.FS) (finding.Report, error) {
	sink := s.liveSink(ctx)
	rep, err := s.scanFS(bound(ctx, fsys, s.maxFileSize, newReadBudget(s.maxReadBytes), nil, sink), sink, projectPass{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return finding.Report{}, ctxErr
	}
	return rep, err
}

func (s *Scanner) liveSink(ctx context.Context) *warnSink {
	warn := s.emitFunc()
	if warn == nil {
		return newWarnSink(nil)
	}
	return newWarnSink(func(w error) {
		if ctx.Err() == nil {
			warn(w)
		}
	})
}

// bound mirrors fsys's fs.StatFS and fs.ReadLinkFS: fsguard picks its arm by
// asserting them, so offering one fsys lacks changes what a link resolves to.
func bound(ctx context.Context, fsys fs.FS, limit int64, budget *readCap, entities *limits.Entities, sink *warnSink) fs.FS {
	if ctx.Done() == nil && limit <= 0 && budget == nil && entities == nil {
		return fsys
	}
	b := boundFS{ctx: ctx, fsys: fsys, limit: limit, budget: budget, entities: entities, sink: sink}
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

func newReadBudget(n int64) *readCap {
	if n <= 0 {
		return nil
	}
	return &readCap{max: n}
}

type boundFS struct {
	ctx      context.Context
	fsys     fs.FS
	limit    int64
	budget   *readCap
	entities *limits.Entities
	sink     *warnSink
}

func (b boundFS) EntityBudget() *limits.Entities { return b.entities }

func (b boundFS) ScanEnd() limits.End {
	if err := b.ctx.Err(); err != nil {
		return limits.End{Err: err}
	}
	return limits.End{Err: limits.Ended(b.fsys)}
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
	if err != nil || b.limit <= 0 && b.budget == nil {
		return f, err
	}
	c := &cappedFile{File: f, name: name, budget: b.budget, sink: b.sink}
	if b.limit > 0 {
		c.file = &readCap{max: b.limit}
	}
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
	if b.limit <= 0 && b.budget == nil {
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

type readCap struct {
	max, used int64
	spent     bool
}

type cappedFile struct {
	fs.File
	name   string
	file   *readCap
	budget *readCap
	sink   *warnSink
}

func (f *cappedFile) Read(p []byte) (int, error) {
	if err := f.refusal(); err != nil {
		return 0, err
	}
	room := f.room()
	if int64(len(p)) > room {
		p = p[:room+1]
	}
	n, err := f.File.Read(p)
	if int64(n) <= room {
		f.take(int64(n), false)
		return n, err
	}
	f.take(room, true)
	return int(room), f.refusal()
}

func (f *cappedFile) room() int64 {
	room := int64(math.MaxInt64)
	for _, c := range []*readCap{f.file, f.budget} {
		if c != nil {
			room = min(room, c.max-c.used)
		}
	}
	return room
}

func (f *cappedFile) take(n int64, over bool) {
	for _, c := range []*readCap{f.file, f.budget} {
		if c != nil {
			c.used += n
			c.spent = c.spent || over && c.used == c.max
		}
	}
}

func (f *cappedFile) refusal() error {
	switch {
	case f.budget != nil && f.budget.spent:
		err := &fs.PathError{Op: "read", Path: f.name, Err: limits.RefusalBy(limits.ErrReadBudget, fmt.Sprintf("past the scan's %s read budget; not scanned", byteSize(f.budget.max)))}
		// A reader may drop this error, and the refusal must still leave
		// the report incomplete.
		f.sink.source(adapter.Warning{File: f.name, Err: err}, fmt.Errorf("agentaudit: read budget: %s: %w", f.name, err))
		return err
	case f.file != nil && f.file.spent:
		return &fs.PathError{Op: "read", Path: f.name, Err: limits.RefusalBy(limits.ErrFileSize, fmt.Sprintf("over the %s limit for one file; not scanned", byteSize(f.file.max)))}
	}
	return nil
}

func byteSize(n int64) string {
	switch {
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

type cappedDirFile struct {
	*cappedFile
	dir fs.ReadDirFile
}

func (f cappedDirFile) ReadDir(n int) ([]fs.DirEntry, error) { return f.dir.ReadDir(n) }
