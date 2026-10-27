package agentaudit_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

type countingFS struct {
	m        fstest.MapFS
	calls    []string
	cancelAt int
	cancel   context.CancelFunc
}

func (c *countingFS) count(op, name string) {
	c.calls = append(c.calls, op+" "+name)
	if len(c.calls) == c.cancelAt {
		c.cancel()
	}
}

func (c *countingFS) Open(name string) (fs.File, error) {
	c.count("open", name)
	return c.m.Open(name)
}

func (c *countingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	c.count("readdir", name)
	return c.m.ReadDir(name)
}

func (c *countingFS) ReadFile(name string) ([]byte, error) {
	c.count("readfile", name)
	return c.m.ReadFile(name)
}

type countingStatFS struct{ *countingFS }

func (c countingStatFS) Stat(name string) (fs.FileInfo, error) {
	c.count("stat", name)
	return c.m.Stat(name)
}

type countingLinkFS struct{ *countingFS }

func (c countingLinkFS) Lstat(name string) (fs.FileInfo, error) {
	c.count("lstat", name)
	return c.m.Lstat(name)
}

func (c countingLinkFS) ReadLink(name string) (string, error) {
	c.count("readlink", name)
	return c.m.ReadLink(name)
}

type countingStatLinkFS struct{ *countingFS }

func (c countingStatLinkFS) Stat(name string) (fs.FileInfo, error) {
	return countingStatFS(c).Stat(name)
}

func (c countingStatLinkFS) Lstat(name string) (fs.FileInfo, error) {
	return countingLinkFS(c).Lstat(name)
}

func (c countingStatLinkFS) ReadLink(name string) (string, error) {
	return countingLinkFS(c).ReadLink(name)
}

var countingVariants = []struct {
	name string
	wrap func(*countingFS) fs.FS
}{
	{"neither", func(c *countingFS) fs.FS { return c }},
	{"StatFS", func(c *countingFS) fs.FS { return countingStatFS{c} }},
	{"ReadLinkFS", func(c *countingFS) fs.FS { return countingLinkFS{c} }},
	{"StatFS and ReadLinkFS", func(c *countingFS) fs.FS { return countingStatLinkFS{c} }},
}

func implements[T any](fsys fs.FS) bool {
	_, ok := fsys.(T)
	return ok
}

func TestScanContextFailsADoneContextBeforeAnyCall(t *testing.T) {
	for _, v := range countingVariants {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			c := &countingFS{m: hookScanFS()}

			rep, err := agentaudit.New().ScanContext(ctx, v.wrap(c))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ScanContext() error = %v, want context.Canceled", err)
			}
			if !reflect.DeepEqual(rep, finding.Report{}) {
				t.Errorf("ScanContext() report = %+v, want the zero Report", rep)
			}
			if len(c.calls) != 0 {
				t.Errorf("inner FS saw %q, want no call", c.calls)
			}
		})
	}
}

func TestScanContextScansThroughALiveContext(t *testing.T) {
	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, v := range countingVariants {
		for _, tc := range []struct {
			name string
			ctx  context.Context
		}{
			{"background", context.Background()},
			{"cancellable", live},
		} {
			t.Run(v.name+"/"+tc.name, func(t *testing.T) {
				c := &countingFS{m: hookScanFS()}

				rep, err := agentaudit.New().ScanContext(tc.ctx, v.wrap(c))
				if err != nil {
					t.Fatalf("ScanContext() error = %v, want nil", err)
				}
				if !rep.HasFindings() {
					t.Errorf("ScanContext() found nothing in %v", hookScanFS())
				}
				if len(c.calls) == 0 {
					t.Error("inner FS saw no calls")
				}
			})
		}
	}
}

// The malformed .mcp.json gives the scan a warning of its own to withhold.
func TestScanContextDiscardsAScanCancelledAtAnyCall(t *testing.T) {
	tree := hookScanFS()
	tree[".mcp.json"] = &fstest.MapFile{Data: []byte("{")}
	for _, v := range countingVariants {
		t.Run(v.name, func(t *testing.T) {
			live, cancel := context.WithCancel(context.Background())
			defer cancel()
			var liveWarnings []error
			full := &countingFS{m: tree}
			s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { liveWarnings = append(liveWarnings, w) }))
			rep, err := s.ScanContext(live, v.wrap(full))
			if err != nil || !rep.HasFindings() {
				t.Fatalf("uncancelled ScanContext() = %+v, %v, want the hook found", rep, err)
			}
			if len(liveWarnings) == 0 {
				t.Fatal("uncancelled ScanContext() warned nothing about the malformed .mcp.json")
			}

			total := len(full.calls)
			for n := 1; n <= total; n++ {
				ctx, stop := context.WithCancel(context.Background())
				c := &countingFS{m: tree, cancelAt: n, cancel: stop}
				var late []error
				s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) {
					if ctx.Err() != nil {
						late = append(late, w)
					}
				}))

				rep, err := s.ScanContext(ctx, v.wrap(c))
				stop()
				if !errors.Is(err, context.Canceled) {
					t.Errorf("cancel at call %d of %d: error = %v, want context.Canceled", n, total, err)
				}
				if !reflect.DeepEqual(rep, finding.Report{}) {
					t.Errorf("cancel at call %d of %d: report = %+v, want the zero Report", n, total, rep)
				}
				if len(c.calls) != n {
					t.Errorf("cancel at call %d of %d: inner FS saw %q", n, total, c.calls)
				}
				if len(late) != 0 {
					t.Errorf("cancel at call %d of %d: warned %v after the cancel", n, total, late)
				}
			}
		})
	}
}

type endWatchAdapter struct {
	cancel context.CancelFunc
	seen   *[]error
}

func (endWatchAdapter) Agent() adapter.AgentID { return adapter.AgentID("end-watch") }

func (endWatchAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{{Dir: ".watch", File: "config.json"}}
}

func (a endWatchAdapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	*a.seen = append(*a.seen, limits.Ended(fsys))
	a.cancel()
	*a.seen = append(*a.seen, limits.Ended(fsys))
	return nil, nil, nil
}

// An adapter sees its ScanContext end through the fsys its parse is handed,
// with or without an entity budget bound around that fsys.
func TestScanContextEndReachesTheAdapterParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []agentaudit.Option
	}{
		{"default entity budget", nil},
		{"no entity budget", []agentaudit.Option{agentaudit.WithMaxEntities(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var seen []error
			s := agentaudit.New(append(tc.opts, agentaudit.WithAdapters(endWatchAdapter{cancel: cancel, seen: &seen}))...)

			_, err := s.ScanContext(ctx, fstest.MapFS{".watch/config.json": {Data: []byte("{}")}})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("ScanContext() error = %v, want context.Canceled", err)
			}
			if want := []error{nil, context.Canceled}; !reflect.DeepEqual(seen, want) {
				t.Errorf("Parse saw limits.Ended() = %v before and after the cancel, want %v", seen, want)
			}
		})
	}
}

var errClaimedEnd = errors.New("the scanned FS's own end")

type scanErrClaimFS struct{ *countingFS }

func (scanErrClaimFS) ScanErr() error { return errClaimedEnd }

type scanEndErrClaimFS struct{ *countingFS }

func (scanEndErrClaimFS) ScanEnd() error { return errClaimedEnd }

type scanEndStructClaimFS struct{ *countingFS }

func (scanEndStructClaimFS) ScanEnd() struct{ Err error } { return struct{ Err error }{errClaimedEnd} }

type limitsEndClaimFS struct{ *countingFS }

func (limitsEndClaimFS) ScanEnd() limits.End { return limits.End{Err: errClaimedEnd} }

// A scanned fs.FS claiming its scan has ended, through a method a package
// outside agentaudit's import path can write, is scanned exactly as the same
// tree making no claim; the same claim made through limits.End changes what
// the scan reports.
func TestScanIgnoresAnEndClaimAnOutsidePackageCanWrite(t *testing.T) {
	tree := fstest.MapFS{
		".claude/skills/demo/SKILL.md":       {Data: []byte("---\nname: demo\n---\nRun scripts/run.sh\n")},
		".claude/skills/demo/scripts/run.sh": {Data: []byte("#!/bin/sh")},
	}
	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	claims := []struct {
		method string
		wrap   func(*countingFS) fs.FS
	}{
		{"ScanErr() error", func(c *countingFS) fs.FS { return scanErrClaimFS{c} }},
		{"ScanEnd() error", func(c *countingFS) fs.FS { return scanEndErrClaimFS{c} }},
		{"ScanEnd() struct{ Err error }", func(c *countingFS) fs.FS { return scanEndStructClaimFS{c} }},
	}

	for _, tc := range []struct {
		name string
		scan func(fs.FS) (agentaudit.Report, error)
	}{
		{"Scan", agentaudit.New().Scan},
		{"ScanContext", func(fsys fs.FS) (agentaudit.Report, error) { return agentaudit.New().ScanContext(live, fsys) }},
		{"Scan with every limit off", agentaudit.New(agentaudit.WithMaxFileSize(0), agentaudit.WithMaxReadBytes(0), agentaudit.WithMaxEntities(0)).Scan},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tc.scan(&countingFS{m: tree})
			if err != nil || !want.HasFindings() {
				t.Fatalf("scan of the tree = %+v, %v, want its payload found", want, err)
			}
			for _, claim := range claims {
				got, err := tc.scan(claim.wrap(&countingFS{m: tree}))
				if err != nil {
					t.Fatalf("scan of the tree claiming its end through %s error = %v, want nil", claim.method, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("scan of the tree claiming its end through %s = %+v, want %+v", claim.method, got, want)
				}
			}
			if got, _ := tc.scan(limitsEndClaimFS{&countingFS{m: tree}}); reflect.DeepEqual(got, want) {
				t.Errorf("scan of the tree reporting its end through limits.End = %+v, want it to differ from %+v", got, want)
			}
		})
	}
}

func TestBoundFailsEachMethodOnADoneContextWithoutTheInnerFS(t *testing.T) {
	tree := fstest.MapFS{
		"f": &fstest.MapFile{Data: []byte("x")},
		"l": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("f")},
	}
	methods := []struct {
		name string
		call func(fs.FS) error
	}{
		{"Open", func(f fs.FS) error {
			file, err := f.Open("f")
			if err == nil {
				file.Close()
			}
			return err
		}},
		{"ReadDir", func(f fs.FS) error { _, err := f.(fs.ReadDirFS).ReadDir("."); return err }},
		{"ReadFile", func(f fs.FS) error { _, err := f.(fs.ReadFileFS).ReadFile("f"); return err }},
		{"Stat", func(f fs.FS) error { _, err := f.(fs.StatFS).Stat("f"); return err }},
		{"Lstat", func(f fs.FS) error { _, err := f.(fs.ReadLinkFS).Lstat("l"); return err }},
		{"ReadLink", func(f fs.FS) error { _, err := f.(fs.ReadLinkFS).ReadLink("l"); return err }},
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	live, stop := context.WithCancel(context.Background())
	defer stop()

	for _, limit := range []int64{0, maxFileSize} {
		for _, m := range methods {
			t.Run(fmt.Sprintf("%s/cap %d", m.name, limit), func(t *testing.T) {
				c := &countingFS{m: tree}
				if err := m.call(agentaudit.Bound(live, countingStatLinkFS{c}, limit)); err != nil || len(c.calls) != 1 {
					t.Fatalf("live ctx: error = %v, inner FS saw %q, want nil and one call", err, c.calls)
				}

				c = &countingFS{m: tree}
				err := m.call(agentaudit.Bound(done, countingStatLinkFS{c}, limit))
				var pathErr *fs.PathError
				if !errors.As(err, &pathErr) || !errors.Is(err, context.Canceled) {
					t.Errorf("done ctx: error = %#v, want a *fs.PathError wrapping context.Canceled", err)
				}
				if len(c.calls) != 0 {
					t.Errorf("done ctx: inner FS saw %q, want no call", c.calls)
				}
			})
		}
	}
}

func TestScanContextReportsAPassedDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	rep, err := agentaudit.New().ScanContext(ctx, hookScanFS())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ScanContext() error = %v, want context.DeadlineExceeded", err)
	}
	if !reflect.DeepEqual(rep, finding.Report{}) {
		t.Errorf("ScanContext() report = %+v, want the zero Report", rep)
	}
}

func TestBoundOffersStatAndLinkOnlyWhereTheInnerFSDoes(t *testing.T) {
	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, v := range countingVariants {
		t.Run(v.name, func(t *testing.T) {
			inner := v.wrap(&countingFS{})
			for _, limit := range []int64{0, -1} {
				if got := agentaudit.Bound(context.Background(), inner, limit); got != inner {
					t.Errorf("Bound(background, %d) = %T, want the inner FS itself", limit, got)
				}
			}

			got := agentaudit.Bound(live, inner, 0)
			if got == inner {
				t.Fatal("Bound() with a cancellable ctx returned the inner FS unwrapped")
			}
			for _, iface := range []struct {
				name      string
				has, want bool
			}{
				{"fs.StatFS", implements[fs.StatFS](got), implements[fs.StatFS](inner)},
				{"fs.ReadLinkFS", implements[fs.ReadLinkFS](got), implements[fs.ReadLinkFS](inner)},
				{"fs.ReadDirFS", implements[fs.ReadDirFS](got), true},
				{"fs.ReadFileFS", implements[fs.ReadFileFS](got), true},
				{"fs.SubFS", implements[fs.SubFS](got), false},
				{"fs.GlobFS", implements[fs.GlobFS](got), false},
			} {
				if iface.has != iface.want {
					t.Errorf("Bound() result implements %s = %v, want %v", iface.name, iface.has, iface.want)
				}
			}
		})
	}
}

// A live ctx leaves the calls, the warnings and the report as Scan makes
// them; the links are where a mismatched method set would show.
func TestScanContextWithALiveContextMakesTheCallsScanMakes(t *testing.T) {
	linked := fstest.MapFS{
		".claude/fifo":                &fstest.MapFile{Mode: fs.ModeNamedPipe},
		".claude/settings.json":       &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("fifo")},
		".claude/real.json":           &fstest.MapFile{Data: []byte(validStubSettings)},
		".claude/settings.local.json": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("real.json")},
	}
	live, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, v := range countingVariants {
		t.Run(v.name, func(t *testing.T) {
			scan := func(ctx context.Context) (finding.Report, []string, []string) {
				var warnings []string
				s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))
				c := &countingFS{m: linked}
				rep, err := s.ScanContext(ctx, v.wrap(c))
				if err != nil {
					t.Fatalf("ScanContext() error = %v, want nil", err)
				}
				return rep, warnings, c.calls
			}
			bare, bareWarnings, bareCalls := scan(context.Background())
			wrapped, wrappedWarnings, wrappedCalls := scan(live)

			refused := func(w string) bool { return strings.Contains(w, "not a regular file") }
			if !slices.ContainsFunc(bareWarnings, refused) {
				t.Fatalf("unwrapped warnings = %q, want the FIFO link refused", bareWarnings)
			}
			if !reflect.DeepEqual(wrappedCalls, bareCalls) {
				t.Errorf("wrapped calls = %q, want %q", wrappedCalls, bareCalls)
			}
			if !reflect.DeepEqual(wrappedWarnings, bareWarnings) {
				t.Errorf("wrapped warnings = %q, want %q", wrappedWarnings, bareWarnings)
			}
			if !reflect.DeepEqual(wrapped, bare) {
				t.Errorf("wrapped report = %+v, want %+v", wrapped, bare)
			}
		})
	}
}
