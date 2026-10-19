package agentaudit_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const maxFileSize = 256

func padded(body string, size int) []byte {
	return []byte(body + strings.Repeat(" ", size-len(body)))
}

type zeroSizeFS struct {
	m fstest.MapFS
}

func (z zeroSizeFS) Open(name string) (fs.File, error) {
	f, err := z.m.Open(name)
	if err != nil {
		return nil, err
	}
	return zeroSizeFile{f}, nil
}

func (z zeroSizeFS) Stat(name string) (fs.FileInfo, error) {
	info, err := z.m.Stat(name)
	if err != nil {
		return nil, err
	}
	return zeroSizeInfo{info}, nil
}

func (z zeroSizeFS) ReadDir(name string) ([]fs.DirEntry, error) { return z.m.ReadDir(name) }

type zeroSizeFile struct{ fs.File }

func (f zeroSizeFile) Stat() (fs.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return zeroSizeInfo{info}, nil
}

type zeroSizeInfo struct{ fs.FileInfo }

func (zeroSizeInfo) Size() int64 { return 0 }

func TestWithMaxFileSizeRefusesAFileOnlyPastTheCap(t *testing.T) {
	mapTree := func(file string, data []byte) fs.FS {
		return fstest.MapFS{file: &fstest.MapFile{Data: data}}
	}
	zeroSizeTree := func(file string, data []byte) fs.FS {
		return zeroSizeFS{m: fstest.MapFS{file: &fstest.MapFile{Data: data}}}
	}
	scan := func(s *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) { return s.Scan(fsys) }
	scanGlobal := func(s *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) { return s.ScanGlobal(fsys) }
	scanRecursive := func(s *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) {
		reps, err := s.ScanRecursive(fsys)
		if err != nil {
			return finding.Report{}, err
		}
		for _, r := range reps {
			if r.Path == "proj" {
				return r.Report, nil
			}
		}
		return finding.Report{}, fmt.Errorf("no report for proj in %+v", reps)
	}
	hasHook := func(rep finding.Report) bool {
		return slices.ContainsFunc(rep.Findings(), func(f finding.Finding) bool {
			return f.RuleID == "claude.hook.command"
		})
	}
	pluginNamedCapped := func(rep finding.Report) bool {
		return slices.ContainsFunc(rep.Findings(), func(f finding.Finding) bool {
			p, ok := f.Capability.Entity.(ir.Plugin)
			return ok && p.Name == "capped"
		})
	}

	cases := []struct {
		name   string
		file   string
		warned string
		body   string
		tree   func(file string, data []byte) fs.FS
		scan   func(*agentaudit.Scanner, fs.FS) (finding.Report, error)
		parsed func(finding.Report) bool
	}{
		{"settings", ".claude/settings.json", ".claude/settings.json", validStubSettings, mapTree, scan, hasHook},
		{"plugin manifest", "vendored/.claude-plugin/plugin.json", "vendored/.claude-plugin/plugin.json", `{"name":"capped"}`, mapTree, scan, pluginNamedCapped},
		{"ScanRecursive", "proj/.claude/settings.json", ".claude/settings.json", validStubSettings, mapTree, scanRecursive, hasHook},
		{"ScanGlobal", ".claude/settings.json", ".claude/settings.json", validStubSettings, mapTree, scanGlobal, hasHook},
		{"Stat reports no size", ".claude/settings.json", ".claude/settings.json", validStubSettings, zeroSizeTree, scan, hasHook},
	}
	for _, tc := range cases {
		for _, size := range []int{maxFileSize, maxFileSize + 1} {
			t.Run(fmt.Sprintf("%s/%d bytes", tc.name, size), func(t *testing.T) {
				var warnings []string
				s := agentaudit.New(
					agentaudit.WithMaxFileSize(maxFileSize),
					agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
				)

				rep, err := tc.scan(s, tc.tree(tc.file, padded(tc.body, size)))
				if err != nil {
					t.Fatalf("scan error = %v, want nil", err)
				}
				over := size > maxFileSize
				if got := tc.parsed(rep); got == over {
					t.Errorf("%s parsed = %v, want %v (findings: %+v)", tc.file, got, !over, rep.Findings())
				}
				wantUnreadable := 0
				if over {
					wantUnreadable = 1
				}
				if got := rep.UnreadableSources(); got != wantUnreadable {
					t.Errorf("UnreadableSources() = %d, want %d (warnings: %q)", got, wantUnreadable, warnings)
				}
				named := slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, tc.warned) })
				if named != over {
					t.Errorf("a warning names %s = %v, want %v (warnings: %q)", tc.warned, named, over, warnings)
				}
			})
		}
	}
}

func TestWithMaxFileSizeAtZeroBelowOrTheInt64MaxScansAsUncapped(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json":   &fstest.MapFile{Data: padded(validStubSettings, 4*maxFileSize)},
		".claude/skills/demo/run": &fstest.MapFile{Data: padded("#!/bin/sh\n", 4*maxFileSize)},
	}
	want, err := agentaudit.New().Scan(fsys)
	if err != nil {
		t.Fatalf("uncapped Scan() error = %v", err)
	}
	for _, id := range []string{"claude.hook.command", "claude.payload.bundled-script"} {
		if !slices.ContainsFunc(want.Findings(), func(f finding.Finding) bool { return f.RuleID == id }) {
			t.Fatalf("uncapped Scan() has no %s finding: %+v", id, want.Findings())
		}
	}

	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, n := range []int64{0, -1, math.MaxInt64} {
		for _, tc := range []struct {
			name string
			ctx  context.Context
		}{
			{"background", context.Background()},
			{"cancellable", live},
		} {
			t.Run(fmt.Sprintf("%d/%s", n, tc.name), func(t *testing.T) {
				got, err := agentaudit.New(agentaudit.WithMaxFileSize(n)).ScanContext(tc.ctx, fsys)
				if err != nil {
					t.Fatalf("ScanContext() error = %v, want nil", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("ScanContext() = %+v, want the uncapped %+v", got, want)
				}
			})
		}
	}
}

func TestBoundFileStaysRefusedOnceOverTheCap(t *testing.T) {
	fsys := agentaudit.Bound(context.Background(), fstest.MapFS{
		"f": &fstest.MapFile{Data: padded("", maxFileSize+1)},
	}, maxFileSize)
	f, err := fsys.Open("f")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadAll() error = %v, want a *fs.PathError other than fs.ErrNotExist", err)
	}
	if len(data) != maxFileSize {
		t.Errorf("ReadAll() delivered %d bytes, want the %d under the cap", len(data), maxFileSize)
	}
	if n, err := f.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Errorf("Read() after the cap = %d, %v, want 0 and an error", n, err)
	}
}

// The cap counts the bytes a read takes, not the file's length, so a payload
// sniffed by its first bytes stays under a cap its sniff fits in.
func TestWithMaxFileSizeSniffsAnOverCapPayloadByItsFirstBytes(t *testing.T) {
	const payload = ".claude/skills/demo/run"
	fsys := fstest.MapFS{payload: &fstest.MapFile{Data: padded("#!/bin/sh\n", 4*maxFileSize)}}

	for _, tc := range []struct {
		limit int64
		read  bool
	}{
		{maxFileSize, true},
		{1, false},
	} {
		t.Run(fmt.Sprint(tc.limit), func(t *testing.T) {
			var warnings []string
			s := agentaudit.New(
				agentaudit.WithMaxFileSize(tc.limit),
				agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
			)

			rep, err := s.Scan(fsys)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			found := slices.ContainsFunc(rep.Findings(), func(f finding.Finding) bool {
				p, ok := f.Capability.Entity.(ir.BundledPayload)
				return ok && p.Path == payload
			})
			if found != tc.read {
				t.Errorf("finding for %s = %v, want %v (findings: %+v)", payload, found, tc.read, rep.Findings())
			}
			wantUnreadable := 0
			if !tc.read {
				wantUnreadable = 1
			}
			if got := rep.UnreadableSources(); got != wantUnreadable {
				t.Errorf("UnreadableSources() = %d, want %d (warnings: %q)", got, wantUnreadable, warnings)
			}
		})
	}
}

func TestBoundDirectoryStaysListableUnderTheCap(t *testing.T) {
	fsys := agentaudit.Bound(context.Background(), fstest.MapFS{"d/f": &fstest.MapFile{}}, maxFileSize)
	f, err := fsys.Open("d")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer f.Close()

	dir, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatalf("Open() of a directory = %T, want an fs.ReadDirFile", f)
	}
	entries, err := dir.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "f" {
		t.Errorf("ReadDir() = %v, %v, want the one entry f", entries, err)
	}
}
