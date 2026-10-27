package claude

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

func payloadEntitiesOK(t *testing.T, fsys fs.FS) []ir.BundledPayload {
	t.Helper()
	entities, warnings, err := payloadEntities(fsys)
	if err != nil {
		t.Fatalf("payloadEntities() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("payloadEntities() warnings = %+v, want none", warnings)
	}
	out := make([]ir.BundledPayload, 0, len(entities))
	for _, e := range entities {
		bp, ok := e.(ir.BundledPayload)
		if !ok {
			t.Fatalf("entity %T is not ir.BundledPayload", e)
		}
		out = append(out, bp)
	}
	return out
}

func TestPayloadEntities_ClassificationMatrix(t *testing.T) {
	tests := []struct {
		name           string
		fsys           fstest.MapFS
		wantPaths      []string
		wantExecutable string
		wantExtension  string
	}{
		{
			name:          ".sh sibling, not executable, still emits",
			fsys:          fstest.MapFS{".claude/skills/demo/scripts/validate.sh": {Data: []byte("#!/bin/sh")}},
			wantPaths:     []string{".claude/skills/demo/scripts/validate.sh"},
			wantExtension: ".sh",
		},
		{
			name:           "extension-less +x file emits, Executable true, Extension empty",
			fsys:           fstest.MapFS{".claude/skills/demo/scripts/tool": {Data: []byte("bin"), Mode: 0o755}},
			wantPaths:      []string{".claude/skills/demo/scripts/tool"},
			wantExecutable: "true",
		},
		{
			name: "+x README.md never emits",
			fsys: fstest.MapFS{".claude/skills/demo/README.md": {Data: []byte("# readme"), Mode: 0o755}},
		},
		{
			name: "+x SKILL.md is not a payload",
			fsys: fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: demo\n---"), Mode: 0o755}},
		},
		{
			name:          "README.sh not executable still emits via extension allow-list",
			fsys:          fstest.MapFS{".claude/skills/demo/README.sh": {Data: []byte("#!/bin/sh")}},
			wantPaths:     []string{".claude/skills/demo/README.sh"},
			wantExtension: ".sh",
		},
		{
			name: "requirements.txt not executable emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/requirements.txt": {Data: []byte("pyyaml")}},
		},
		{
			name:           "+x notes.txt emits — documented, accepted",
			fsys:           fstest.MapFS{".claude/skills/demo/notes.txt": {Data: []byte("todo"), Mode: 0o755}},
			wantPaths:      []string{".claude/skills/demo/notes.txt"},
			wantExecutable: "true",
			wantExtension:  ".txt",
		},
		{
			name:      "extension-less shebang file emits with no +x bit",
			fsys:      fstest.MapFS{".claude/skills/demo/scripts/tool": {Data: []byte("#!/bin/sh\necho hi\n")}},
			wantPaths: []string{".claude/skills/demo/scripts/tool"},
		},
		{
			name: "extension-less file with no shebang emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/tool": {Data: []byte("echo hi\n")}},
		},
		{
			name: "extension-less file shorter than the shebang prefix emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/tool": {Data: []byte("#")}},
		},
		{
			name: "extension-less empty file emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/tool": {Data: nil}},
		},
		{
			name: "shebang under an extension outside the allow-list emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/tool.rb": {Data: []byte("#!/usr/bin/env ruby\n")}},
		},
		{
			name:          "bare dotfile with a shebang emits with no +x bit",
			fsys:          fstest.MapFS{".claude/skills/demo/scripts/.setup": {Data: []byte("#!/bin/sh\n")}},
			wantPaths:     []string{".claude/skills/demo/scripts/.setup"},
			wantExtension: ".setup",
		},
		{
			name:          "upper-case bare dotfile reaches the sniff too",
			fsys:          fstest.MapFS{".claude/skills/demo/scripts/.SETUP": {Data: []byte("#!/bin/sh\n")}},
			wantPaths:     []string{".claude/skills/demo/scripts/.SETUP"},
			wantExtension: ".setup",
		},
		{
			name: "bare dotfile with no shebang emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/.env": {Data: []byte("TOKEN=x\n")}},
		},
		{
			name:           "dot-prefixed +x name emits through the executable arm",
			fsys:           fstest.MapFS{".claude/skills/demo/scripts/.bootstrap": {Data: []byte("#!/bin/sh\n"), Mode: 0o755}},
			wantPaths:      []string{".claude/skills/demo/scripts/.bootstrap"},
			wantExecutable: "true",
			wantExtension:  ".bootstrap",
		},
		{
			name:          "dot-prefixed name carrying an allow-listed extension emits",
			fsys:          fstest.MapFS{".claude/skills/demo/scripts/.hidden.sh": {Data: []byte("#!/bin/sh\n")}},
			wantPaths:     []string{".claude/skills/demo/scripts/.hidden.sh"},
			wantExtension: ".sh",
		},
		{
			name: "dot-prefixed name carrying an unknown extension emits nothing",
			fsys: fstest.MapFS{".claude/skills/demo/scripts/.hidden.txt": {Data: []byte("#!/bin/sh\n")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := payloadEntitiesOK(t, tt.fsys)
			if len(got) != len(tt.wantPaths) {
				t.Fatalf("entities = %+v, want paths %v", got, tt.wantPaths)
			}
			for i, wantPath := range tt.wantPaths {
				if got[i].Path != wantPath {
					t.Errorf("entity[%d].Path = %q, want %q", i, got[i].Path, wantPath)
				}
				if got[i].Referenced != "" {
					t.Errorf("entity[%d].Referenced = %q, want empty", i, got[i].Referenced)
				}
			}
			if len(tt.wantPaths) > 0 && got[0].Executable != tt.wantExecutable {
				t.Errorf("Executable = %q, want %q", got[0].Executable, tt.wantExecutable)
			}
			if len(tt.wantPaths) > 0 && got[0].Extension != tt.wantExtension {
				t.Errorf("Extension = %q, want %q", got[0].Extension, tt.wantExtension)
			}
		})
	}
}

// errInfoDirEntry is a synthetic fs.DirEntry whose Info() errors, which
// fstest.MapFS cannot itself produce.
type errInfoDirEntry struct{}

func (errInfoDirEntry) Name() string               { return "stub" }
func (errInfoDirEntry) IsDir() bool                { return false }
func (errInfoDirEntry) Type() fs.FileMode          { return 0 }
func (errInfoDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("stat failed") }

// A symlink whose extension IS in the payload allow-list must warn, so a
// symlinked script is refused and counted rather than silently dropped.
func TestPayloadEntities_SymlinkWithPayloadExtensionWarnsUnreadable(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/skills/demo/scripts/run.sh": {Data: []byte("target"), Mode: fs.ModeSymlink},
	}
	_, warnings, err := payloadEntities(fsys)
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one for the symlinked .sh payload", warnings)
	}
	if warnings[0].File != ".claude/skills/demo/scripts/run.sh" {
		t.Fatalf("warnings[0].File = %q, want the symlinked path", warnings[0].File)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warnings[0].Err = %v, want it to satisfy errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
	}
}

func TestPayloadEntities_SymlinkedMarkdownToAFileOrNothingEmitsNoWarning(t *testing.T) {
	tests := []struct {
		name string
		fsys fstest.MapFS
	}{
		{
			name: "the target is missing",
			fsys: fstest.MapFS{".claude/skills/demo/reference.md": {Data: []byte("target"), Mode: fs.ModeSymlink}},
		},
		{
			name: "the target is a regular file",
			fsys: fstest.MapFS{
				".claude/skills/demo/reference.md": {Data: []byte("../../../shared/reference.md"), Mode: fs.ModeSymlink},
				"shared/reference.md":              {Data: []byte("# notes\n")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, warnings, err := payloadEntities(tt.fsys)
			if err != nil {
				t.Fatalf("payloadEntities() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none for a symlinked Markdown file", warnings)
			}
		})
	}
}

// A Markdown link over a pipe stays as silent as the pipe.
func TestPayloadEntitiesLeaveAMarkdownLinkOverAPipeSilentWithoutOpening(t *testing.T) {
	const link = ".claude/skills/demo/notes.md"
	got := bounded(t, payloadEntities, blockingWalkFS{m: fstest.MapFS{
		link:   {Data: []byte("../../../pipe"), Mode: fs.ModeSymlink},
		"pipe": {Mode: fs.ModeNamedPipe},
	}})
	if len(got.entities) != 0 || len(got.warnings) != 0 {
		t.Fatalf("payloadEntities() = (%+v, %+v), want neither", got.entities, got.warnings)
	}
}

// failingOpenFS denies Open(failPath) while its parent directory still lists
// it, so a walk reaches an entry whose bytes it cannot read.
type failingOpenFS struct {
	m        fstest.MapFS
	failPath string
}

func (f failingOpenFS) Open(name string) (fs.File, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.m.Open(name)
}

func (f failingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// A candidate whose bytes the sniff cannot read is reported and counted
// rather than dropped, so a read fault does not resolve into a clean report.
func TestPayloadEntitiesUnreadableShebangCandidateWarnsUnreadable(t *testing.T) {
	const payloadPath = ".claude/commands/tool"
	fsys := failingOpenFS{
		m:        fstest.MapFS{payloadPath: &fstest.MapFile{Data: []byte("#!/bin/sh")}},
		failPath: payloadPath,
	}

	entities, warnings, err := payloadEntities(fsys)
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("payloadEntities() entities = %+v, want none for a candidate the sniff could not read", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one for the unreadable candidate", warnings)
	}
	if warnings[0].File != payloadPath {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, payloadPath)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Errorf("warnings[0].Err = %v, want it to satisfy errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
	}
	if !errors.Is(warnings[0].Err, fs.ErrPermission) {
		t.Errorf("warnings[0].Err = %v, want the underlying read fault still reachable", warnings[0].Err)
	}
}

type countingFile struct {
	fs.File
	read *int
}

func (f countingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	*f.read += n
	return n, err
}

type byteCountingFS struct {
	m    fstest.MapFS
	read *int
}

func (f byteCountingFS) Open(name string) (fs.File, error) {
	file, err := f.m.Open(name)
	if err != nil {
		return nil, err
	}
	return countingFile{File: file, read: f.read}, nil
}

func (f byteCountingFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// The sniff draws only the shebang prefix from the payload it classifies.
func TestPayloadEntitiesShebangSniffReadsOnlyThePrefix(t *testing.T) {
	var read int
	payload := append([]byte(shebangPrefix), bytes.Repeat([]byte("A"), 4096)...)
	fsys := byteCountingFS{
		m:    fstest.MapFS{".claude/commands/tool": &fstest.MapFile{Data: payload}},
		read: &read,
	}

	entities := payloadEntitiesOK(t, fsys)
	if len(entities) != 1 {
		t.Fatalf("payloadEntities() = %+v, want the shebang payload emitted", entities)
	}
	if read != len(shebangPrefix) {
		t.Errorf("sniff read %d bytes, want len(shebangPrefix) = %d", read, len(shebangPrefix))
	}
}

// blockingWalkFS lists its directories from the map while Open blocks,
// standing in for a named pipe with no writer.
type blockingWalkFS struct {
	m fstest.MapFS
}

func (f blockingWalkFS) Open(string) (fs.File, error) { select {} }

func (f blockingWalkFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f blockingWalkFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// The walk reaches a verdict on an irregular entry without opening it: this
// fixture turns any open into a deadline rather than an assertion.
func TestPayloadEntitiesFIFOIsClassifiedWithoutOpening(t *testing.T) {
	fsys := blockingWalkFS{m: fstest.MapFS{
		".claude/commands/tool": &fstest.MapFile{Mode: fs.ModeNamedPipe},
	}}

	type result struct {
		entities []ir.Entity
		warnings []adapter.Warning
	}
	done := make(chan result, 1)
	go func() {
		entities, warnings, _ := payloadEntities(fsys)
		done <- result{entities, warnings}
	}()

	select {
	case got := <-done:
		if len(got.entities) != 0 || len(got.warnings) != 0 {
			t.Fatalf("payloadEntities() = (%+v, %+v), want neither for an irregular entry outside the extension allow-list", got.entities, got.warnings)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("payloadEntities never returned; the sniff opened the pipe instead of reading its type bits")
	}
}

func TestExecutable_InfoErrorIsNotExecutable(t *testing.T) {
	if executable(errInfoDirEntry{}) {
		t.Fatal("executable() = true, want false when Info() errors")
	}
}

func TestPayloadEntities_DeterministicOrder(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/skills/b/scripts/z.sh": {Data: []byte("z")},
		".claude/skills/a/scripts/a.sh": {Data: []byte("a")},
		".claude/commands/tool":         {Data: []byte("bin"), Mode: 0o755},
		".claude/commands/deploy.sh":    {Data: []byte("d")},
	}
	want := []string{
		".claude/skills/a/scripts/a.sh", ".claude/skills/b/scripts/z.sh",
		".claude/commands/deploy.sh", ".claude/commands/tool",
	}

	got := payloadEntitiesOK(t, fsys)
	gotPaths := make([]string, len(got))
	for i, e := range got {
		gotPaths[i] = e.Path
	}
	if !reflect.DeepEqual(gotPaths, want) {
		t.Fatalf("payload paths = %v, want %v", gotPaths, want)
	}
}

// The surviving payload sits in a sibling subtree the walk had not yet
// reached, which is the arm an abort would take out.
func TestPayloadEntitiesUnreadableSubdirWarnsAndKeepsSiblings(t *testing.T) {
	fsys := failingReadDirFS{
		m: fstest.MapFS{
			".claude/skills/good/scripts/ok.sh": &fstest.MapFile{Data: []byte("#!/bin/sh")},
			".claude/skills/bad/scripts/x.sh":   &fstest.MapFile{Data: []byte("#!/bin/sh")},
		},
		failPath: ".claude/skills/bad/scripts",
	}

	entities, warnings, err := payloadEntities(fsys)
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil (a below-root failure must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("payloadEntities() warnings = none, want a warning for the unreadable bad/scripts directory")
	}

	var paths []string
	for _, e := range entities {
		bp, ok := e.(ir.BundledPayload)
		if !ok {
			t.Fatalf("entity %T is not ir.BundledPayload", e)
		}
		paths = append(paths, bp.Path)
	}
	if len(paths) != 1 || paths[0] != ".claude/skills/good/scripts/ok.sh" {
		t.Fatalf("payloadEntities() paths = %v, want exactly [.claude/skills/good/scripts/ok.sh] (the sibling must survive the unreadable directory)", paths)
	}
}

func TestPayloadEntities_MissingRootsYieldsNoEntities(t *testing.T) {
	entities, warnings, err := payloadEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("payloadEntities() error = %v", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("payloadEntities() = (%v, %v), want no entities or warnings", entities, warnings)
	}
}

func findPayload(t *testing.T, entities []ir.BundledPayload, p string) ir.BundledPayload {
	t.Helper()
	for _, e := range entities {
		if e.Path == p {
			return e
		}
	}
	t.Fatalf("no payload entity for %q in %+v", p, entities)
	return ir.BundledPayload{}
}

func TestReferenceCorrelator_Matrix(t *testing.T) {
	fm, x := "---\nname: demo\n---\n", ".claude/skills/demo/scripts/x.sh"
	tests := []struct {
		name             string
		fsys             fstest.MapFS
		payloadPath      string
		wantReferencedBy string // "" means want unreferenced
	}{
		{"body prose mention", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Run " + x + " now.\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"allowed-tools space-separated form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: demo\nallowed-tools: Bash(${CLAUDE_SKILL_DIR}/scripts/x.sh *)\n---\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"allowed-tools comma-separated form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: demo\nallowed-tools: Read, Bash(${CLAUDE_SKILL_DIR}/scripts/x.sh *)\n---\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"allowed-tools YAML-list form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: demo\nallowed-tools:\n  - Bash(${CLAUDE_SKILL_DIR}/scripts/x.sh *)\n---\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"${CLAUDE_PROJECT_DIR}/ form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "See ${CLAUDE_PROJECT_DIR}/" + x + "\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"unbraced $CLAUDE_SKILL_DIR form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Run $CLAUDE_SKILL_DIR/scripts/x.sh\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"owner-relative form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Run scripts/x.sh\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"./-relative form", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Run ./scripts/x.sh\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"dotted base name match", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "See x.sh for details.\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"extension-less base name NOT matched by bare word", fstest.MapFS{".claude/commands/deploy.md": {Data: []byte("---\nname: deploy\n---\nUse the tool now.\n")}, ".claude/commands/tool": {Data: []byte("bin"), Mode: 0o755}}, ".claude/commands/tool", ""},
		{"extension-less base name DOES match via full path", fstest.MapFS{".claude/commands/deploy.md": {Data: []byte("---\nname: deploy\n---\nRun ${CLAUDE_PROJECT_DIR}/.claude/commands/tool\n")}, ".claude/commands/tool": {Data: []byte("bin"), Mode: 0o755}}, ".claude/commands/tool", ".claude/commands/deploy.md"},
		{"nearest-ancestor SKILL.md owns a nested sub-skill payload", fstest.MapFS{".claude/skills/parent/SKILL.md": {Data: []byte("---\nname: parent\n---\nNo mentions here.\n")}, ".claude/skills/parent/sub/SKILL.md": {Data: []byte("---\nname: sub\n---\nRun scripts/y.sh\n")}, ".claude/skills/parent/sub/scripts/y.sh": {Data: []byte("#!/bin/sh")}}, ".claude/skills/parent/sub/scripts/y.sh", ".claude/skills/parent/sub/SKILL.md"},
		{"sibling reference.md is never an owner", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "No mention.\n")}, ".claude/skills/demo/reference.md": {Data: []byte("See scripts/x.sh for details.\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ""},
		{"commands-tree first indexed match wins", fstest.MapFS{".claude/commands/aaa.md": {Data: []byte("---\nname: aaa\n---\nRun ${CLAUDE_PROJECT_DIR}/.claude/commands/tool\n")}, ".claude/commands/bbb.md": {Data: []byte("---\nname: bbb\n---\nRun ${CLAUDE_PROJECT_DIR}/.claude/commands/tool\n")}, ".claude/commands/tool": {Data: []byte("bin"), Mode: 0o755}}, ".claude/commands/tool", ".claude/commands/aaa.md"},
		{"cross-root correlation is not attempted", fstest.MapFS{".claude/commands/deploy.md": {Data: []byte("---\nname: deploy\n---\nRun " + x + "\n")}, ".claude/skills/demo/SKILL.md": {Data: []byte(fm + "No mention.\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ""},
		{"malformed frontmatter YAML still correlates via unparsed text", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: [unterminated\n---\nRun scripts/x.sh\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ".claude/skills/demo/SKILL.md"},
		{"a payload named after a directory variable is not referenced by that variable", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Run $CLAUDE_PROJECT_DIR.sh\n")}, ".claude/skills/demo/$CLAUDE_PROJECT_DIR.sh": {Data: []byte("#!/bin/sh")}}, ".claude/skills/demo/$CLAUDE_PROJECT_DIR.sh", ""},
		{"no mention anywhere leaves Referenced empty", fstest.MapFS{".claude/skills/demo/SKILL.md": {Data: []byte(fm + "Nothing relevant here.\n")}, x: {Data: []byte("#!/bin/sh")}}, x, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities := payloadEntitiesOK(t, tt.fsys)
			bp := findPayload(t, entities, tt.payloadPath)
			if tt.wantReferencedBy == "" {
				if bp.Referenced != "" || bp.ReferencedBy != "" {
					t.Errorf("Referenced=%q ReferencedBy=%q, want both empty", bp.Referenced, bp.ReferencedBy)
				}
				return
			}
			if bp.Referenced != "true" {
				t.Errorf("Referenced = %q, want %q", bp.Referenced, "true")
			}
			if bp.ReferencedBy != tt.wantReferencedBy {
				t.Errorf("ReferencedBy = %q, want %q", bp.ReferencedBy, tt.wantReferencedBy)
			}
		})
	}
}

// payloadWalkOrderFS serves a directory listing in a chosen order, a shape
// fstest.MapFS cannot express on its own: it sorts its ReadDir and offers no
// hook to serve anything else, while fs.ReadDir hands a ReadDirFS's slice to
// fs.WalkDir untouched. served records what was handed over, so a test can
// show the orders it compares really disagree instead of asserting it.
type payloadWalkOrderFS struct {
	m       fstest.MapFS
	reverse bool
	served  []string
}

func (f *payloadWalkOrderFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f *payloadWalkOrderFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := f.m.ReadDir(name)
	if err != nil {
		return nil, err
	}
	if f.reverse {
		slices.Reverse(entries)
	}
	for _, e := range entries {
		f.served = append(f.served, path.Join(name, e.Name()))
	}
	return entries, nil
}

// A payload filename that sorts on the far side of its owning Markdown must
// not flip that payload between reported as referenced and reported as
// unreferenced.
func TestReferenceCorrelatorSurvivesEitherWalkOrder(t *testing.T) {
	tests := []struct {
		name                   string
		files                  fstest.MapFS
		payloadPath, ownerPath string
	}{
		{
			name: "skill owner beside its payload",
			files: fstest.MapFS{
				".claude/skills/demo/SKILL.md": {Data: []byte("---\nname: demo\n---\nRun run.sh\n")},
				".claude/skills/demo/run.sh":   {Data: []byte("#!/bin/sh")},
			},
			payloadPath: ".claude/skills/demo/run.sh",
			ownerPath:   ".claude/skills/demo/SKILL.md",
		},
		{
			name: "command owner beside its payload",
			files: fstest.MapFS{
				".claude/commands/deploy.md": {Data: []byte("---\nname: deploy\n---\nRun run.sh\n")},
				".claude/commands/run.sh":    {Data: []byte("#!/bin/sh")},
			},
			payloadPath: ".claude/commands/run.sh",
			ownerPath:   ".claude/commands/deploy.md",
		},
	}

	servedBefore := func(served []string, first, second string) bool {
		i, j := slices.Index(served, first), slices.Index(served, second)
		return i >= 0 && j >= 0 && i < j
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ownerFirst := &payloadWalkOrderFS{m: tt.files}
			payloadFirst := &payloadWalkOrderFS{m: tt.files, reverse: true}

			gotOwnerFirst := findPayload(t, payloadEntitiesOK(t, ownerFirst), tt.payloadPath)
			gotPayloadFirst := findPayload(t, payloadEntitiesOK(t, payloadFirst), tt.payloadPath)

			if !servedBefore(ownerFirst.served, tt.ownerPath, tt.payloadPath) {
				t.Fatalf("walk order = %v, want %q served before %q", ownerFirst.served, tt.ownerPath, tt.payloadPath)
			}
			if !servedBefore(payloadFirst.served, tt.payloadPath, tt.ownerPath) {
				t.Fatalf("walk order = %v, want %q served before %q", payloadFirst.served, tt.payloadPath, tt.ownerPath)
			}

			if gotOwnerFirst.Referenced != gotPayloadFirst.Referenced || gotOwnerFirst.ReferencedBy != gotPayloadFirst.ReferencedBy {
				t.Errorf("owner-first (Referenced=%q, ReferencedBy=%q) but payload-first (Referenced=%q, ReferencedBy=%q); both walk orders must agree",
					gotOwnerFirst.Referenced, gotOwnerFirst.ReferencedBy, gotPayloadFirst.Referenced, gotPayloadFirst.ReferencedBy)
			}
			if gotOwnerFirst.Referenced != "true" || gotOwnerFirst.ReferencedBy != tt.ownerPath {
				t.Errorf("Referenced=%q ReferencedBy=%q, want %q and %q", gotOwnerFirst.Referenced, gotOwnerFirst.ReferencedBy, "true", tt.ownerPath)
			}
		})
	}
}

type endingFS struct {
	m    fstest.MapFS
	live int
}

func (f *endingFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f *endingFS) ScanEnd() limits.End {
	if f.live > 0 {
		f.live--
		return limits.End{}
	}
	return limits.End{Err: context.DeadlineExceeded}
}

// A scan that has ended stops correlation between one payload and the next,
// under either payload root.
func TestPayloadEntitiesStopOnceTheirScanHasEnded(t *testing.T) {
	for _, root := range []struct {
		name, owner, referenced, unreferenced string
	}{
		{"commands", ".claude/commands/deploy.md", ".claude/commands/scripts/a.sh", ".claude/commands/x/b.sh"},
		{"skills", ".claude/skills/demo/SKILL.md", ".claude/skills/demo/scripts/a.sh", ".claude/skills/demo/x/b.sh"},
	} {
		tree := fstest.MapFS{
			root.owner:        {Data: []byte("Run scripts/a.sh\n")},
			root.referenced:   {Data: []byte("#!/bin/sh")},
			root.unreferenced: {Data: []byte("#!/bin/sh")},
		}
		payloads := 2

		for _, tt := range []struct {
			name string
			live int
		}{
			{"ended before the first payload", 0},
			{"ended after the first payload", 1},
		} {
			t.Run(root.name+"/"+tt.name, func(t *testing.T) {
				entities, _, err := payloadEntities(&endingFS{m: tree, live: tt.live})
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("payloadEntities() error = %v, want context.DeadlineExceeded", err)
				}
				if entities != nil {
					t.Errorf("payloadEntities() entities = %+v, want none once the scan has ended", entities)
				}
			})
		}

		t.Run(root.name+"/a scan that runs on correlates every payload", func(t *testing.T) {
			got := payloadEntitiesOK(t, &endingFS{m: tree, live: payloads})
			if len(got) != payloads {
				t.Fatalf("payloadEntities() = %+v, want %d payloads", got, payloads)
			}
			if a := findPayload(t, got, root.referenced); a.ReferencedBy != root.owner {
				t.Errorf("%s ReferencedBy = %q, want %q", root.referenced, a.ReferencedBy, root.owner)
			}
			if b := findPayload(t, got, root.unreferenced); b.Referenced != "" {
				t.Errorf("%s Referenced = %q, want empty", root.unreferenced, b.Referenced)
			}
		})
	}
}

// A command file costs correlation no more allocations beside many payloads
// than beside one.
func TestPayloadCorrelationAllocatesPerFileNotPerPair(t *testing.T) {
	allocs := func(files, payloads int) float64 {
		fsys := fstest.MapFS{}
		for i := range files {
			fsys[fmt.Sprintf(".claude/commands/c%02d.md", i)] = &fstest.MapFile{Data: []byte("Run ${CLAUDE_PROJECT_DIR}/bin/tool\n")}
		}
		for i := range payloads {
			fsys[fmt.Sprintf(".claude/commands/x/p%02d.sh", i)] = &fstest.MapFile{Data: []byte("#!/bin/sh")}
		}
		if got := payloadEntitiesOK(t, fsys); len(got) != payloads || slices.ContainsFunc(got, func(p ir.BundledPayload) bool { return p.Referenced != "" }) {
			t.Fatalf("payloadEntities() = %+v, want %d unreferenced payloads", got, payloads)
		}
		return testing.AllocsPerRun(10, func() { _, _, _ = payloadEntities(fsys) })
	}
	const fewFiles, moreFiles, manyPayloads = 1, 8, 64
	extraFiles := func(payloads int) float64 { return allocs(moreFiles, payloads) - allocs(fewFiles, payloads) }

	one, many := extraFiles(1), extraFiles(manyPayloads)
	if one <= 0 {
		t.Fatalf("%d more command files cost %v allocations beside one payload, want some", moreFiles-fewFiles, one)
	}
	if many > one {
		t.Errorf("%d more command files cost %v allocations beside %d payloads but %v beside one, want no more", moreFiles-fewFiles, many, manyPayloads, one)
	}
}

// The trailing-slash cases pin the clean relative output.
func TestExpandDirVars(t *testing.T) {
	tests := []struct{ name, text, skillDir, want string }{
		{"braced skill dir, trailing slash", "${CLAUDE_SKILL_DIR}/scripts/x.sh", ".claude/skills/demo", ".claude/skills/demo/scripts/x.sh"},
		{"braced skill dir, bare", "cd ${CLAUDE_SKILL_DIR} && ls", ".claude/skills/demo", "cd .claude/skills/demo && ls"},
		{"unbraced skill dir, trailing slash", "$CLAUDE_SKILL_DIR/scripts/x.sh", ".claude/skills/demo", ".claude/skills/demo/scripts/x.sh"},
		{"unbraced skill dir, bare", "cd $CLAUDE_SKILL_DIR && ls", ".claude/skills/demo", "cd .claude/skills/demo && ls"},
		{"braced project dir, trailing slash yields clean relative path", "${CLAUDE_PROJECT_DIR}/.claude/commands/tool", ".", ".claude/commands/tool"},
		{"braced project dir, bare", "cd ${CLAUDE_PROJECT_DIR} && ls", ".", "cd . && ls"},
		{"unbraced project dir, trailing slash yields clean relative path", "$CLAUDE_PROJECT_DIR/.claude/commands/tool", ".", ".claude/commands/tool"},
		{"unbraced project dir, bare", "cd $CLAUDE_PROJECT_DIR && ls", ".", "cd . && ls"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandDirVars(tt.text, dirVars{Skill: tt.skillDir}); got != tt.want {
				t.Errorf("expandDirVars(%q, dirVars{Skill:%q}) = %q, want %q", tt.text, tt.skillDir, got, tt.want)
			}
		})
	}
}

func TestExpandDirVarsSubstitutesPluginRoot(t *testing.T) {
	tests := []struct{ name, text, root, want string }{
		{"braced plugin root, trailing slash", "${CLAUDE_PLUGIN_ROOT}/bin/db", "plugins/vendor", "plugins/vendor/bin/db"},
		{"braced plugin root, bare", "cd ${CLAUDE_PLUGIN_ROOT} && ls", "plugins/vendor", "cd plugins/vendor && ls"},
		{"unbraced plugin root, trailing slash", "$CLAUDE_PLUGIN_ROOT/bin/db", "plugins/vendor", "plugins/vendor/bin/db"},
		{"unbraced plugin root, bare", "cd $CLAUDE_PLUGIN_ROOT && ls", "plugins/vendor", "cd plugins/vendor && ls"},
		{"root \".\" trailing slash collapses to clean relative path", "${CLAUDE_PLUGIN_ROOT}/bin/db", ".", "bin/db"},
		{"root \".\" bare", "cd ${CLAUDE_PLUGIN_ROOT} && ls", ".", "cd . && ls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandDirVars(tt.text, dirVars{PluginRoot: tt.root}); got != tt.want {
				t.Errorf("expandDirVars(%q, dirVars{PluginRoot:%q}) = %q, want %q", tt.text, tt.root, got, tt.want)
			}
		})
	}
}

// No PluginRoot value is introduced at the ${CLAUDE_PLUGIN_DATA} position.
func TestExpandDirVarsLeavesPluginDataLiteral(t *testing.T) {
	tests := []string{
		"${CLAUDE_PLUGIN_DATA}/state.json",
		"cat $CLAUDE_PLUGIN_DATA/state.json",
	}
	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			got := expandDirVars(text, dirVars{PluginRoot: "plugins/vendor"})
			if got != text {
				t.Errorf("expandDirVars(%q) = %q, want byte-identical (never substituted)", text, got)
			}
			if strings.Contains(got, "plugins/vendor") {
				t.Errorf("expandDirVars(%q) = %q, must not introduce PluginRoot at this position", text, got)
			}
		})
	}
}

// A link in the project's skills or commands tree that carries no Markdown
// name is named rather than followed or skipped, and the real skill beside it
// keeps its script and its command in the report.
func TestParseNamesALinkedEntryAndKeepsTheSkillBesideIt(t *testing.T) {
	const script = skillsDir + "/real/scripts/r.sh"

	tests := []struct {
		name   string
		link   string
		target string
	}{
		{name: "a skill folder", link: skillsDir + "/linked", target: "../../shared/sk"},
		{name: "a command folder", link: commandsDir + "/linked", target: "../../shared/cmds"},
		{name: "an extension-less script", link: skillsDir + "/real/scripts/tool", target: "../../../../shared/tool"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				tt.link:                      {Data: []byte(tt.target), Mode: fs.ModeSymlink | 0o777},
				"shared/sk/SKILL.md":         skillBody("shared", "shared.sh"),
				"shared/sk/scripts/x.sh":     {Data: []byte("#!/bin/sh\n")},
				"shared/cmds/deploy.md":      inlineBody("shared.sh"),
				"shared/tool":                {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
				skillsDir + "/real/SKILL.md": skillBody("real", "in-tree.sh"),
				script:                       {Data: []byte("#!/bin/sh\n")},
			}

			entities, warnings, err := New().Parse(fsys)
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}

			var payloads []string
			for _, e := range entities {
				if file := ir.LocationOf(e).File; strings.HasPrefix(file, "shared/") || strings.HasPrefix(file, tt.link) {
					t.Fatalf("entity %+v was read through the link", e)
				}
				if bp, ok := e.(ir.BundledPayload); ok {
					payloads = append(payloads, bp.Path)
				}
			}
			if !slices.Equal(payloads, []string{script}) {
				t.Fatalf("payloads = %v, want %v", payloads, []string{script})
			}
			if got := inlineShellCommands(entities); !slices.Equal(got, []string{"in-tree.sh"}) {
				t.Fatalf("inline shell commands = %v, want the real skill's", got)
			}
			if len(warnings) != 1 || warnings[0].File != tt.link {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, tt.link)
			}
			if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
				t.Fatalf("warnings[0].Err = %v, want errors.Is(_, adapter.ErrUnreadable)", warnings[0].Err)
			}
		})
	}
}

// Without fs.StatFS the target's type is out of reach short of an open, so
// a link is refused on its own mode even over a regular file.
func TestPayloadEntitiesRefuseALinkWithoutStatFS(t *testing.T) {
	const link = ".claude/skills/demo/reference.md"
	_, warnings, err := payloadEntities(noStatFS{m: fstest.MapFS{
		link:                  {Data: []byte("../../../shared/reference.md"), Mode: fs.ModeSymlink},
		"shared/reference.md": {Data: []byte("# notes\n")},
	}})
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil", err)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
}

type noStatFS struct{ m fstest.MapFS }

func (f noStatFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f noStatFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

// A link whose target fails to stat for any reason but absence is refused,
// since nothing says what it hides.
func TestPayloadEntitiesRefuseALinkWhoseTargetFailsToStat(t *testing.T) {
	const link = ".claude/skills/demo/reference.md"
	_, warnings, err := payloadEntities(statFaultFS{fault: link, m: fstest.MapFS{
		link:                  {Data: []byte("../../../shared/reference.md"), Mode: fs.ModeSymlink},
		"shared/reference.md": {Data: []byte("# notes\n")},
	}})
	if err != nil {
		t.Fatalf("payloadEntities() error = %v, want nil", err)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
}

type statFaultFS struct {
	m     fstest.MapFS
	fault string
}

func (f statFaultFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f statFaultFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f statFaultFS) Stat(name string) (fs.FileInfo, error) {
	if name == f.fault {
		return nil, &fs.PathError{Op: "statat", Path: name, Err: errors.New("path escapes from parent")}
	}
	return f.m.Stat(name)
}
