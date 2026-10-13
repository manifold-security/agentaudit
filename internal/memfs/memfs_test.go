package memfs_test

import (
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/memfs"
)

func newFS(t *testing.T, files map[string][]byte) fs.FS {
	t.Helper()

	fsys, err := memfs.New(files)
	if err != nil {
		t.Fatalf("memfs.New() error = %v, want nil", err)
	}
	return fsys
}

// fstest.TestFS holds the io/fs contract over a tree whose directories the
// FS invented rather than received.
func TestFSSatisfiesTheIOFSContract(t *testing.T) {
	names := []string{
		".claude/settings.json",
		".claude/skills/demo/SKILL.md",
		".claude/skills/demo/scripts/validate.sh",
		"top.md",
	}
	files := map[string][]byte{}
	for _, name := range names {
		files[name] = []byte(name)
	}

	if err := fstest.TestFS(newFS(t, files), names...); err != nil {
		t.Fatalf("fstest.TestFS() error = %v, want nil", err)
	}
}

// An unsynthesized parent stops the descent, so the deepest file has to be
// reachable and each invented level has to present itself as a directory.
func TestWalkDirReachesAFileBeneathSynthesizedParents(t *testing.T) {
	fsys := newFS(t, map[string][]byte{
		".claude/skills/demo/scripts/validate.sh": []byte("#!/bin/sh\n"),
	})

	var walked []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		kind := "file"
		if d.IsDir() {
			kind = "dir"
		}
		walked = append(walked, p+" "+kind)
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir() error = %v, want nil", err)
	}

	want := []string{
		". dir",
		".claude dir",
		".claude/skills dir",
		".claude/skills/demo dir",
		".claude/skills/demo/scripts dir",
		".claude/skills/demo/scripts/validate.sh file",
	}
	if len(walked) != len(want) {
		t.Fatalf("fs.WalkDir visited %v, want %v", walked, want)
	}
	for i := range want {
		if walked[i] != want[i] {
			t.Fatalf("fs.WalkDir visited %v, want %v", walked, want)
		}
	}
}

// A type bit on a regular file makes the claude adapter's plugin guards
// refuse it as unreadable, and a directory without fs.ModeDir loses that
// whole surface.
func TestModeSeparatesDirectoriesFromRegularFilesAndWithholdsTheExecuteBitFromFiles(t *testing.T) {
	const manifest = "plugins/toolkit/.claude-plugin/plugin.json"
	fsys := newFS(t, map[string][]byte{manifest: []byte(`{"name":"toolkit"}`)})

	file, err := fs.Stat(fsys, manifest)
	if err != nil {
		t.Fatalf("fs.Stat(%q) error = %v, want nil", manifest, err)
	}
	if !file.Mode().IsRegular() {
		t.Fatalf("fs.Stat(%q).Mode() = %v, want a regular file", manifest, file.Mode())
	}
	if got := file.Mode().Type(); got != 0 {
		t.Fatalf("fs.Stat(%q).Mode().Type() = %v, want no type bit", manifest, got)
	}
	if got := file.Mode().Perm() & 0o111; got != 0 {
		t.Fatalf("fs.Stat(%q).Mode().Perm() = %#o, want no execute bit", manifest, file.Mode().Perm())
	}
	if got, want := file.Size(), int64(len(`{"name":"toolkit"}`)); got != want {
		t.Fatalf("fs.Stat(%q).Size() = %d, want %d", manifest, got, want)
	}

	dir, err := fs.Stat(fsys, "plugins/toolkit")
	if err != nil {
		t.Fatalf("fs.Stat(%q) error = %v, want nil", "plugins/toolkit", err)
	}
	if !dir.IsDir() {
		t.Fatalf("fs.Stat(%q).IsDir() = false, want true", "plugins/toolkit")
	}
	if got := dir.Mode().Type(); got != fs.ModeDir {
		t.Fatalf("fs.Stat(%q).Mode().Type() = %v, want %v", "plugins/toolkit", got, fs.ModeDir)
	}
	if got := dir.Mode().Perm() & 0o111; got == 0 {
		t.Fatalf("fs.Stat(%q).Mode().Perm() = %#o, want a directory to stay traversable", "plugins/toolkit", dir.Mode().Perm())
	}
}

// An entry disagreeing with fs.Stat sends fsguard.LinkMode and payloads.go's
// executable down different branches for one file.
func TestDirEntryTypeAndInfoAgreeWithStat(t *testing.T) {
	const manifest = "plugins/toolkit/.claude-plugin/plugin.json"
	fsys := newFS(t, map[string][]byte{manifest: []byte(`{}`)})

	if _, ok := fsys.(fs.ReadLinkFS); ok {
		t.Fatalf("fsys implements fs.ReadLinkFS; fsguard.LinkMode's fs.ReadDir fallback is what this pins")
	}

	entries, err := fs.ReadDir(fsys, "plugins/toolkit/.claude-plugin")
	if err != nil {
		t.Fatalf("fs.ReadDir() error = %v, want nil", err)
	}
	if len(entries) != 1 {
		t.Fatalf("fs.ReadDir() = %v, want one entry", entries)
	}

	entry := entries[0]
	if got := entry.Name(); got != "plugin.json" {
		t.Fatalf("entry.Name() = %q, want %q", got, "plugin.json")
	}
	if got := entry.Type(); got != 0 {
		t.Fatalf("entry.Type() = %v, want no type bit", got)
	}

	info, err := entry.Info()
	if err != nil {
		t.Fatalf("entry.Info() error = %v, want nil", err)
	}
	stat, err := fs.Stat(fsys, manifest)
	if err != nil {
		t.Fatalf("fs.Stat() error = %v, want nil", err)
	}
	if info.Mode() != stat.Mode() || info.Size() != stat.Size() || info.Name() != stat.Name() {
		t.Fatalf("entry.Info() = %v/%d/%q, want fs.Stat's %v/%d/%q", info.Mode(), info.Size(), info.Name(), stat.Mode(), stat.Size(), stat.Name())
	}
}

// A key io/fs cannot name has no place in the tree, and neither does the root:
// it names a directory rather than a file, so New turns it away on its own
// arm. The accepted row is the companion that rules out a New refusing
// everything.
func TestNewRefusesAKeyItCannotHoldAsAFile(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "rooted", path: "/.claude/settings.json", wantErr: true},
		{name: "parent traversal", path: ".claude/../settings.json", wantErr: true},
		{name: "dot prefixed", path: "./.claude/settings.json", wantErr: true},
		{name: "trailing slash", path: ".claude/", wantErr: true},
		{name: "empty", path: "", wantErr: true},
		{name: "the root itself", path: ".", wantErr: true},
		{name: "unrooted and clean", path: ".claude/settings.json", wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := memfs.New(map[string][]byte{tc.path: []byte(`{}`)})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("memfs.New(%q) error = %v, want nil", tc.path, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("memfs.New(%q) error = nil, want an error naming the path", tc.path)
			}
			if !strings.Contains(err.Error(), strconv.Quote(tc.path)) {
				t.Fatalf("memfs.New(%q) error = %v, want it to name the path it refused", tc.path, err)
			}
		})
	}
}

// A host set naming both a file and a directory at one path is a fault to
// report rather than a shape to pick a winner from.
func TestNewRefusesAPathThatIsBothFileAndDirectory(t *testing.T) {
	const collision = ".claude/settings.json"
	_, err := memfs.New(map[string][]byte{
		collision:            []byte(`{}`),
		collision + "/inner": []byte(`{}`),
	})
	if err == nil {
		t.Fatalf("memfs.New() error = nil, want a refusal of the file-and-directory pair")
	}
	for _, want := range []string{strconv.Quote(collision), strconv.Quote(collision + "/inner")} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("memfs.New() error = %v, want it to name %s", err, want)
		}
	}
}

// An absent name reports fs.ErrNotExist through each entry point, which is the
// sentinel the facade and the adapters branch on.
func TestAbsentNamesReportErrNotExist(t *testing.T) {
	fsys := newFS(t, map[string][]byte{".claude/settings.json": []byte(`{}`)})

	if _, err := fsys.Open("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open(missing) error = %v, want fs.ErrNotExist", err)
	}
	if _, err := fs.Stat(fsys, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fs.Stat(missing) error = %v, want fs.ErrNotExist", err)
	}
	if _, err := fs.ReadFile(fsys, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fs.ReadFile(missing) error = %v, want fs.ErrNotExist", err)
	}
	if _, err := fs.ReadDir(fsys, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fs.ReadDir(missing) error = %v, want fs.ErrNotExist", err)
	}
	if _, err := fs.ReadFile(fsys, ".claude/settings.json"); err != nil {
		t.Fatalf("fs.ReadFile(present) error = %v, want nil", err)
	}
}

// A returned slice aliasing the host's own bytes would let one reader mutate
// what every later reader sees, in a tool whose contract is to touch nothing.
func TestReadFileReturnsBytesTheCallerCannotUseToMutateTheFS(t *testing.T) {
	const name = ".claude/settings.json"
	fsys := newFS(t, map[string][]byte{name: []byte(`{"a":1}`)})

	first, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("fs.ReadFile() error = %v, want nil", err)
	}
	first[0] = 'X'

	second, err := fs.ReadFile(fsys, name)
	if err != nil {
		t.Fatalf("fs.ReadFile() error = %v, want nil", err)
	}
	if string(second) != `{"a":1}` {
		t.Fatalf("fs.ReadFile() = %q after a caller wrote to an earlier result, want %q", second, `{"a":1}`)
	}
}

// A wrong-type or unnameable path answers with a fault, never an absence:
// reading one as the other would turn a host set nothing could traverse into a
// clean report — a directory declared as a file, say, whose contents nothing
// ever enumerates.
func TestWrongTypeAndUnnameablePathsDoNotReportAsAbsence(t *testing.T) {
	const file = ".claude/settings.json"
	fsys := newFS(t, map[string][]byte{file: []byte(`{}`)})

	_, err := fs.ReadDir(fsys, file)
	assertFault(t, "fs.ReadDir on a regular file", err)

	_, err = fs.ReadFile(fsys, ".claude")
	assertFault(t, "fs.ReadFile on a directory", err)

	handle, err := fsys.Open(".claude")
	if err != nil {
		t.Fatalf("Open(%q) error = %v, want nil", ".claude", err)
	}
	defer handle.Close()
	_, err = handle.Read(make([]byte, 1))
	assertFault(t, "Read on a directory handle", err)

	const unnameable = "/.claude"
	if _, err := fsys.Open(unnameable); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Open(%q) error = %v, want fs.ErrInvalid", unnameable, err)
	}
	if _, err := fs.Stat(fsys, unnameable); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("fs.Stat(%q) error = %v, want fs.ErrInvalid", unnameable, err)
	}
	if _, err := fs.ReadDir(fsys, unnameable); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("fs.ReadDir(%q) error = %v, want fs.ErrInvalid", unnameable, err)
	}
	if _, err := fs.ReadFile(fsys, unnameable); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("fs.ReadFile(%q) error = %v, want fs.ErrInvalid", unnameable, err)
	}
}

// An empty host set builds a root with nothing under it rather than failing,
// so a caller can tell an empty tree from a refused one.
func TestNewAcceptsAnEmptySetAndBuildsAnEmptyRoot(t *testing.T) {
	fsys := newFS(t, map[string][]byte{})

	info, err := fs.Stat(fsys, ".")
	if err != nil {
		t.Fatalf("fs.Stat(\".\") error = %v, want nil", err)
	}
	if !info.IsDir() {
		t.Fatalf("fs.Stat(\".\").IsDir() = false, want true")
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("fs.ReadDir(\".\") error = %v, want nil", err)
	}
	if len(entries) != 0 {
		t.Fatalf("fs.ReadDir(\".\") = %v, want no entry", entries)
	}
}

// assertFault rejects an absence and an end of file alike: either spelling
// lets a caller read a source it could not traverse as one that simply held
// nothing.
func assertFault(t *testing.T, what string, err error) {
	t.Helper()

	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("%s error = %v, want an fs.PathError", what, err)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, io.EOF) {
		t.Fatalf("%s error = %v, want a fault no caller can read as an empty source", what, err)
	}
}
