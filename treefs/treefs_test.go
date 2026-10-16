package treefs_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/treefs"
)

func held(blobs map[string]string) func(string) ([]byte, bool) {
	return func(p string) ([]byte, bool) {
		data, ok := blobs[p]
		return []byte(data), ok
	}
}

// Refusal holds in either entry order, since an archive's entry names and
// their order are both attacker-chosen.
func TestNewRefusesAnEntryThatIsNotOneNode(t *testing.T) {
	file := fs.FileMode(0o644)
	tests := []struct {
		name    string
		entries []treefs.Entry
		path    string
	}{
		{"parent segment", []treefs.Entry{{Path: "../x", Mode: file}}, "../x"},
		{"absolute", []treefs.Entry{{Path: "/x", Mode: file}}, "/x"},
		{"empty segment", []treefs.Entry{{Path: "a//b", Mode: file}}, "a//b"},
		{"trailing slash", []treefs.Entry{{Path: "a/", Mode: file}}, "a/"},
		{"root", []treefs.Entry{{Path: ".", Mode: fs.ModeDir | 0o755}}, "."},
		{"duplicate", []treefs.Entry{{Path: "a", Mode: file}, {Path: "a", Mode: file}}, "a"},
		{"duplicate directory", []treefs.Entry{{Path: "a", Mode: fs.ModeDir | 0o755}, {Path: "a", Mode: fs.ModeDir | 0o755}}, "a"},
		{"file then child", []treefs.Entry{{Path: "a", Mode: file}, {Path: "a/b", Mode: file}}, "a"},
		{"child then file", []treefs.Entry{{Path: "a/b", Mode: file}, {Path: "a", Mode: file}}, "a"},
		{"file then grandchild", []treefs.Entry{{Path: "a", Mode: file}, {Path: "a/b/c", Mode: file}}, "a"},
		{"link then child", []treefs.Entry{{Path: "a", Mode: fs.ModeSymlink | 0o777}, {Path: "a/b", Mode: file}}, "a"},
		{"child then link", []treefs.Entry{{Path: "a/b", Mode: file}, {Path: "a", Mode: fs.ModeSymlink | 0o777}}, "a"},
		{"NUL", []treefs.Entry{{Path: "a\x00b", Mode: file}}, "a\x00b"},
		{"longer than 4096 bytes", []treefs.Entry{{Path: strings.Repeat("a", 4097), Mode: file}}, strings.Repeat("a", 4097)},
		{"directory and link at once", []treefs.Entry{
			{Path: "cfg", Mode: fs.ModeDir | fs.ModeSymlink | 0o777},
			{Path: "cfg/settings.json", Mode: file},
		}, "cfg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := treefs.New(tt.entries, held(nil))
			if err == nil || !strings.Contains(err.Error(), strconv.Quote(tt.path)) {
				t.Fatalf("New() error = %v, want one naming %q", err, tt.path)
			}
		})
	}
}

// Parents are implied, so a directory listed after its children is the
// same directory, not a fresh empty one.
func TestNewBuildsTheSameTreeForwardReversedAndShuffled(t *testing.T) {
	entries := shapeEntries()
	reversed := slices.Clone(entries)
	slices.Reverse(reversed)
	shuffled := []treefs.Entry{entries[3], entries[0], entries[6], entries[1], entries[5], entries[2], entries[4]}

	want := treeShape(t, entries)
	if !strings.Contains(want, "cfg/sub/tool -rwxr-xr-x") {
		t.Fatalf("forward listing lacks cfg/sub/tool:\n%s", want)
	}
	for name, order := range map[string][]treefs.Entry{"reversed": reversed, "shuffled": shuffled} {
		if got := treeShape(t, order); got != want {
			t.Fatalf("%s order:\n%s\nwant, as given forward:\n%s", name, got, want)
		}
	}
}

func shapeEntries() []treefs.Entry {
	return []treefs.Entry{
		{Path: "cfg", Mode: fs.ModeDir | 0o755},
		{Path: "cfg/a.json", Mode: 0o644},
		{Path: "cfg/sub", Mode: fs.ModeDir | 0o700},
		{Path: "cfg/sub/tool", Mode: 0o755},
		{Path: "cfg/link", Mode: fs.ModeSymlink | 0o777},
		{Path: "top", Mode: 0o644},
		{Path: "deep/er/file", Mode: 0o644},
	}
}

func shapeTreeOf(t *testing.T, entries []treefs.Entry) *treefs.FS {
	t.Helper()

	tree, err := treefs.New(entries, held(map[string]string{"cfg/link": "a.json", "top": "a.json"}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return tree
}

func shapeTree(t *testing.T) *treefs.FS {
	t.Helper()

	return shapeTreeOf(t, shapeEntries())
}

func treeShape(t *testing.T, entries []treefs.Entry) string {
	t.Helper()

	tree := shapeTreeOf(t, entries)
	var b strings.Builder
	err := fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %v\n", p, d.Type())
		if d.IsDir() {
			children, err := tree.ReadDir(p)
			if err != nil {
				return err
			}
			for _, c := range children {
				fmt.Fprintf(&b, "  %s %v\n", c.Name(), c.Type())
			}
		}
		info, err := tree.Stat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %v\n", p, info.Mode())
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir() error = %v", err)
	}
	return b.String()
}

func TestNewPassesModesThrough(t *testing.T) {
	tree, err := treefs.New([]treefs.Entry{
		{Path: "bin/tool", Mode: 0o755},
		{Path: "link", Mode: fs.ModeSymlink | 0o777},
		{Path: "submodule", Mode: fs.ModeDir | 0o755},
	}, held(map[string]string{"link": "bin/tool"}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("exec bit", func(t *testing.T) {
		info, err := tree.Stat("bin/tool")
		if err != nil || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("Stat(bin/tool) = %v, %v; want an executable mode", info, err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		info, err := tree.Lstat("link")
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			t.Fatalf("Lstat(link) = %v, %v; want a symlink mode", info, err)
		}
	})
	t.Run("directory with no children", func(t *testing.T) {
		info, err := tree.Stat("submodule")
		if err != nil || !info.IsDir() {
			t.Fatalf("Stat(submodule) = %v, %v; want a directory", info, err)
		}
		entries, err := tree.ReadDir("submodule")
		if err != nil || len(entries) != 0 {
			t.Fatalf("ReadDir(submodule) = %v, %v; want empty", entries, err)
		}
	})
}

func TestMissingDrainsTheUnheldReadsInPathOrder(t *testing.T) {
	paths := []string{"e", "d/x", "c", "b/y", "a"}
	var entries []treefs.Entry
	for _, p := range paths {
		entries = append(entries, treefs.Entry{Path: p, Mode: 0o644})
	}
	tree, err := treefs.New(entries, held(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, p := range paths {
		data, err := tree.ReadFile(p)
		if err != nil || len(data) != 0 {
			t.Fatalf("ReadFile(%q) = %q, %v; want empty content before Seal", p, data, err)
		}
	}
	if got, want := tree.Missing(), []string{"a", "b/y", "c", "d/x", "e"}; !slices.Equal(got, want) {
		t.Fatalf("Missing() = %q, want %q", got, want)
	}
	if got := tree.Missing(); len(got) != 0 {
		t.Fatalf("second Missing() = %q, want empty", got)
	}
}

// Seal turns resolution through an unheld link from fs.ErrNotExist into
// another failure; Lstat of the link itself still answers.
func TestSealFailsResolutionThroughAnUnheldLink(t *testing.T) {
	tree, err := treefs.New([]treefs.Entry{
		{Path: "link", Mode: fs.ModeSymlink | 0o777},
		{Path: "real/file", Mode: 0o644},
	}, held(map[string]string{"real/file": "data"}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	calls := map[string]func() error{
		"Stat(link)":          func() error { _, err := tree.Stat("link"); return err },
		"Open(link)":          func() error { _, err := tree.Open("link"); return err },
		"ReadDir(link)":       func() error { _, err := tree.ReadDir("link"); return err },
		"ReadLink(link)":      func() error { _, err := tree.ReadLink("link"); return err },
		"ReadFile(link/file)": func() error { _, err := tree.ReadFile("link/file"); return err },
		"Lstat(link/file)":    func() error { _, err := tree.Lstat("link/file"); return err },
	}

	for name, call := range calls {
		if err := call(); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s before Seal error = %v, want fs.ErrNotExist", name, err)
		}
	}
	tree.Seal()
	for name, call := range calls {
		var pathErr *fs.PathError
		if err := call(); !errors.As(err, &pathErr) || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s after Seal error = %v, want a *fs.PathError other than fs.ErrNotExist", name, err)
		}
	}
	if info, err := tree.Lstat("link"); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(link) after Seal = %v, %v; want the link's own mode", info, err)
	}
}

func TestNewAcceptsAPathOf4096Bytes(t *testing.T) {
	long := strings.Repeat("a", 4096)
	tree, err := treefs.New([]treefs.Entry{{Path: long, Mode: 0o644}}, held(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := tree.Stat(long); err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
}

func TestAMalformedLinkTargetIsRefused(t *testing.T) {
	for name, target := range map[string]string{
		"empty":                  "",
		"NUL":                    "file\x00/x",
		"longer than 4096 bytes": strings.Repeat("./", 2049) + "file",
	} {
		t.Run(name, func(t *testing.T) {
			info, err := linkTo(t, target).Stat("link")
			if err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("Stat(link) = %v, %v; want a refusal other than fs.ErrNotExist", info, err)
			}
		})
	}
	if _, err := linkTo(t, strings.Repeat("./", 2046)+"file").Stat("link"); err != nil {
		t.Fatalf("Stat(link) through a 4096-byte target error = %v, want nil", err)
	}
}

func linkTo(t *testing.T, target string) *treefs.FS {
	t.Helper()

	tree, err := treefs.New([]treefs.Entry{
		{Path: "link", Mode: fs.ModeSymlink | 0o777},
		{Path: "file", Mode: 0o644},
	}, held(map[string]string{"link": target, "file": "data"}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return tree
}

func TestAnOpenedDirectoryReadsInPages(t *testing.T) {
	tree := shapeTree(t)
	want, err := tree.ReadDir("cfg")
	if err != nil || len(want) < 2 {
		t.Fatalf("ReadDir(cfg) = %v, %v; want at least two entries", want, err)
	}

	f, err := tree.Open("cfg")
	if err != nil {
		t.Fatalf("Open(cfg) error = %v", err)
	}
	dir := f.(fs.ReadDirFile)
	var got []fs.DirEntry
	for {
		page, err := dir.ReadDir(1)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(page) != 1 {
			t.Fatalf("ReadDir(1) = %v, %v; want one entry", page, err)
		}
		got = append(got, page...)
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Name() != want[i].Name() {
			t.Fatalf("page %d = %q, want %q", i, got[i].Name(), want[i].Name())
		}
	}
}

func TestEveryMethodRefusesAnInvalidName(t *testing.T) {
	tree := shapeTree(t)
	calls := map[string]func(string) error{
		"Open":     func(n string) error { _, err := tree.Open(n); return err },
		"Stat":     func(n string) error { _, err := tree.Stat(n); return err },
		"Lstat":    func(n string) error { _, err := tree.Lstat(n); return err },
		"ReadDir":  func(n string) error { _, err := tree.ReadDir(n); return err },
		"ReadFile": func(n string) error { _, err := tree.ReadFile(n); return err },
		"ReadLink": func(n string) error { _, err := tree.ReadLink(n); return err },
	}
	for method, call := range calls {
		for _, name := range []string{"/top", "cfg//a.json", "cfg/./link", "cfg/"} {
			if err := call(name); !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("%s(%q) error = %v, want fs.ErrInvalid", method, name, err)
			}
		}
	}
}

func TestReadDirAndReadLinkRefuseTheWrongKind(t *testing.T) {
	tree := shapeTree(t)
	if entries, err := tree.ReadDir("top"); err == nil {
		t.Fatalf("ReadDir(top) = %v, nil; want an error for a file", entries)
	}
	if target, err := tree.ReadLink("top"); err == nil {
		t.Fatalf("ReadLink(top) = %q, nil; want an error for a file", target)
	}
}
