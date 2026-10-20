package treefs_test

import (
	"fmt"
	"io/fs"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/treefs"
)

func children(t *testing.T, b *treefs.Builder, dir int, kids ...treefs.Kid) int {
	t.Helper()

	first, err := b.Children(dir, kids)
	if err != nil {
		t.Fatalf("Children(%d) error = %v", dir, err)
	}
	return first
}

// A breadth-first layout of shapeEntries serves the tree New builds from
// them, links resolved through blobs fetched by ID.
func TestBuilderServesTheTreeNewBuilds(t *testing.T) {
	b := treefs.NewBuilder()
	root := children(t, b, 0,
		treefs.Kid{Name: "cfg", Mode: fs.ModeDir | 0o755},
		treefs.Kid{Name: "deep", Mode: fs.ModeDir | 0o755},
		treefs.Kid{Name: "top", Mode: 0o644, ID: 4},
	)
	cfg := children(t, b, root,
		treefs.Kid{Name: "a.json", Mode: 0o644, ID: 1},
		treefs.Kid{Name: "link", Mode: fs.ModeSymlink | 0o777, ID: 2},
		treefs.Kid{Name: "sub", Mode: fs.ModeDir | 0o700},
	)
	deep := children(t, b, root+1, treefs.Kid{Name: "er", Mode: fs.ModeDir | 0o755})
	children(t, b, cfg+2, treefs.Kid{Name: "tool", Mode: 0o755, ID: 3})
	children(t, b, deep, treefs.Kid{Name: "file", Mode: 0o644, ID: 5})
	blobs := map[uint32]string{2: "a.json", 4: "a.json"}
	built := b.FS(func(id uint32) ([]byte, bool) {
		data, ok := blobs[id]
		return []byte(data), ok
	})

	if got, want := shapeOf(t, built), treeShape(t, shapeEntries()); got != want {
		t.Fatalf("built tree:\n%s\nwant, as New builds it:\n%s", got, want)
	}
}

// A refused entry is quoted by its path, as New quotes one.
func TestChildrenRefusesAnEntryThatIsNotOneNode(t *testing.T) {
	file := fs.FileMode(0o644)
	for _, tt := range []struct {
		name   string
		layout func(b *treefs.Builder) error
		want   []string
	}{
		{"unsorted", kidsOf(treefs.Kid{Name: "b", Mode: file}, treefs.Kid{Name: "a", Mode: file}), quoted("a", "not sorted")},
		{"duplicate", kidsOf(treefs.Kid{Name: "a", Mode: file}, treefs.Kid{Name: "a", Mode: file}), quoted("a", "duplicate")},
		{"empty", kidsOf(treefs.Kid{Name: "", Mode: file}), quoted("", "invalid")},
		{"dot", kidsOf(treefs.Kid{Name: ".", Mode: file}), quoted(".", "invalid")},
		{"dot dot", kidsOf(treefs.Kid{Name: "..", Mode: file}), quoted("..", "invalid")},
		{"slash", kidsOf(treefs.Kid{Name: "a/b", Mode: file}), quoted("a/b", "invalid")},
		{"NUL", kidsOf(treefs.Kid{Name: "a\x00b", Mode: file}), quoted("a\x00b", "invalid")},
		{"not UTF-8", kidsOf(treefs.Kid{Name: "\xff\xfe", Mode: file}), quoted("\xff\xfe", "invalid")},
		{"character device", kidsOf(treefs.Kid{Name: "dev", Mode: fs.ModeDevice | fs.ModeCharDevice | 0o644}), quoted("dev", "unsupported file type")},
		{"below a file", func(b *treefs.Builder) error {
			if _, err := b.Children(0, []treefs.Kid{{Name: "f", Mode: file}}); err != nil {
				return err
			}
			_, err := b.Children(1, []treefs.Kid{{Name: "x", Mode: file}})
			return err
		}, quoted("f", "not a directory")},
		{"twice", func(b *treefs.Builder) error {
			if _, err := b.Children(0, []treefs.Kid{{Name: "a", Mode: fs.ModeDir | 0o755}}); err != nil {
				return err
			}
			_, err := b.Children(0, []treefs.Kid{{Name: "b", Mode: file}})
			return err
		}, quoted(".", "already")},
		{"unlaid index", func(b *treefs.Builder) error {
			_, err := b.Children(1, []treefs.Kid{{Name: "a", Mode: file}})
			return err
		}, []string{"no entry at index 1"}},
		{"after FS", func(b *treefs.Builder) error {
			b.FS(nil)
			_, err := b.Children(0, []treefs.Kid{{Name: "a", Mode: file}})
			return err
		}, []string{"ended"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.layout(treefs.NewBuilder())
			for _, want := range tt.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %v, want one holding %q", err, want)
				}
			}
		})
	}
}

func quoted(path, reason string) []string {
	return []string{strconv.Quote(path), reason}
}

func kidsOf(kids ...treefs.Kid) func(b *treefs.Builder) error {
	return func(b *treefs.Builder) error {
		_, err := b.Children(0, kids)
		return err
	}
}

// A path's length counts its directory's path: a 4094-byte name fits at the
// root and passes the limit one directory down.
func TestChildrenRefusesAPathOver4095BytesBelowADirectory(t *testing.T) {
	children(t, treefs.NewBuilder(), 0, treefs.Kid{Name: strings.Repeat("n", 4094), Mode: 0o644})
	for n, accepted := range map[int]bool{4093: true, 4094: false} {
		b := treefs.NewBuilder()
		children(t, b, 0, treefs.Kid{Name: "d", Mode: fs.ModeDir | 0o755})
		_, err := b.Children(1, []treefs.Kid{{Name: strings.Repeat("n", n), Mode: 0o644}})
		if (err == nil) != accepted {
			t.Fatalf("Children() with a %d-byte path: error = %.120v, want accepted %v", n+2, err, accepted)
		}
		if !accepted && !strings.Contains(err.Error(), fmt.Sprint(n+2)) {
			t.Fatalf("Children() error = %.120v, want the length %d named", err, n+2)
		}
	}
}

func TestFSReturnsNoTreeOnceTheLayoutHasEnded(t *testing.T) {
	b := treefs.NewBuilder()
	if b.FS(nil) == nil {
		t.Fatal("first FS() = nil, want the tree")
	}
	if tree := b.FS(nil); tree != nil {
		t.Fatalf("second FS() = %v, want nil", tree)
	}
}

// Missing and the blob function see the same refusals, so a caller may
// track either; a held read records nothing.
func TestMissingHoldsThePathsOfTheIDsTheBlobFunctionRefused(t *testing.T) {
	b := treefs.NewBuilder()
	root := children(t, b, 0,
		treefs.Kid{Name: "dir", Mode: fs.ModeDir | 0o755},
		treefs.Kid{Name: "held", Mode: 0o644, ID: 1},
		treefs.Kid{Name: "link", Mode: fs.ModeSymlink | 0o777, ID: 2},
		treefs.Kid{Name: "unheld", Mode: 0o644, ID: 3},
	)
	children(t, b, root, treefs.Kid{Name: "deep", Mode: 0o644, ID: 4})
	asked := map[uint32]int{}
	var refused []uint32
	tree := b.FS(func(id uint32) ([]byte, bool) {
		asked[id]++
		if id == 1 {
			return []byte("data"), true
		}
		refused = append(refused, id)
		return nil, false
	})

	if data, err := tree.ReadFile("held"); err != nil || string(data) != "data" {
		t.Fatalf("ReadFile(held) = %q, %v; want data", data, err)
	}
	if asked[1] == 0 || len(tree.Missing()) != 0 {
		t.Fatalf("a held read asked %d time(s) and left Missing non-empty", asked[1])
	}
	_, _ = tree.ReadFile("unheld")
	_, _ = tree.Stat("link")
	_, _ = tree.ReadLink("link")
	_, _ = tree.Open("dir/deep")

	byID := map[uint32]string{2: "link", 3: "unheld", 4: "dir/deep"}
	var want []string
	for _, id := range refused {
		if !slices.Contains(want, byID[id]) {
			want = append(want, byID[id])
		}
	}
	slices.Sort(want)
	if got := tree.Missing(); !slices.Equal(got, want) || len(want) != len(byID) {
		t.Fatalf("Missing() = %q, want %q, the paths of every refused ID %v", got, want, refused)
	}
}

func TestAWideDirectoryResolvesEachNameAndNoOther(t *testing.T) {
	var kids []treefs.Kid
	for i := 0; i < 1000; i += 2 {
		kids = append(kids, treefs.Kid{Name: fmt.Sprintf("n%04d", i), Mode: 0o644})
	}
	b := treefs.NewBuilder()
	children(t, b, 0, kids...)
	tree := b.FS(func(uint32) ([]byte, bool) { return nil, false })

	for i := range 1000 {
		name := fmt.Sprintf("n%04d", i)
		_, err := tree.Lstat(name)
		if listed := i%2 == 0; (err == nil) != listed {
			t.Fatalf("Lstat(%s) error = %v, want found %v", name, err, listed)
		}
	}
	for _, name := range []string{"a", "n", "n09999", "z"} {
		if _, err := tree.Lstat(name); err == nil {
			t.Fatalf("Lstat(%s) found an entry never laid out", name)
		}
	}
}

// The heap grows far less with the tree held than with the paths New was
// given, which measure over the bound themselves.
func TestNewKeepsNoneOfItsEntriesPaths(t *testing.T) {
	const files, dirLen = 4096, 4000
	const bound = files * dirLen / 8

	before := heapAlloc()
	entries := longPaths(files, dirLen)
	if after := heapAlloc(); after < before+bound {
		t.Fatalf("the paths themselves measure %d bytes, want over %d", after-before, bound)
	}
	runtime.KeepAlive(entries)

	before = heapAlloc()
	tree := treeOfLongPaths(t, files, dirLen)
	if after := heapAlloc(); after > before+bound {
		t.Fatalf("the tree holds %d bytes beside %d paths of %d bytes, want at most %d", after-before, files, dirLen, bound)
	}
	if _, err := tree.Lstat(strings.Repeat("d", dirLen) + "/7"); err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
}

func longPaths(files, dirLen int) []treefs.Entry {
	dir := strings.Repeat("d", dirLen)
	entries := make([]treefs.Entry, files)
	for i := range entries {
		entries[i] = treefs.Entry{Path: dir + "/" + strconv.Itoa(i), Mode: 0o644}
	}
	return entries
}

func treeOfLongPaths(t *testing.T, files, dirLen int) *treefs.FS {
	t.Helper()

	tree, err := treefs.New(longPaths(files, dirLen), held(nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return tree
}

func heapAlloc() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}
