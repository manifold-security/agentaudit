package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/manifold-security/agentaudit"
)

// The duplicate in b/ is refused before the name in a/c/ is, though a
// depth-first walk reaches a/c/ first.
func TestFetchRefusesAShallowFaultBeforeADeepOne(t *testing.T) {
	repo := newEmptyRepo()
	blob := storeBlob(t, repo.st, []byte("x"))
	named := storeObject(t, repo.st, &object.Tree{Entries: []object.TreeEntry{{Name: "..", Mode: filemode.Regular, Hash: blob}}})
	a := storeTree(t, repo.st, []object.TreeEntry{{Name: "c", Mode: filemode.Dir, Hash: named}})
	dup := storeObject(t, repo.st, &object.Tree{Entries: []object.TreeEntry{
		{Name: "x", Mode: filemode.Regular, Hash: blob},
		{Name: "x", Mode: filemode.Regular, Hash: blob},
	}})
	repo.refs["refs/heads/main"] = repo.commitTree(t, storeTree(t, repo.st, []object.TreeEntry{
		{Name: "a", Mode: filemode.Dir, Hash: a},
		{Name: "b", Mode: filemode.Dir, Hash: dup},
	}))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err == nil || !strings.Contains(err.Error(), `duplicate path "b/x"`) {
		t.Fatalf("Fetch() error = %v, want the duplicate in b/ refused before the name in a/c/", err)
	}
}

func TestFetchRefusesATreeEntryNameThatIsNotUTF8(t *testing.T) {
	repo := newEmptyRepo()
	cfg := storeTree(t, repo.st, []object.TreeEntry{{Name: ".mcp.json", Mode: filemode.Regular, Hash: storeBlob(t, repo.st, []byte(mcpJSON))}})
	repo.refs["refs/heads/main"] = repo.commitTree(t, storeTree(t, repo.st, []object.TreeEntry{{Name: "\xff\xfe", Mode: filemode.Dir, Hash: cfg}}))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err == nil || !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("Fetch() error = %v, want the name refused as an invalid path", err)
	}
}

// A file of mode 0o100750 reads, and a tree listed under two spellings of
// the directory mode is still stored when the second is laid out.
func TestFetchReadsThroughNonCanonicalModes(t *testing.T) {
	repo := newEmptyRepo()
	cfg := storeBlob(t, repo.st, []byte(mcpJSON))
	sub := storeTree(t, repo.st, []object.TreeEntry{{Name: ".mcp.json", Mode: filemode.FileMode(0o100750), Hash: cfg}})
	repo.refs["refs/heads/main"] = repo.commitTree(t, storeTree(t, repo.st, []object.TreeEntry{
		{Name: ".mcp.json", Mode: filemode.FileMode(0o100750), Hash: cfg},
		{Name: "a", Mode: filemode.Dir, Hash: sub},
		{Name: "b", Mode: filemode.FileMode(0o40755), Hash: sub},
	}))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	_, tree, err := fetch("https://github.com/o/r", "", DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	for _, name := range []string{".mcp.json", "a/.mcp.json", "b/.mcp.json"} {
		data, err := fs.ReadFile(tree, name)
		if err != nil || string(data) != mcpJSON {
			t.Fatalf("ReadFile(%s) = %q, %v; want the config", name, data, err)
		}
		if info, err := fs.Lstat(tree, name); err != nil || info.Mode() != 0o755 {
			t.Fatalf("Lstat(%s) = %v, %v; want mode -rwxr-xr-x", name, info, err)
		}
	}
}

// The tree reads blobs through what it needs alone, so the fetcher can be
// collected while the tree is in use.
func TestFetchedTreeKeepsNoFetcherAlive(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	u, err := ParseURL("https://github.com/o/r")
	if err != nil {
		t.Fatal(err)
	}

	f := newFetcher(context.Background(), DefaultLimits())
	collected := cleanupProbe(f, 3)
	adv, err := f.open(u)
	if err != nil {
		t.Fatalf("open() error = %v", err)
	}
	_, tree, err := f.fetch(adv, u, "", agentaudit.New())
	if err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if collected() {
		t.Fatal("the fetcher went while still referenced; the probe sees nothing")
	}
	runtime.KeepAlive(f)
	if !collected() {
		t.Fatal("the fetcher is still reachable from the tree it built")
	}
	if len(scanOf(t, tree).Findings()) == 0 {
		t.Fatal("the tree scanned to no finding after the fetcher went")
	}
}

// The store that held the trees is let go once they are laid out, though the
// fetcher and its tree are still in use.
func TestFetchedTreeKeepsNoTreeStoreAlive(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	u, err := ParseURL("https://github.com/o/r")
	if err != nil {
		t.Fatal(err)
	}

	f := newFetcher(context.Background(), DefaultLimits())
	collected := cleanupProbe(f.st, 3)
	if collected() {
		t.Fatal("the tree store went while still referenced; the probe sees nothing")
	}
	adv, err := f.open(u)
	if err != nil {
		t.Fatalf("open() error = %v", err)
	}
	_, tree, err := f.fetch(adv, u, "", agentaudit.New())
	if err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if !collected() {
		t.Fatal("the store that held the trees is still reachable from the fetcher or its tree")
	}
	runtime.KeepAlive(f)
	runtime.KeepAlive(tree)
}

func TestFetchCollectsAfterTheTreeFetchAndAfterTheRelease(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}, "d/e/f": {Data: []byte("f")}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	u, err := ParseURL("https://github.com/o/r")
	if err != nil {
		t.Fatal(err)
	}
	f := newFetcher(context.Background(), DefaultLimits())
	var stored []int
	var trees *memory.Storage
	saved := collect
	collect = func() {
		if trees == nil {
			trees = f.st
		}
		stored = append(stored, len(trees.Trees))
	}
	t.Cleanup(func() { collect = saved })

	adv, err := f.open(u)
	if err != nil {
		t.Fatalf("open() error = %v", err)
	}
	if _, _, err := f.fetch(adv, u, "", agentaudit.New()); err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if len(stored) != 2 || stored[0] == 0 || stored[1] != 0 {
		t.Fatalf("Fetch() collected with %v tree objects stored, want once with the trees and once with none", stored)
	}
}

// Identical directories nest, so a tree stored once is listed at several
// paths, below trees each listed at several.
func TestFetchListsATreeAtEveryPathThatNamesIt(t *testing.T) {
	files := fstest.MapFS{}
	for _, p := range []string{"x/x/x", "x/x/y", "x/y/x", "x/y/y", "y/x/x", "y/x/y", "y/y/x", "y/y/y"} {
		files[p+"/f"] = &fstest.MapFile{Data: []byte("f")}
	}
	repo, _ := newFakeRepo(t, files)
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	_, tree, err := fetch("https://github.com/o/r", "", DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	for p := range files {
		if _, err := fs.Lstat(tree, p); err != nil {
			t.Fatalf("Lstat(%s) error = %v", p, err)
		}
	}
}

// A directory with only directories below it is left out, though every
// entry below it still counts toward TreeEntries.
func TestFetchLeavesOutADirectoryWithOnlyDirectoriesBelowIt(t *testing.T) {
	repo := newEmptyRepo()
	empty := storeTree(t, repo.st, nil)
	holdsEmpty := storeTree(t, repo.st, []object.TreeEntry{{Name: "z", Mode: filemode.Dir, Hash: empty}})
	sub := storeTree(t, repo.st, []object.TreeEntry{{Name: ".mcp.json", Mode: filemode.Regular, Hash: storeBlob(t, repo.st, []byte(mcpJSON))}})
	rows := []struct {
		branch string
		claude []object.TreeEntry
		listed string
	}{
		{"empty", nil, ""},
		{"hollow", []object.TreeEntry{{Name: "x", Mode: filemode.Dir, Hash: holdsEmpty}, {Name: "y", Mode: filemode.Dir, Hash: holdsEmpty}}, ""},
		{"file", []object.TreeEntry{{Name: "x", Mode: filemode.Regular, Hash: storeBlob(t, repo.st, []byte("x"))}}, ".claude/x"},
		{"link", []object.TreeEntry{{Name: "settings.json", Mode: filemode.Symlink, Hash: storeBlob(t, repo.st, []byte("../sub/.mcp.json"))}}, ".claude/settings.json"},
		{"gitlink", []object.TreeEntry{{Name: "x", Mode: filemode.Submodule, Hash: plumbing.NewHash(strings.Repeat("1", 40))}}, ".claude/x"},
		{"treenamed", []object.TreeEntry{{Name: "x", Mode: filemode.Regular, Hash: empty}, {Name: "y", Mode: filemode.Dir, Hash: empty}}, ".claude/x"},
	}
	for _, row := range rows {
		repo.refs["refs/heads/"+row.branch] = repo.commitTree(t, storeTree(t, repo.st, []object.TreeEntry{
			{Name: ".claude", Mode: filemode.Dir, Hash: storeTree(t, repo.st, row.claude)},
			{Name: "sub", Mode: filemode.Dir, Hash: sub},
		}))
	}
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	for _, row := range rows {
		_, tree, err := fetch("https://github.com/o/r", row.branch, DefaultLimits())
		if err != nil {
			t.Fatalf("Fetch(%s) error = %v", row.branch, err)
		}
		projects, err := agentaudit.New().ScanRecursive(tree)
		if err != nil {
			t.Fatalf("ScanRecursive(%s) error = %v", row.branch, err)
		}
		var got []string
		for _, p := range projects {
			got = append(got, p.Path)
		}
		want := []string{"sub"}
		if row.listed != "" {
			want = []string{".", "sub"}
			if _, err := fs.Lstat(tree, row.listed); err != nil {
				t.Fatalf("Lstat(%s) on the %s branch: error = %v", row.listed, row.branch, err)
			}
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ScanRecursive() with the %s .claude found projects %q, want %q", row.branch, got, want)
		}
	}
	const entries = 7
	if _, _, err := fetch("https://github.com/o/r", "hollow", withLimits(func(l *Limits) { l.TreeEntries = entries })); err != nil {
		t.Fatalf("Fetch() with TreeEntries at the entries: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "hollow", withLimits(func(l *Limits) { l.TreeEntries = entries - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with TreeEntries one under the entries, .claude/x/z and .claude/y/z among them: error = %v, want ErrTooLarge", err)
	}
}

// Each level of the chain names the one below twice, so its leaf tree is
// listed 2^depth times; past the entry limit the count holds one above it.
func TestTreeRefsMultiplyDownTheTreeAndHoldAtTheLimit(t *testing.T) {
	st := memory.NewStorage()
	leaf := storeTree(t, st, []object.TreeEntry{{Name: "f", Mode: filemode.Regular, Hash: storeBlob(t, st, []byte("f"))}})
	h := leaf
	roots := map[int]plumbing.Hash{}
	for depth := 1; depth <= 70; depth++ {
		h = storeTree(t, st, []object.TreeEntry{{Name: "x", Mode: filemode.Dir, Hash: h}, {Name: "y", Mode: filemode.Dir, Hash: h}})
		roots[depth] = h
	}
	const entries = 999
	for depth, want := range map[int]int{3: 8, 9: 512, 10: entries + 1, 70: entries + 1} {
		refs, _, err := treeRefs(st, roots[depth], entries)
		if err != nil || refs[leaf] != want {
			t.Fatalf("treeRefs() at depth %d counts the leaf %d time(s), %v, want %d", depth, refs[leaf], err, want)
		}
	}
}

// The count stops at the first entry past the limit, as the listing would,
// so trees too many to list are not each read and counted first.
func TestTreeRefsStopAtTheFirstEntryPastTheLimit(t *testing.T) {
	st := memory.NewStorage()
	var mids []object.TreeEntry
	for m := range 20 {
		var leaves []object.TreeEntry
		for i := range 1000 {
			blob := plumbing.ComputeHash(plumbing.BlobObject, []byte(fmt.Sprintf("%d/%d", m, i)))
			leaf := storeTree(t, st, []object.TreeEntry{{Name: "f", Mode: filemode.Regular, Hash: blob}})
			leaves = append(leaves, object.TreeEntry{Name: fmt.Sprintf("d%04d", i), Mode: filemode.Dir, Hash: leaf})
		}
		mids = append(mids, object.TreeEntry{Name: fmt.Sprintf("m%02d", m), Mode: filemode.Dir, Hash: storeTree(t, st, leaves)})
	}
	root := storeTree(t, st, mids)
	const entries = 20 + 2*20*1000

	walked := totalAlloc(func() {
		if _, _, err := treeRefs(st, root, entries); err != nil {
			t.Fatalf("treeRefs() with the entries at the limit: error = %v", err)
		}
	})
	if _, _, err := treeRefs(st, root, entries-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("treeRefs() one entry under the trees' count: error = %v, want ErrTooLarge", err)
	}
	var err error
	stopped := totalAlloc(func() { _, _, err = treeRefs(st, root, 10) })
	if !errors.Is(err, ErrTooLarge) || stopped*8 > walked {
		t.Fatalf("treeRefs() with a limit of 10: error = %v after %d bytes, want ErrTooLarge well under the %d bytes of a full count", err, stopped, walked)
	}
}

func TestFetchCountsATreeTowardTreeEntriesAtEveryPathThatNamesIt(t *testing.T) {
	repo := newEmptyRepo()
	h := storeTree(t, repo.st, []object.TreeEntry{{Name: "f", Mode: filemode.Regular, Hash: storeBlob(t, repo.st, []byte("f"))}})
	const depth = 7
	for range depth {
		h = storeTree(t, repo.st, []object.TreeEntry{{Name: "x", Mode: filemode.Dir, Hash: h}, {Name: "y", Mode: filemode.Dir, Hash: h}})
	}
	repo.refs["refs/heads/main"] = repo.commitTree(t, h)
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	const dirs, files = 1<<(depth+1) - 2, 1 << depth
	const listed = dirs + files

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TreeEntries = listed })); err != nil {
		t.Fatalf("Fetch() with TreeEntries at the %d entries listed: error = %v", listed, err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TreeEntries = listed - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with TreeEntries one under the %d entries listed: error = %v, want ErrTooLarge", listed, err)
	}
}

func TestFetchNamesAMissingSubtreeByItsPath(t *testing.T) {
	repo, under := nestedRepo(t, []string{"a", "b", "c"}, "f")
	repo.omit = under[1]
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err == nil || !strings.Contains(err.Error(), `the tree at "a/b"`) {
		t.Fatalf("Fetch() error = %v, want the tree at a/b named", err)
	}
}

// A pack prescan or storePack has read goes at the first collection, where
// a pack still held does not.
func TestAReadPackIsCollectableAfterOneCollection(t *testing.T) {
	held := encodedPack(t)
	if cleanupProbe(&held[0], 1)() {
		t.Fatal("a held pack went at the first collection; the probe sees nothing")
	}
	runtime.KeepAlive(held)

	for name, read := range map[string]func([]byte) error{
		"prescan": func(pack []byte) error {
			_, _, err := prescan(context.Background(), pack, DefaultLimits(), 0)
			return err
		},
		"storePack": func(pack []byte) error { return storePack(memory.NewStorage(), pack) },
	} {
		t.Run(name, func(t *testing.T) {
			pack := encodedPack(t)
			collected := cleanupProbe(&pack[0], 1)
			if err := read(pack); err != nil {
				t.Fatalf("%s() error = %v", name, err)
			}
			pack = nil

			if !collected() {
				t.Fatalf("the pack %s read is still reachable after one collection", name)
			}
		})
	}
}

func TestADropReaderScansAsSeekable(t *testing.T) {
	if !packfile.NewScanner(&dropReader{bytes.NewReader(nil)}).IsSeekable {
		t.Fatal("go-git scans a dropReader as unseekable")
	}
}

func encodedPack(t *testing.T) []byte {
	t.Helper()
	repo, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}, "d/f": {Data: []byte(strings.Repeat("f", 4096))}})
	var hashes []plumbing.Hash
	for h := range repo.st.Objects {
		hashes = append(hashes, h)
	}
	var buf bytes.Buffer
	if _, err := packfile.NewEncoder(&buf, repo.st, false).Encode(hashes, 10); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(buf.Bytes())
}

func cleanupProbe[T any](ptr *T, collections int) func() bool {
	done := make(chan struct{})
	runtime.AddCleanup(ptr, func(done chan struct{}) { close(done) }, done)
	return func() bool {
		for range collections {
			runtime.GC()
			select {
			case <-done:
				return true
			default:
			}
		}
		select {
		case <-done:
			return true
		case <-time.After(time.Second):
			return false
		}
	}
}
