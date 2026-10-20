package remote

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"

	"github.com/manifold-security/agentaudit"
)

func withLimits(change func(*Limits)) Limits {
	l := DefaultLimits()
	change(&l)
	return l
}

func paddedJSON(n int) []byte {
	return []byte(`{"x":"` + strings.Repeat("a", n-8) + `"}`)
}

func randomText(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(raw)[:n])
}

func objectSize(t *testing.T, repo *fakeRepo, h plumbing.Hash) int64 {
	t.Helper()
	n, err := repo.st.EncodedObjectSize(h)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func scanOf(t *testing.T, fsys fs.FS) agentaudit.Report {
	t.Helper()
	report, err := agentaudit.New().Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return report
}

func timesWanted(log []fakeRequest, h plumbing.Hash) int {
	n := 0
	for _, req := range log {
		for _, want := range req.wants {
			if want == h {
				n++
			}
		}
	}
	return n
}

func TestDefaultLimitsAreTheContractValues(t *testing.T) {
	want := Limits{Rounds: 8, TreeEntries: 200_000, PathBytes: 32 << 20, Files: 2_000, RefsBytes: 32 << 20, PackBytes: 16 << 20, FileBytes: 5 << 20, TotalBytes: 64 << 20}
	if got := DefaultLimits(); got != want {
		t.Fatalf("DefaultLimits() = %+v, want %+v", got, want)
	}
}

func TestFetchRefusesANonPositiveLimitBeforeAnyRequest(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	for name, zero := range map[string]func(*Limits){
		"Rounds":      func(l *Limits) { l.Rounds = 0 },
		"TreeEntries": func(l *Limits) { l.TreeEntries = 0 },
		"PathBytes":   func(l *Limits) { l.PathBytes = 0 },
		"Files":       func(l *Limits) { l.Files = 0 },
		"RefsBytes":   func(l *Limits) { l.RefsBytes = 0 },
		"PackBytes":   func(l *Limits) { l.PackBytes = 0 },
		"FileBytes":   func(l *Limits) { l.FileBytes = -1 },
		"TotalBytes":  func(l *Limits) { l.TotalBytes = 0 },
	} {
		if _, _, err := fetch("https://github.com/o/r", "", withLimits(zero)); err == nil {
			t.Fatalf("Fetch() with %s not positive: error = nil", name)
		}
	}
	if log := f.requests(); len(log) != 0 {
		t.Fatalf("requests = %+v, want none", log)
	}

	largest := Limits{Rounds: math.MaxInt, TreeEntries: math.MaxInt, PathBytes: math.MaxInt64, Files: math.MaxInt, RefsBytes: math.MaxInt64, PackBytes: math.MaxInt64, FileBytes: math.MaxInt64, TotalBytes: math.MaxInt64}
	for _, l := range []Limits{DefaultLimits(), largest} {
		if _, _, err := fetch("https://github.com/o/r", "", l); err != nil {
			t.Fatalf("Fetch() with %+v: error = %v", l, err)
		}
	}
	if log := f.requests(); len(log) == 0 {
		t.Fatal("requests = none after fetches with positive limits; the fake is not the one asked")
	}
}

func TestFetchCapsTheAdvertisementAtRefsBytesAndEachPackAtPackBytes(t *testing.T) {
	sizes := func(t *testing.T, f *fakeGit) (adv, pack int64, largest int) {
		t.Helper()
		if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		log := f.requests()
		adv = int64(log[0].bytes)
		for i := 1; i < len(log); i++ {
			if n := int64(log[i].bytes); n > pack {
				pack, largest = n, i
			}
		}
		return adv, pack, largest
	}
	capped := func(refs, pack int64) Limits {
		return withLimits(func(l *Limits) { l.RefsBytes, l.PackBytes = refs, pack })
	}

	t.Run("advertisement", func(t *testing.T) {
		repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
		for i := 0; i < 2000; i++ {
			repo.refs[fmt.Sprintf("refs/heads/branch-%04d", i)] = repo.refs["refs/heads/main"]
		}
		f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
		useFake(t, f)
		adv, pack, _ := sizes(t, f)
		if 10*pack > adv {
			t.Fatalf("the largest pack, %d bytes, is over a tenth of the %d-byte advertisement this row bounds", pack, adv)
		}

		if _, _, err := fetch("https://github.com/o/r", "", capped(adv, pack)); err != nil {
			t.Fatalf("Fetch() with RefsBytes at the advertisement's size: error = %v", err)
		}
		before := len(f.requests())
		if _, _, err := fetch("https://github.com/o/r", "", capped(adv-1, pack)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Fetch() with RefsBytes one below the advertisement: error = %v, want ErrTooLarge", err)
		}
		if after := f.requests()[before:]; len(after) != 1 {
			t.Fatalf("requests after an oversized advertisement = %+v, want the GET alone", after)
		}
	})

	manyFiles := fstest.MapFS{}
	for i := 0; i < 2000; i++ {
		manyFiles[fmt.Sprintf("file-%04d.txt", i)] = &fstest.MapFile{Data: []byte("x")}
	}
	for name, tc := range map[string]struct {
		files   fstest.MapFS
		largest int
	}{
		"the trees":       {manyFiles, 1},
		"a round's blobs": {oneFile(".mcp.json", string(randomText(t, 64<<10))), 2},
	} {
		t.Run(name, func(t *testing.T) {
			repo, _ := newFakeRepo(t, tc.files)
			f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
			useFake(t, f)
			adv, pack, largest := sizes(t, f)
			if largest != tc.largest {
				t.Fatalf("the largest response is request %d, want %d", largest, tc.largest)
			}
			if 10*adv > pack {
				t.Fatalf("the %d-byte advertisement is over a tenth of the largest pack, %d bytes, this row bounds", adv, pack)
			}

			if _, _, err := fetch("https://github.com/o/r", "", capped(adv, pack)); err != nil {
				t.Fatalf("Fetch() with PackBytes at the largest pack's size: error = %v", err)
			}
			if _, _, err := fetch("https://github.com/o/r", "", capped(adv, pack-1)); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Fetch() with PackBytes one below the largest pack: error = %v, want ErrTooLarge", err)
			}
		})
	}
}

// A blob over FileBytes is left out and requested once; the scan then counts
// its path unreadable, while a blob at the limit arrives.
func TestFetchWithholdsABlobOverFileBytes(t *testing.T) {
	const limit = 1000
	repo, commit := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: randomText(t, limit)},
		".claude/settings.json": {Data: randomText(t, limit+1)},
	})
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	_, tree, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = limit }))
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if data, err := fs.ReadFile(tree, ".mcp.json"); err != nil || len(data) != limit {
		t.Fatalf("ReadFile(.mcp.json) = %d bytes, %v, want the %d-byte blob", len(data), err, limit)
	}
	if _, err := fs.ReadFile(tree, ".claude/settings.json"); err == nil {
		t.Fatal("ReadFile(.claude/settings.json) error = nil, want the over-limit blob withheld")
	}
	if got := scanOf(t, tree).UnreadableSources(); got != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1", got)
	}
	if n := timesWanted(f.requests(), blobHash(t, repo, commit, ".claude/settings.json")); n != 1 {
		t.Fatalf("the over-limit blob was wanted %d times, want once", n)
	}
}

func TestFetchRefusesATreeOverFileBytes(t *testing.T) {
	files := fstest.MapFS{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("file-%02d.txt", i)] = &fstest.MapFile{Data: []byte{byte(i)}}
	}
	repo, commit := newFakeRepo(t, files)
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	c := commitObject(t, repo, commit)
	size := objectSize(t, repo, c.TreeHash)
	if objectSize(t, repo, commit) >= size {
		t.Fatalf("the commit is not below the %d-byte tree this row bounds", size)
	}

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = size })); err != nil {
		t.Fatalf("Fetch() with FileBytes at the tree's size: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = size - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with FileBytes one below the tree: error = %v, want ErrTooLarge", err)
	}
}

// A delta is judged by the size it inflates to, not by its own data.
func TestFetchRefusesADeltaWhoseTargetIsOverFileBytes(t *testing.T) {
	const size = 4000
	base := paddedJSON(size)
	similar := bytes.Clone(base)
	similar[size/2] = 'b'
	repo, commit := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: base},
		".claude/settings.json": {Data: similar},
	})
	assertPackDeltifies(t, repo, blobHash(t, repo, commit, ".mcp.json"), blobHash(t, repo, commit, ".claude/settings.json"))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = size })); err != nil {
		t.Fatalf("Fetch() with FileBytes at the target's size: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = size - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with FileBytes one below the target: error = %v, want ErrTooLarge", err)
	}
}

func assertPackDeltifies(t *testing.T, repo *fakeRepo, hashes ...plumbing.Hash) {
	t.Helper()
	var pack bytes.Buffer
	if _, err := packfile.NewEncoder(&pack, repo.st, false).Encode(hashes, 10); err != nil {
		t.Fatal(err)
	}
	s := packfile.NewScanner(bytes.NewReader(pack.Bytes()))
	_, n, err := s.Header()
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < n; i++ {
		h, err := s.NextObjectHeader()
		if err != nil {
			t.Fatal(err)
		}
		if h.Type == plumbing.OFSDeltaObject || h.Type == plumbing.REFDeltaObject {
			return
		}
	}
	t.Fatal("the pack holds no delta; this row would not reach the delta check")
}

// The total counts the commit and the trees as well as the blobs.
func TestFetchRefusesARunningTotalOverTotalBytes(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: randomText(t, 3000)},
		".claude/settings.json": {Data: randomText(t, 3000)},
	})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	var total int64
	for h := range repo.st.Objects {
		total += objectSize(t, repo, h)
	}

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TotalBytes = total })); err != nil {
		t.Fatalf("Fetch() with TotalBytes at the sum: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TotalBytes = total - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with TotalBytes one below the sum: error = %v, want ErrTooLarge", err)
	}
}

func TestFetchRefusesMoreTreeEntriesThanTreeEntries(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{"a": {Data: []byte("a")}, "d/b": {Data: []byte("b")}, "d/c": {Data: []byte("c")}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	const entries = 4

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TreeEntries = entries })); err != nil {
		t.Fatalf("Fetch() with TreeEntries at the count: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TreeEntries = entries - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with TreeEntries one below the count: error = %v, want ErrTooLarge", err)
	}
}

func TestFetchRefusesMoreBlobsThanFiles(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: []byte(mcpJSON)},
		".claude/settings.json": {Data: []byte(`{}`)},
		".cursor/mcp.json":      {Data: []byte(`{"mcpServers":{}}`)},
	})
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)
	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	blobs := map[plumbing.Hash]bool{}
	for _, req := range f.requests()[2:] {
		for _, want := range req.wants {
			blobs[want] = true
		}
	}
	if len(blobs) < 2 {
		t.Fatalf("the fetch asked for %d blob(s); this row needs at least two", len(blobs))
	}

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.Files = len(blobs) })); err != nil {
		t.Fatalf("Fetch() with Files at the count: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.Files = len(blobs) - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with Files one below the count: error = %v, want ErrTooLarge", err)
	}
}

func TestWantedStopsAtTheFirstBlobPastFilesAndWantsEachBlobOnce(t *testing.T) {
	const asked = 1000
	hashes := make([]plumbing.Hash, asked)
	for i := range hashes {
		hashes[i] = plumbing.ComputeHash(plumbing.BlobObject, []byte(fmt.Sprintf("p%04d", i)))
	}
	drawn := 0
	counted := func(yield func(plumbing.Hash) bool) {
		for _, h := range hashes {
			drawn++
			if !yield(h) {
				return
			}
		}
	}
	fetcherWith := func(files int) *fetcher {
		return &fetcher{l: Limits{Files: files}, fetched: map[plumbing.Hash]bool{}, withheld: map[plumbing.Hash]bool{}}
	}

	for files, wantDrawn := range map[int]int{asked: asked, 10: 11} {
		drawn = 0
		wants, err := fetcherWith(files).wanted(counted)
		if files < asked && !errors.Is(err, ErrTooLarge) {
			t.Fatalf("wanted() with Files %d: error = %v, want ErrTooLarge", files, err)
		}
		if files == asked && (err != nil || len(wants) != asked) {
			t.Fatalf("wanted() with Files %d = %d blobs, %v, want all %d", files, len(wants), err, asked)
		}
		if drawn != wantDrawn {
			t.Fatalf("wanted() with Files %d drew %d missed blobs, want %d", files, drawn, wantDrawn)
		}
	}

	wants, err := fetcherWith(asked).wanted(slices.Values([]plumbing.Hash{hashes[0], hashes[0], hashes[1], hashes[1]}))
	if err != nil || len(wants) != 2 {
		t.Fatalf("wanted() over two blobs each missed twice = %v, %v, want 2 blobs", wants, err)
	}
}

// Directories count toward TreeEntries as files do, so depth alone reaches
// the cap, and the listing is refused before any blob is asked for.
func TestFetchCountsEveryDirectoryTowardTreeEntries(t *testing.T) {
	const depth = 10
	repo, _ := newFakeRepo(t, fstest.MapFS{
		".mcp.json":                         {Data: []byte(mcpJSON)},
		strings.Repeat("d/", depth) + "end": {Data: []byte("end")},
	})
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() under DefaultLimits: error = %v", err)
	}
	if log := f.requests(); len(log) != 3 {
		t.Fatalf("requests under DefaultLimits = %+v, want the GET, the tree POST and a blob POST", log)
	}
	before := len(f.requests())
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.TreeEntries = depth })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with TreeEntries %d over a file %d directories deep: error = %v, want ErrTooLarge", depth, depth, err)
	}
	if log := f.requests()[before:]; len(log) != 2 {
		t.Fatalf("requests = %+v, want the GET and the tree POST alone, with no blob asked for", log)
	}
}

// Every path the listing names, directories included, counts toward
// PathBytes, and the listing stops at the path that passes it before it
// reads the tree that path names: the second repository's pack leaves that
// tree out.
func TestFetchRefusesPathsPastPathBytesBeforeReadingBelowThem(t *testing.T) {
	repo, _ := nestedRepo(t, []string{"aaaa", "bbbb"}, "f")
	cut, under := nestedRepo(t, []string{"aaaa", "bbbb"}, "f")
	cut.omit = under[1]
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo, "o/cut": cut}})
	sum := int64(len("aaaa") + len("aaaa/bbbb") + len("aaaa/bbbb/f"))

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.PathBytes = sum })); err != nil {
		t.Fatalf("Fetch() with PathBytes at the paths' sum: error = %v", err)
	}
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.PathBytes = sum - 1 })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with PathBytes one below the sum: error = %v, want ErrTooLarge", err)
	}
	crossing := int64(len("aaaa") + len("aaaa/bbbb") - 1)
	if _, _, err := fetch("https://github.com/o/cut", "", withLimits(func(l *Limits) { l.PathBytes = crossing })); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() with PathBytes passed at a directory whose tree is left out: error = %v, want ErrTooLarge", err)
	}
}

// The plugin's component is read only once its manifest has been, so a
// single round leaves it unasked and the sealed tree counts it unreadable.
func TestFetchWithholdsWhatIsStillUnaskedAfterRounds(t *testing.T) {
	repo, _ := newFakeRepo(t, rootFS(t, "../testdata/malicious/claude-plugin-components"))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	for rounds, want := range map[int]int{1: 1, 2: 0} {
		_, tree, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.Rounds = rounds }))
		if err != nil {
			t.Fatalf("Fetch() with Rounds %d: error = %v", rounds, err)
		}
		if got := scanOf(t, tree).UnreadableSources(); got != want {
			t.Fatalf("Rounds %d: UnreadableSources() = %d, want %d", rounds, got, want)
		}
	}
}

func TestFetchAsksRoundByRoundUntilTheScanReadsNothingNew(t *testing.T) {
	repo, _ := newFakeRepo(t, rootFS(t, "../testdata/malicious/claude-plugin-components"))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	var wants []int
	for _, req := range f.requests()[1:] {
		wants = append(wants, len(req.wants))
	}
	if fmt.Sprint(wants) != "[1 6 1]" {
		t.Fatalf("POSTs want %v objects, want [1 6 1]: the commit, then each round's new blobs", wants)
	}
}

func TestFetchRefusesAnOversizedBlobItDidNotAskFor(t *testing.T) {
	fetchSmall := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := Fetch(ctx, "https://github.com/o/r", "", agentaudit.New(), withLimits(func(l *Limits) { l.FileBytes = 1000 })); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Fetch() error = %v, want ErrTooLarge", err)
		}
	}
	t.Run("with the trees", func(t *testing.T) {
		repo, _ := newFakeRepo(t, oneFile(".mcp.json", string(paddedJSON(2000))))
		useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}, ignoreFilter: true})
		fetchSmall(t)
	})
	t.Run("with a round's blobs", func(t *testing.T) {
		repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
		repo.extra = storeBlob(t, repo.st, randomText(t, 2000))
		useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
		fetchSmall(t)
	})
}

func TestFetchAsksForAWithheldBlobOnce(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: paddedJSON(2000)},
		".claude/settings.json": {Data: []byte(`{}`)},
	})
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	if _, _, err := fetch("https://github.com/o/r", "", withLimits(func(l *Limits) { l.FileBytes = 1000 })); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	log := f.requests()
	if n := timesWanted(log, blobHash(t, repo, commit, ".mcp.json")); n != 1 {
		t.Fatalf("the withheld blob was wanted %d times, want once", n)
	}
	if len(log) != 4 {
		t.Fatalf("requests = %d, want the GET, the tree POST, the round's POST and its retry without the withheld blob", len(log))
	}
}

// Each object here is the pack's first, so the running total is zero when
// its header declares a size far past the limits over a stream that holds
// almost nothing.
func TestPrescanRefusesADeclaredSizeWithoutInflating(t *testing.T) {
	for _, tc := range []struct {
		typ  plumbing.ObjectType
		base []byte
	}{
		{plumbing.BlobObject, nil},
		{plumbing.TreeObject, nil},
		{plumbing.REFDeltaObject, make([]byte, 20)},
	} {
		t.Run(tc.typ.String(), func(t *testing.T) {
			pack := handBuiltPack(tc.typ, 1<<30, tc.base, []byte("x"))
			if _, _, err := prescan(context.Background(), pack, DefaultLimits(), 0); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("prescan() error = %v, want ErrTooLarge", err)
			}
		})
	}
}

// handBuiltPack declares a size its zlib stream need not hold.
func handBuiltPack(typ plumbing.ObjectType, declared int64, deltaBase, data []byte) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, uint32(2))
	_ = binary.Write(&b, binary.BigEndian, uint32(1))
	c := byte(int(typ)&0x07)<<4 | byte(declared&0x0f)
	for size := declared >> 4; size > 0; size >>= 7 {
		b.WriteByte(c | 0x80)
		c = byte(size & 0x7f)
	}
	b.WriteByte(c)
	b.Write(deltaBase)
	zw := zlib.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	b.Write(make([]byte, 20))
	return b.Bytes()
}

func totalAlloc(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestPrescanStopsOnTheContext(t *testing.T) {
	repo, commit := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	var pack bytes.Buffer
	if _, err := packfile.NewEncoder(&pack, repo.st, false).Encode([]plumbing.Hash{commit, commitObject(t, repo, commit).TreeHash}, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prescan(context.Background(), pack.Bytes(), DefaultLimits(), 0); err != nil {
		t.Fatalf("prescan() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := prescan(ctx, pack.Bytes(), DefaultLimits(), 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("prescan() with a cancelled context: error = %v, want context.Canceled", err)
	}
}

func TestCtxWriterReturnsTheContextErrorOnceDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := ctxWriter{ctx: ctx, w: io.Discard}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("Write() before cancel: error = %v", err)
	}
	cancel()
	if _, err := w.Write([]byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write() after cancel: error = %v, want context.Canceled", err)
	}
}

const bigBlob = 64 << 20

func bigLimits(l *Limits) {
	l.FileBytes = 1 << 20
	l.TotalBytes = 128 << 20
}

func TestFetchWithholdsA64MiBBlobWithoutHoldingIt(t *testing.T) {
	repo, commit := newFakeRepo(t, oneFile(".mcp.json", strings.Repeat(" ", bigBlob)))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(bigLimits)); err != nil {
		t.Fatalf("warm-up Fetch() error = %v", err)
	}
	before := len(f.requests())

	var err error
	var tree fs.FS
	alloc := totalAlloc(func() { _, tree, err = fetch("https://github.com/o/r", "", withLimits(bigLimits)) })
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	t.Logf("Fetch() allocated %d bytes", alloc)
	if alloc > 16<<20 {
		t.Fatalf("Fetch() allocated %d bytes, want under 16 MiB", alloc)
	}
	if got := scanOf(t, tree).UnreadableSources(); got != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1", got)
	}
	if n := timesWanted(f.requests()[before:], blobHash(t, repo, commit, ".mcp.json")); n != 1 {
		t.Fatalf("the 64 MiB blob was wanted %d times, want once", n)
	}

	assertAllocSeesHeldBlobs(t, f, withLimits(func(l *Limits) { bigLimits(l); l.FileBytes = bigBlob }))
}

func TestFetchRefusesTwoSimilar64MiBBlobsWithoutHoldingThem(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{
		".mcp.json":             {Data: bytes.Repeat([]byte{' '}, bigBlob)},
		".claude/settings.json": {Data: append(bytes.Repeat([]byte{' '}, bigBlob), 'x')},
	})
	assertPackDeltifies(t, repo, blobHash(t, repo, commit, ".mcp.json"), blobHash(t, repo, commit, ".claude/settings.json"))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)
	if _, _, err := fetch("https://github.com/o/r", "", withLimits(bigLimits)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("warm-up Fetch() error = %v, want ErrTooLarge", err)
	}

	var err error
	alloc := totalAlloc(func() { _, _, err = fetch("https://github.com/o/r", "", withLimits(bigLimits)) })
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Fetch() error = %v, want ErrTooLarge", err)
	}
	t.Logf("Fetch() allocated %d bytes", alloc)
	if alloc > 16<<20 {
		t.Fatalf("Fetch() allocated %d bytes, want under 16 MiB", alloc)
	}

	assertAllocSeesHeldBlobs(t, f, withLimits(func(l *Limits) { l.FileBytes, l.TotalBytes = bigBlob+1, 4*bigBlob }))
}

func assertAllocSeesHeldBlobs(t *testing.T, f *fakeGit, admitting Limits) {
	t.Helper()
	encoded := f.encodedBodies()
	if encoded == 0 {
		t.Fatal("the fake counted no encode in the fetches before the measured one")
	}
	var err error
	alloc := totalAlloc(func() { _, _, err = fetch("https://github.com/o/r", "", admitting) })
	if err != nil {
		t.Fatalf("Fetch() with limits admitting the blobs: error = %v", err)
	}
	if f.encodedBodies() != encoded {
		t.Fatal("the fake encoded a response inside the measured Fetch")
	}
	if alloc <= bigBlob {
		t.Fatalf("Fetch() with limits admitting the blobs allocated %d bytes, want over %d", alloc, bigBlob)
	}
}
