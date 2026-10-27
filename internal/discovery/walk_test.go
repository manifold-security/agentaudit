package discovery

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
)

type statFailWalkFS struct {
	m        fstest.MapFS
	failPath string
}

func (f statFailWalkFS) Open(name string) (fs.File, error)          { return f.m.Open(name) }
func (f statFailWalkFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }

func (f statFailWalkFS) Stat(name string) (fs.FileInfo, error) {
	if name == f.failPath {
		return nil, errors.New("simulated stat failure")
	}
	return fs.Stat(f.m, name)
}

// A relative symlink to an in-tree directory is presented as that directory,
// and its own contents are visited under the symlink's path.
func TestWalkTree_SymlinkedDirectoryResolvingInTreeIsDescended(t *testing.T) {
	fsys := fstest.MapFS{
		"real/file.txt": &fstest.MapFile{Data: []byte("x")},
		"link":          &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink},
	}

	visited := map[string]bool{}
	var linkIsDir bool
	_, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		visited[p] = true
		if p == "link" {
			linkIsDir = d.IsDir()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}

	for _, want := range []string{".", "real", "real/file.txt", "link", "link/file.txt"} {
		if !visited[want] {
			t.Fatalf("visited = %v, want it to include %q", visited, want)
		}
	}
	if !linkIsDir {
		t.Fatal("link's DirEntry.IsDir() = false, want the resolved directory entry so a caller inspecting IsDir() (as Projects does for fs.SkipDir) sees it as a directory")
	}
}

// A symlink resolving to a non-directory is visited as its own unresolved
// entry, never followed.
func TestWalkTree_SymlinkedFileIsVisitedUnfollowedNeverDescended(t *testing.T) {
	fsys := fstest.MapFS{
		"real.txt": &fstest.MapFile{Data: []byte("x")},
		"link.txt": &fstest.MapFile{Data: []byte("real.txt"), Mode: fs.ModeSymlink},
	}

	var gotType fs.FileMode
	found := false
	_, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		if p == "link.txt" {
			found = true
			gotType = d.Type()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	if !found {
		t.Fatal("link.txt never visited")
	}
	if gotType&fs.ModeSymlink == 0 {
		t.Fatalf("link.txt DirEntry type = %v, want the symlink type preserved (unfollowed)", gotType)
	}
}

// A Stat failure while resolving a symlink degrades to an adapter.Warning
// naming the path, and the walk continues past it.
func TestWalkTree_SymlinkStatFailureWarnsAndContinues(t *testing.T) {
	fsys := statFailWalkFS{
		m: fstest.MapFS{
			"broken-link": &fstest.MapFile{Data: []byte("nowhere"), Mode: fs.ModeSymlink},
			"sibling.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failPath: "broken-link",
	}

	var visitedSibling, visitedBroken bool
	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		if p == "sibling.txt" {
			visitedSibling = true
		}
		if p == "broken-link" {
			visitedBroken = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil (a below-root failure must warn, never abort)", err)
	}
	if len(warnings) != 1 || warnings[0].File != "broken-link" {
		t.Fatalf("warnings = %+v, want exactly one naming broken-link", warnings)
	}
	if !visitedSibling {
		t.Fatal("sibling.txt never visited, want the walk to continue past the failed symlink")
	}
	if !visitedBroken {
		t.Fatal("broken-link never visited, want it visited unfollowed despite the Stat failure")
	}
}

// A failure resolving the walk root itself is fatal, never degraded to a
// warning.
func TestWalkTree_RootStatFailureStaysFatal(t *testing.T) {
	fsys := statFailWalkFS{
		m:        fstest.MapFS{"file.txt": &fstest.MapFile{Data: []byte("x")}},
		failPath: ".",
	}

	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error { return nil })
	if err == nil {
		t.Fatal("walkTree() error = nil, want non-nil for a root Stat failure")
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none (a root failure is provably warning-free)", warnings)
	}
}

// A symlinked directory's own path is not visited twice — once unfollowed by
// the outer walk and again as the nested descent's own root — and neither is
// any descendant.
func TestWalkTree_EachPathVisitedExactlyOnce(t *testing.T) {
	fsys := fstest.MapFS{
		"real/nested/file.txt": &fstest.MapFile{Data: []byte("x")},
		"link":                 &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink},
	}

	counts := map[string]int{}
	_, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		counts[p]++
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	for p, c := range counts {
		if c != 1 {
			t.Fatalf("path %q visited %d times, want exactly once (all counts: %v)", p, c, counts)
		}
	}
	if counts["link"] == 0 || counts["link/nested/file.txt"] == 0 {
		t.Fatalf("counts = %v, want link and its resolved descendant visited", counts)
	}
}

// Exhausting the resolution budget refuses further symlinked-directory
// resolutions with a counted warning, while the walk itself keeps going: a
// plain, non-symlinked sibling is still fully visited.
func TestWalkTree_SymlinkResolutionBudgetExhaustionWarnsAndContinuesWalk(t *testing.T) {
	fsys := fstest.MapFS{
		"plain/inside.txt": &fstest.MapFile{Data: []byte("x")},
	}
	extra := 5
	total := symlinkResolutionBudget + extra
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("real%d", i)
		fsys[name+"/marker.txt"] = &fstest.MapFile{Data: []byte("x")}
		fsys[fmt.Sprintf("link%d", i)] = &fstest.MapFile{Data: []byte(name), Mode: fs.ModeSymlink}
	}

	var visitedPlain bool
	var resolvedCount int
	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		if p == "plain/inside.txt" {
			visitedPlain = true
		}
		if strings.HasPrefix(p, "link") && d.IsDir() {
			resolvedCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	if !visitedPlain {
		t.Fatal("plain/inside.txt never visited, want the walk to continue past budget exhaustion")
	}
	if resolvedCount != symlinkResolutionBudget {
		t.Fatalf("resolved %d symlinked directories, want exactly the budget (%d)", resolvedCount, symlinkResolutionBudget)
	}

	var refused int
	for _, w := range warnings {
		if strings.HasPrefix(w.File, "link") && errors.Is(w.Err, adapter.ErrUnreadable) {
			refused++
		}
	}
	if refused != extra {
		t.Fatalf("refused %d symlinked directories, want exactly the %d beyond budget", refused, extra)
	}
}

// Links back to their own directory add at most the visit cap to the walk:
// its warnings stay within one per visit plus one per stopped descent, the
// stopped descents are refused by name, and the walk still reaches what lies
// past the links.
func TestWalkTree_SelfLinkedDirectoryAddsAtMostTheVisitCap(t *testing.T) {
	const dangling, selfLinks = 1000, 3
	fsys := fstest.MapFS{
		"zz-plain/inside.txt": &fstest.MapFile{Data: []byte("x")},
	}
	for i := range dangling {
		fsys[fmt.Sprintf("cmds/c%04d.md", i)] = &fstest.MapFile{Data: []byte("nowhere"), Mode: fs.ModeSymlink}
	}
	for i := range selfLinks {
		fsys[fmt.Sprintf("cmds/z%d", i)] = &fstest.MapFile{Data: []byte("."), Mode: fs.ModeSymlink}
	}
	listed := listedWithoutLinks(t, fsys)
	limit := max(listed, symlinkVisitFloor)

	visits := 0
	var visitedPlain bool
	warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		visits++
		visitedPlain = visitedPlain || p == "zz-plain/inside.txt"
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	if beneath := visits - listed; beneath != limit {
		t.Fatalf("visited %d entries beneath resolved links, want the cap of %d", beneath, limit)
	}
	if most := listed + limit + symlinkResolutionBudget; len(warnings) > most {
		t.Fatalf("walk retained %d warnings, want at most %d (one per visit, plus one per stopped descent)", len(warnings), most)
	}
	if !visitedPlain {
		t.Fatal("zz-plain/inside.txt never visited, want the walk to continue past the spent budget")
	}
	refused := 0
	for _, w := range warnings {
		if errors.Is(w.Err, adapter.ErrUnreadable) {
			if !strings.HasPrefix(w.File, "cmds/z") {
				t.Fatalf("refused %q, want only the links", w.File)
			}
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no refusal, want the spent budget to stop the links")
	}
}

// The cap is inclusive whether the floor or the listing sets it, and a
// stopped descent also skips the subdirectories after it.
func TestWalkTree_LinkVisitCapIsTheFloorOrTheListedEntryCount(t *testing.T) {
	const half = symlinkVisitFloor / 2
	tests := []struct {
		name           string
		links, files   int
		plain          int
		subdirsAfter   bool
		wantBeneath    int
		wantRefused    []string
		wantUnfollowed []string
	}{
		{name: "at the floor", links: 2, files: half, wantBeneath: symlinkVisitFloor},
		{name: "one past the floor", links: 2, files: half + 1, wantBeneath: symlinkVisitFloor, wantRefused: []string{"link2"}},
		{name: "at a listing past the floor", links: 2, files: half + 5, plain: half, wantBeneath: symlinkVisitFloor + 10},
		{name: "one past a listing past the floor", links: 2, files: half + 6, plain: half, wantBeneath: symlinkVisitFloor + 11, wantRefused: []string{"link2"}},
		{name: "links met once the cap is spent", links: 4, files: half, wantBeneath: symlinkVisitFloor, wantRefused: []string{"link3", "link4"}, wantUnfollowed: []string{"link3", "link4"}},
		{name: "subdirectories after a stopped descent", links: 2, files: half, subdirsAfter: true, wantBeneath: symlinkVisitFloor, wantRefused: []string{"link2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			filesDir := "real"
			if tt.subdirsAfter {
				filesDir = "real/a"
				fsys["real/b/x"] = &fstest.MapFile{Data: []byte("x")}
				fsys["real/c/x"] = &fstest.MapFile{Data: []byte("x")}
			}
			for i := range tt.files {
				fsys[fmt.Sprintf("%s/f%05d", filesDir, i)] = &fstest.MapFile{Data: []byte("x")}
			}
			for i := range tt.plain {
				fsys[fmt.Sprintf("plain/e%05d", i)] = &fstest.MapFile{Data: []byte("x")}
			}
			for i := 1; i <= tt.links; i++ {
				fsys[fmt.Sprintf("link%d", i)] = &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink}
			}
			listed := listedWithoutLinks(t, fsys)

			visits := 0
			var unfollowed []string
			warnings, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
				visits++
				if d.Type()&fs.ModeSymlink != 0 {
					unfollowed = append(unfollowed, p)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walkTree() error = %v, want nil", err)
			}
			if beneath := visits - listed; beneath != tt.wantBeneath {
				t.Fatalf("visited %d entries beneath resolved links, want %d (the tree lists %d)", beneath, tt.wantBeneath, listed)
			}
			var refused []string
			for _, w := range warnings {
				if !errors.Is(w.Err, adapter.ErrUnreadable) {
					t.Fatalf("warning %+v is not a refusal, want only budget refusals here", w)
				}
				refused = append(refused, w.File)
			}
			if fmt.Sprint(refused) != fmt.Sprint(tt.wantRefused) {
				t.Fatalf("refused %v, want %v", refused, tt.wantRefused)
			}
			if fmt.Sprint(unfollowed) != fmt.Sprint(tt.wantUnfollowed) {
				t.Fatalf("visited %v unfollowed, want %v", unfollowed, tt.wantUnfollowed)
			}
		})
	}
}

type readDirCountingWalkFS struct {
	m     fstest.MapFS
	reads *int
}

func (f readDirCountingWalkFS) Open(name string) (fs.File, error)     { return f.m.Open(name) }
func (f readDirCountingWalkFS) Stat(name string) (fs.FileInfo, error) { return f.m.Stat(name) }

func (f readDirCountingWalkFS) ReadDir(name string) ([]fs.DirEntry, error) {
	*f.reads++
	return f.m.ReadDir(name)
}

// The tree is listed for the cap only once links spend symlinkVisitFloor:
// below it the walk reads just the directories it walks, and one visit past
// it reads the tree once more.
func TestWalkTree_ListsTheTreeOnlyOnceLinksSpendTheFloor(t *testing.T) {
	tests := []struct {
		name      string
		files     int
		wantReads int
	}{
		{"under the floor", 3, 4},
		{"past the floor", symlinkVisitFloor/2 + 1, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := fstest.MapFS{
				"link1": &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink},
				"link2": &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink},
			}
			for i := range tt.files {
				m[fmt.Sprintf("real/f%05d", i)] = &fstest.MapFile{Data: []byte("x")}
			}
			reads := 0
			if _, _, err := walkTree(readDirCountingWalkFS{m: m, reads: &reads}, func(string, fs.DirEntry) error { return nil }); err != nil {
				t.Fatalf("walkTree() error = %v, want nil", err)
			}
			if reads != tt.wantReads {
				t.Fatalf("walk read %d directories, want %d", reads, tt.wantReads)
			}
		})
	}
}

func listedWithoutLinks(t *testing.T, fsys fs.FS) int {
	t.Helper()
	n := 0
	err := fs.WalkDir(fsys, ".", func(_ string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("listing the fixture: %v", err)
	}
	return n
}

// Measures resolution cost for a fixture shaped like real usage: several
// projects, each symlinking one of its own config directories. The margin
// between that cost and symlinkResolutionBudget is the safety margin the
// budget's chosen value rests on.
func TestWalkTree_RealisticMultiProjectFixtureStaysFarUnderBudget(t *testing.T) {
	const projectCount = 5
	fsys := fstest.MapFS{}
	for i := 0; i < projectCount; i++ {
		proj := fmt.Sprintf("project%d", i)
		fsys[proj+"/.mcp.json"] = &fstest.MapFile{Data: []byte("{}")}
		fsys[proj+"/real-config/settings.json"] = &fstest.MapFile{Data: []byte("{}")}
		fsys[proj+"/.claude"] = &fstest.MapFile{Data: []byte("real-config"), Mode: fs.ModeSymlink}
	}

	resolved := 0
	_, containerResolutions, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		if d.IsDir() && strings.HasSuffix(p, "/.claude") {
			resolved++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	if resolved != projectCount {
		t.Fatalf("resolved %d symlinked .claude directories, want %d (one per project)", resolved, projectCount)
	}

	t.Logf("realistic fixture: %d projects each symlinking one config directory consumes %d of %d budget units (%.1f%% of budget)",
		projectCount, containerResolutions, symlinkResolutionBudget, 100*float64(containerResolutions)/float64(symlinkResolutionBudget))

	if containerResolutions >= symlinkResolutionBudget/4 {
		t.Fatalf("realistic fixture consumed %d of %d budget units, want comfortably under a quarter of the budget", containerResolutions, symlinkResolutionBudget)
	}

	for i := 0; i < projectCount; i++ {
		proj := fmt.Sprintf("project%d", i)
		sub, err := fs.Sub(fsys, proj)
		if err != nil {
			t.Fatalf("fs.Sub(%s) error = %v", proj, err)
		}
		_, perProjectResolutions, err := walkTree(sub, func(p string, d fs.DirEntry) error { return nil })
		if err != nil {
			t.Fatalf("walkTree(%s) error = %v, want nil", proj, err)
		}
		if perProjectResolutions != 1 {
			t.Fatalf("project %s consumed %d budget units on its own scan, want exactly 1 (its own .claude symlink)", proj, perProjectResolutions)
		}
	}
}

// Returning fs.SkipDir for a resolved symlinked directory skips that
// directory's subtree and nothing else; see walkFrom for the fs.WalkDir trap
// this avoids.
func TestWalkTree_VisitSkipDirOnResolvedSymlinkedDirectorySkipsOnlyItsSubtree(t *testing.T) {
	fsys := fstest.MapFS{
		"real/inside.txt": &fstest.MapFile{Data: []byte("x")},
		"link":            &fstest.MapFile{Data: []byte("real"), Mode: fs.ModeSymlink},
		"sibling.txt":     &fstest.MapFile{Data: []byte("y")},
	}

	visited := map[string]bool{}
	_, _, err := walkTree(fsys, func(p string, d fs.DirEntry) error {
		visited[p] = true
		if p == "link" {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walkTree() error = %v, want nil", err)
	}
	if visited["link/inside.txt"] {
		t.Fatal("link/inside.txt was visited, want fs.SkipDir on link to stop its descent")
	}
	if !visited["sibling.txt"] {
		t.Fatal("sibling.txt was never visited, want fs.SkipDir on link to leave siblings unaffected")
	}
}
