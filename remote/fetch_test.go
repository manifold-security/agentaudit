package remote

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/treefs"
)

func useFake(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := serve(t, h)
	base, rt := githubBase, baseTransport
	githubBase, baseTransport = srv.URL, srv.Client().Transport
	t.Cleanup(func() { githubBase, baseTransport = base, rt })
	return srv
}

func fetch(rawURL, ref string, l Limits) (string, *treefs.FS, error) {
	return Fetch(context.Background(), rawURL, ref, agentaudit.New(), l)
}

func oneFile(name, data string) fstest.MapFS {
	return fstest.MapFS{name: {Data: []byte(data)}}
}

const mcpJSON = `{"mcpServers":{"fs":{"command":"npx","args":["-y","server-fs"]}}}`

func TestFetchResolvesTheRefArgument(t *testing.T) {
	repo, main := newFakeRepo(t, oneFile("which", "main"))
	dev := repo.commit(t, oneFile("which", "dev"))
	annotated := repo.commit(t, oneFile("which", "annotated"))
	light := repo.commit(t, oneFile("which", "light"))
	repo.refs["refs/heads/dev"] = dev
	repo.annotate(t, "v1", annotated)
	repo.refs["refs/tags/light"] = light
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	for ref, want := range map[string]plumbing.Hash{"": main, "dev": dev, "v1": annotated, "light": light, dev.String(): dev} {
		commit, _, err := fetch("https://github.com/o/r", ref, DefaultLimits())
		if err != nil {
			t.Fatalf("Fetch(ref %q) error = %v", ref, err)
		}
		if commit != want.String() {
			t.Fatalf("Fetch(ref %q) commit = %s, want %s", ref, commit, want)
		}
	}
}

func TestFetchRefusesARefBesideATreeURL(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile("which", "main"))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	if _, _, err := fetch("https://github.com/o/r/tree/main", "main", DefaultLimits()); !errors.Is(err, ErrURL) {
		t.Fatalf("Fetch() error = %v, want ErrURL", err)
	}
	if log := f.requests(); len(log) != 0 {
		t.Fatalf("requests = %+v, want none", log)
	}
	if _, _, err := fetch("https://github.com/o/r/tree/main", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() without the ref: error = %v", err)
	}
	if log := f.requests(); len(log) == 0 {
		t.Fatal("requests = none after a fetch without the ref; the fake is not the one asked")
	}
}

// Branch feature and tag feature/x can coexist, so only the longest prefix
// naming a ref tells them apart.
func TestFetchResolvesTheLongestRefUnderTreeAndRootsTheTreeBelowIt(t *testing.T) {
	repo, main := newFakeRepo(t, fstest.MapFS{"deep/dir/.mcp.json": {Data: []byte(mcpJSON)}})
	feature := repo.commit(t, fstest.MapFS{"x/sub/.mcp.json": {Data: []byte(`{"mcpServers":{"branch":{"command":"a"}}}`)}})
	tagged := repo.commit(t, fstest.MapFS{"sub/.mcp.json": {Data: []byte(mcpJSON)}})
	repo.refs["refs/heads/feature"] = feature
	repo.annotate(t, "feature/x", tagged)
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	for _, tc := range []struct {
		url  string
		want plumbing.Hash
	}{
		{"https://github.com/o/r/tree/feature/x/sub", tagged},
		{"https://github.com/o/r/tree/main/deep/dir", main},
		{"https://github.com/o/r/tree/" + tagged.String() + "/sub", tagged},
	} {
		commit, tree, err := fetch(tc.url, "", DefaultLimits())
		if err != nil {
			t.Fatalf("Fetch(%s) error = %v", tc.url, err)
		}
		if commit != tc.want.String() {
			t.Fatalf("Fetch(%s) commit = %s, want %s", tc.url, commit, tc.want)
		}
		if data, err := fs.ReadFile(tree, ".mcp.json"); err != nil || string(data) != mcpJSON {
			t.Fatalf("Fetch(%s): .mcp.json at the tree root = %q, %v, want the file under the tree path", tc.url, data, err)
		}
	}
}

func TestFetchRefusesATreePathThatIsNotADirectory(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{
		"dir/.mcp.json": {Data: []byte(mcpJSON)},
		"file.txt":      {Data: []byte("text")},
		"link":          {Data: []byte("dir"), Mode: fs.ModeSymlink},
	})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	for _, sub := range []string{"missing", "file.txt", "link", "dir/.mcp.json"} {
		if _, _, err := fetch("https://github.com/o/r/tree/main/"+sub, "", DefaultLimits()); !errors.Is(err, ErrRef) {
			t.Fatalf("Fetch(/tree/main/%s) error = %v, want ErrRef", sub, err)
		}
	}
}

// The tree path is a containment root, as os.OpenRoot of that directory in
// a clone would be.
func TestFetchRefusesALinkOutOfTheTreePath(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{
		"outside.json":  {Data: []byte(mcpJSON)},
		"sub/.mcp.json": {Data: []byte("../outside.json"), Mode: fs.ModeSymlink},
	})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	_, tree, err := fetch("https://github.com/o/r/tree/main/sub", "", DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if _, err := fs.ReadLink(tree, ".mcp.json"); err != nil {
		t.Fatalf("ReadLink(.mcp.json) error = %v, want the link listed under the tree path", err)
	}
	if data, err := fs.ReadFile(tree, ".mcp.json"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile(.mcp.json) = %q, %v, want a refusal that is not ErrNotExist", data, err)
	}
}

func TestFetchMapsAnUnknownRefToErrRef(t *testing.T) {
	repo, commit := newFakeRepo(t, oneFile("which", "main"))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	blob := blobHash(t, repo, commit, "which").String()

	for _, tc := range []struct{ url, ref string }{
		{"https://github.com/o/r", "nope"},
		{"https://github.com/o/r", blob},
		{"https://github.com/o/r/tree/nope", ""},
		{"https://github.com/o/r/tree/nope/sub", ""},
		{"https://github.com/o/r/tree/" + blob, ""},
	} {
		if _, _, err := fetch(tc.url, tc.ref, DefaultLimits()); !errors.Is(err, ErrRef) {
			t.Fatalf("Fetch(%s, %q) error = %v, want ErrRef", tc.url, tc.ref, err)
		}
	}
}

func TestFetchFailsOnAnObjectIDTheServerLacksWithoutASentinel(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile("which", "main"))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	missing := strings.Repeat("ab", 20)

	for _, tc := range []struct{ url, ref string }{
		{"https://github.com/o/r", missing},
		{"https://github.com/o/r/tree/" + missing, ""},
	} {
		_, _, err := fetch(tc.url, tc.ref, DefaultLimits())
		if err == nil {
			t.Fatalf("Fetch(%s, %q) error = nil, want the fetch to fail", tc.url, tc.ref)
		}
		for _, sentinel := range []error{ErrRef, ErrNotFound, ErrTooLarge, ErrURL} {
			if errors.Is(err, sentinel) {
				t.Fatalf("Fetch(%s, %q) error = %v, want none of the sentinels", tc.url, tc.ref, err)
			}
		}
	}
}

func TestFetchMapsAnAnonymous401And404ToErrNotFound(t *testing.T) {
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/private": {status: http.StatusUnauthorized}}})

	for _, url := range []string{"https://github.com/o/private", "https://github.com/o/missing"} {
		if _, _, err := fetch(url, "", DefaultLimits()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Fetch(%s) error = %v, want ErrNotFound", url, err)
		}
	}
}

// Text a server writes into the protocol reaches the error escaped and cut
// short.
func TestFetchEscapesAndShortensServerTextInItsError(t *testing.T) {
	const hostile = "\x1b[2J\r\n\u009b\x7f"
	repo, commit := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	for name, tc := range map[string]struct {
		suffix string
		lines  []string
	}{
		"side-band error message": {"/git-upload-pack", []string{"shallow " + commit.String() + "\n", "", "NAK\n", "\x03" + hostile + strings.Repeat("A", 10<<10), ""}},
		"refused capability":      {"/info/refs", []string{"# service=git-upload-pack\n", "", commit.String() + " HEAD\x00agent= " + hostile + strings.Repeat("B", 2<<10) + "\n", ""}},
	} {
		t.Run(name, func(t *testing.T) {
			useFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, tc.suffix) {
					f.ServeHTTP(w, r)
					return
				}
				pe := pktline.NewEncoder(w)
				for _, line := range tc.lines {
					if line == "" {
						_ = pe.Flush()
					} else {
						_ = pe.EncodeString(line)
					}
				}
			}))
			_, _, err := fetch("https://github.com/o/r", "", DefaultLimits())
			if err == nil {
				t.Fatal("Fetch() error = nil, want the server's refusal")
			}
			text := err.Error()
			if i := strings.IndexFunc(text, unicode.IsControl); i >= 0 {
				t.Fatalf("error text holds a control character at byte %d: %q", i, text)
			}
			if !strings.Contains(text, `\x1b[2J\r\n\u009b\x7f`) {
				t.Fatalf("error text = %q, want the server's bytes spelled out", text)
			}
			if limit := len("remote: ") + maxErrorText + len("..."); len(text) > limit {
				t.Fatalf("error text is %d bytes, want at most %d", len(text), limit)
			}
		})
	}
}

// Each refusal below quotes a name thousands of bytes long and still keeps
// its error short.
func TestFetchShortensRepositoryTextInItsError(t *testing.T) {
	long := strings.Repeat("n", 3000)
	named := newEmptyRepo()
	named.refs["refs/heads/main"] = named.commitTree(t, storeTree(t, named.st, []object.TreeEntry{{Name: "a/" + strings.Repeat("n", 10<<10), Mode: filemode.Regular, Hash: storeBlob(t, named.st, []byte("x"))}}))
	dup := newEmptyRepo()
	blob := storeBlob(t, dup.st, []byte("x"))
	dup.refs["refs/heads/main"] = dup.commitTree(t, storeTree(t, dup.st, []object.TreeEntry{{Name: long, Mode: filemode.Regular, Hash: blob}, {Name: long, Mode: filemode.Regular, Hash: blob}}))
	missing, under := nestedRepo(t, []string{long}, "f")
	missing.omit = under[0]
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/named": named, "o/dup": dup, "o/missing": missing}})

	for repo, want := range map[string]string{"o/named": "a tree entry named", "o/dup": "duplicate path", "o/missing": "the tree at"} {
		_, _, err := fetch("https://github.com/"+repo, "", DefaultLimits())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Fetch(%s) error = %v, want %q", repo, err, want)
		}
		if n := len(err.Error()); n > 512 {
			t.Fatalf("Fetch(%s) error text is %d bytes, want at most 512", repo, n)
		}
	}
}

func TestServerErrorKeepsItsTextEscapedValidAndShort(t *testing.T) {
	limit := len("remote: ") + maxErrorText + len("...")
	for name, raw := range map[string]string{
		"control bytes only":    strings.Repeat("\x1b", 300),
		"a rune across the cut": strings.Repeat("x", maxErrorText-1) + strings.Repeat("\u20ac", 10),
	} {
		text := serverError{errors.New(raw)}.Error()
		if len(text) > limit {
			t.Fatalf("%s: error text is %d bytes, want at most %d", name, len(text), limit)
		}
		if !utf8.ValidString(text) {
			t.Fatalf("%s: error text %q is not valid UTF-8", name, text)
		}
		if i := strings.IndexFunc(text, unicode.IsControl); i >= 0 {
			t.Fatalf("%s: error text holds a control character at byte %d: %q", name, i, text)
		}
	}
}

func TestFetchKeepsAnErrorBodyOutOfItsError(t *testing.T) {
	repos := map[string]*fakeRepo{}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		repos[fmt.Sprintf("o/r%d", status)] = &fakeRepo{status: status}
	}
	srv := useFake(t, &fakeGit{repos: repos})

	for name := range repos {
		if _, err := fakeSession(t, srv, name).AdvertisedReferencesContext(context.Background()); err == nil || !strings.Contains(err.Error(), "the fake's own words") {
			t.Fatalf("go-git's own error for %s = %v, want it to quote the response body", name, err)
		}
		_, _, err := fetch("https://github.com/"+name, "", DefaultLimits())
		if err == nil || strings.Contains(err.Error(), "the fake's own words") {
			t.Fatalf("Fetch(%s) error = %v, want an error without the response body", name, err)
		}
	}
}

func TestFetchRefusesATreeThePackLeftOut(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{".claude/settings.json": {Data: []byte(`{}`)}, ".mcp.json": {Data: []byte(mcpJSON)}})
	tree, err := commitObject(t, repo, commit).Tree()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := tree.FindEntry(".claude")
	if err != nil {
		t.Fatal(err)
	}
	repo.omit = entry.Hash
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err == nil || !strings.Contains(err.Error(), `".claude"`) {
		t.Fatalf("Fetch() error = %v, want the missing subtree .claude refused", err)
	}
}

func nestedRepo(t *testing.T, names []string, leaf string) (repo *fakeRepo, treeUnderName []plumbing.Hash) {
	t.Helper()
	repo = newEmptyRepo()
	h := storeTree(t, repo.st, []object.TreeEntry{{Name: leaf, Mode: filemode.Regular, Hash: storeBlob(t, repo.st, []byte("x"))}})
	treeUnderName = make([]plumbing.Hash, len(names))
	for i := len(names) - 1; i >= 0; i-- {
		treeUnderName[i] = h
		h = storeTree(t, repo.st, []object.TreeEntry{{Name: names[i], Mode: filemode.Dir, Hash: h}})
	}
	repo.refs["refs/heads/main"] = repo.commitTree(t, h)
	return repo, treeUnderName
}

func pathSegments(n, size int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%03d", i) + strings.Repeat("x", size-3)
	}
	return names
}

// A path of 4095 bytes fetches, and one a byte longer is refused where the
// walk meets it: the pack below leaves out the tree that path names, so
// reading it would fail differently.
func TestFetchRefusesAPathPastTheTreefsLimitBeforeReadingBelowIt(t *testing.T) {
	atLimit, _ := nestedRepo(t, pathSegments(15, 255), strings.Repeat("f", 255))
	over, under := nestedRepo(t, append(pathSegments(15, 255), strings.Repeat("d", 256)), "f")
	over.omit = under[15]
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/limit": atLimit, "o/over": over}})

	if _, _, err := fetch("https://github.com/o/limit", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() with a 4095-byte path: error = %v", err)
	}
	_, _, err := fetch("https://github.com/o/over", "", DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "is 4096 bytes, over 4095") {
		t.Fatalf("Fetch() with a 4096-byte path: error = %v, want the path refused", err)
	}
	for _, sentinel := range []error{ErrTooLarge, ErrRef, ErrNotFound, ErrURL} {
		if errors.Is(err, sentinel) {
			t.Fatalf("Fetch() with a 4096-byte path: error = %v, want none of the sentinels", err)
		}
	}
	for n, accepted := range map[int]bool{maxTreePath: true, maxTreePath + 1: false} {
		if _, err := treefs.New([]treefs.Entry{{Path: strings.Repeat("p", n), Mode: 0o644}}, nil); (err == nil) != accepted {
			t.Fatalf("treefs.New() with a %d-byte path: error = %v, want accepted %v", n, err, accepted)
		}
	}
}

// A tree entry's name is one path segment, as git checks one out.
func TestFetchRefusesATreeEntryNameThatIsNotOneSegment(t *testing.T) {
	repos := map[string]*fakeRepo{}
	for i, name := range []string{"..", ".", "a/b"} {
		repo := newEmptyRepo()
		blob := storeBlob(t, repo.st, []byte(mcpJSON))
		repo.refs["refs/heads/main"] = repo.commitTree(t, storeObject(t, repo.st, &object.Tree{Entries: []object.TreeEntry{
			{Name: name, Mode: filemode.Regular, Hash: blob},
		}}))
		repos[fmt.Sprintf("o/r%d", i)] = repo
	}
	useFake(t, &fakeGit{repos: repos})

	for key := range repos {
		if _, _, err := fetch("https://github.com/"+key, "", DefaultLimits()); err == nil || !strings.Contains(err.Error(), "a tree entry named") {
			t.Fatalf("Fetch(%s) error = %v, want the entry name refused", key, err)
		}
	}
}

// No POST asks for thin-pack, which the fake offers.
func TestFetchAsksForTheTreesThenOnlyTheBlobsTheScanReads(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json":             {Data: []byte(mcpJSON)},
		".claude/settings.json": {Data: []byte(`{"permissions":{"allow":["Bash(npm test)"]}}`)},
		"README.md":             {Data: []byte("# readme\n")},
		"src/main.go":           {Data: []byte("package main\n")},
	}
	repo, commit := newFakeRepo(t, fsys)
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, f)

	if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	read := map[plumbing.Hash]bool{}
	for _, name := range []string{".mcp.json", ".claude/settings.json"} {
		read[blobHash(t, repo, commit, name)] = true
	}

	log := f.requests()
	if len(log) < 3 || log[0].method != http.MethodGet {
		t.Fatalf("requests = %+v, want a GET, the tree POST and at least one blob POST", log)
	}
	first := log[1]
	if !slices.Equal(first.wants, []plumbing.Hash{commit}) || first.deepen != "1" || first.filter != "blob:none" {
		t.Fatalf("first POST = %+v, want the commit alone, deepen 1, filter blob:none", first)
	}
	asked := map[plumbing.Hash]bool{}
	for _, req := range log {
		if req.auth != "" {
			t.Fatalf("request %+v carries credentials, want none", req)
		}
	}
	for _, req := range log[1:] {
		if req.method != http.MethodPost {
			t.Fatalf("request %+v after the advertisement, want POSTs only", req)
		}
		if slices.Contains(req.caps, "thin-pack") {
			t.Fatalf("POST caps = %v, want no thin-pack", req.caps)
		}
	}
	for _, req := range log[2:] {
		if req.deepen != "" || req.filter != "" {
			t.Fatalf("blob POST = %+v, want neither deepen nor filter", req)
		}
		for _, want := range req.wants {
			if !read[want] {
				t.Fatalf("blob POST wants %s, which no scan read", want)
			}
			asked[want] = true
		}
	}
	if len(asked) != len(read) {
		t.Fatalf("blob POSTs asked for %d of the %d blobs the scan reads", len(asked), len(read))
	}
}

func commitObject(t *testing.T, repo *fakeRepo, commit plumbing.Hash) *object.Commit {
	t.Helper()
	c, err := object.GetCommit(repo.st, commit)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func blobHash(t *testing.T, repo *fakeRepo, commit plumbing.Hash, name string) plumbing.Hash {
	t.Helper()
	tree, err := commitObject(t, repo, commit).Tree()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := tree.FindEntry(name)
	if err != nil {
		t.Fatalf("FindEntry(%s) error = %v", name, err)
	}
	return entry.Hash
}

// go-git canonicalises a tree's modes on decode as git does, so a mode
// outside git's set arrives as the one git would check out.
func TestFetchMapsGitModes(t *testing.T) {
	repo := newEmptyRepo()
	script := storeBlob(t, repo.st, []byte("#!/bin/sh\n"))
	bin := storeTree(t, repo.st, []object.TreeEntry{{Name: "run.sh", Mode: filemode.Executable, Hash: script}})
	repo.refs["refs/heads/main"] = repo.commitTree(t, storeTree(t, repo.st, []object.TreeEntry{
		{Name: "bin", Mode: filemode.Dir, Hash: bin},
		{Name: "plain.sh", Mode: filemode.Regular, Hash: script},
		{Name: "link", Mode: filemode.Symlink, Hash: storeBlob(t, repo.st, []byte("plain.sh"))},
		{Name: "vendor", Mode: filemode.Submodule, Hash: plumbing.NewHash(strings.Repeat("ab", 20))},
	}))
	odd := newEmptyRepo()
	x := storeBlob(t, odd.st, []byte("x"))
	odd.refs["refs/heads/main"] = odd.commitTree(t, storeTree(t, odd.st, []object.TreeEntry{
		{Name: "private", Mode: filemode.FileMode(0o100600), Hash: x},
		{Name: "group-exec", Mode: filemode.FileMode(0o100750), Hash: x},
		{Name: "unknown", Mode: filemode.FileMode(0o170000), Hash: x},
	}))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo, "o/odd": odd}})

	_, tree, err := fetch("https://github.com/o/r", "", DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	for name, want := range map[string]fs.FileMode{"bin/run.sh": 0o755, "plain.sh": 0o644, "link": fs.ModeSymlink | 0o777, "vendor": fs.ModeDir | 0o755} {
		info, err := fs.Lstat(tree, name)
		if err != nil || info.Mode() != want {
			t.Fatalf("Lstat(%s) = %v, %v, want mode %v", name, info, err, want)
		}
	}
	if entries, err := fs.ReadDir(tree, "vendor"); err != nil || len(entries) != 0 {
		t.Fatalf("ReadDir(vendor) = %v, %v, want an empty directory", entries, err)
	}

	_, tree, err = fetch("https://github.com/o/odd", "", DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch(o/odd) error = %v", err)
	}
	for name, want := range map[string]fs.FileMode{"private": 0o644, "group-exec": 0o755, "unknown": fs.ModeDir | 0o755} {
		info, err := fs.Lstat(tree, name)
		if err != nil || info.Mode() != want {
			t.Fatalf("o/odd: Lstat(%s) = %v, %v, want mode %v", name, info, err, want)
		}
	}
}

// The deadline ends the wait on a stalled response, not only the work
// after it.
func TestFetchStopsAtTheContextDeadline(t *testing.T) {
	const stall = 5 * time.Second
	repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	for name, f := range map[string]*fakeGit{
		"advertisement": {repos: map[string]*fakeRepo{"o/r": repo}, advDelay: stall},
		"pack":          {repos: map[string]*fakeRepo{"o/r": repo}, packDelay: stall},
	} {
		t.Run(name, func(t *testing.T) {
			useFake(t, f)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			if _, _, err := Fetch(ctx, "https://github.com/o/r", "", agentaudit.New(), DefaultLimits()); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Fetch() error = %v, want context.DeadlineExceeded", err)
			}
			if elapsed := time.Since(start); elapsed >= stall/2 {
				t.Fatalf("Fetch() returned after %v, want it before the %v stall ends", elapsed, stall)
			}
		})
	}
}

func TestSameOriginRefusesAnotherSchemeOrHost(t *testing.T) {
	via := []*http.Request{httptest.NewRequest(http.MethodGet, "https://github.com/o/r/info/refs", nil)}
	for target, follow := range map[string]bool{
		"https://github.com/n/r/info/refs":  true,
		"https://GitHub.com/n/r/info/refs":  true,
		"http://github.com/n/r/info/refs":   false,
		"https://example.com/n/r/info/refs": false,
	} {
		if err := sameOrigin(httptest.NewRequest(http.MethodGet, target, nil), via); (err == nil) != follow {
			t.Fatalf("sameOrigin(%s) error = %v, want follow %v", target, err, follow)
		}
	}
}

func TestFetchFollowsARedirectOnlyWithinTheHost(t *testing.T) {
	repo, commit := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	other := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	otherSrv := serve(t, other)
	useFake(t, &fakeGit{
		repos:    map[string]*fakeRepo{"o/r": repo},
		redirect: map[string]string{"old/r": "/o/r", "moved/r": otherSrv.URL + "/o/r"},
	})

	got, _, err := fetch("https://github.com/old/r", "", DefaultLimits())
	if err != nil || got != commit.String() {
		t.Fatalf("Fetch(old/r) = %s, %v, want %s through the same-host redirect", got, err, commit)
	}
	if _, _, err := fetch("https://github.com/moved/r", "", DefaultLimits()); err == nil {
		t.Fatal("Fetch(moved/r) error = nil, want the redirect to another host refused")
	}
	if log := other.requests(); len(log) != 0 {
		t.Fatalf("the other host received %+v, want nothing", log)
	}
	if _, err := fakeSession(t, otherSrv, "o/r").AdvertisedReferencesContext(context.Background()); err != nil || len(other.requests()) == 0 {
		t.Fatalf("a request straight to the other host: error = %v, requests = %+v, want it recorded", err, other.requests())
	}
}

func TestFetchEndsASameHostRedirectLoop(t *testing.T) {
	useFake(t, &fakeGit{redirect: map[string]string{"loop/r": "/loop/r"}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := Fetch(ctx, "https://github.com/loop/r", "", agentaudit.New(), DefaultLimits()); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Fetch() error = %v, want the loop refused before the deadline", err)
	}
}
