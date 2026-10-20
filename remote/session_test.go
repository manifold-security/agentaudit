package remote

import (
	"context"
	"net/http"
	"runtime"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

func TestFetchLetsGoOfTheAdvertisementOnceTheRefsAreResolved(t *testing.T) {
	repo, _ := newFakeRepo(t, fstest.MapFS{".mcp.json": {Data: []byte(mcpJSON)}})
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	u, err := ParseURL("https://github.com/o/r")
	if err != nil {
		t.Fatal(err)
	}

	f := newFetcher(context.Background(), DefaultLimits())
	adv, err := f.open(u)
	if err != nil {
		t.Fatalf("open() error = %v", err)
	}
	collected := cleanupProbe(adv, 3)
	if collected() {
		t.Fatal("the advertisement went while still referenced; the probe sees nothing")
	}
	if _, _, err := f.fetch(adv, u, "", agentaudit.New()); err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	if !collected() {
		t.Fatal("the fetcher still reaches the decoded advertisement after the refs are resolved")
	}
	runtime.KeepAlive(f)
}

// A moved repository scans as it does at its new name, every pack asked of
// the endpoint the advertisement's redirect ended on.
func TestFetchThroughARedirectAsksTheEndpointItEndedOnForEachPack(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}, redirect: map[string]string{"old/r": "/o/r"}}
	useFake(t, f)

	direct := fetchedFindings(t, "https://github.com/o/r")
	before := len(f.requests())
	moved := fetchedFindings(t, "https://github.com/old/r")
	if len(direct) == 0 || !slices.Equal(moved, direct) {
		t.Fatalf("through the redirect\n%sdirectly\n%s", indentLines(moved), indentLines(direct))
	}
	posts := 0
	for _, req := range f.requests()[before:] {
		if req.method != http.MethodPost {
			continue
		}
		if posts++; req.path != "/o/r/git-upload-pack" {
			t.Fatalf("a pack was asked of %s, want /o/r/git-upload-pack", req.path)
		}
	}
	if posts < 2 {
		t.Fatalf("the redirected fetch made %d pack request(s), want the trees and a round's blobs", posts)
	}
}

// A redirected pack request is refused wherever it points: to another host,
// or to another repository on the same one.
func TestFetchRefusesARedirectedPackRequest(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	other := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	otherSrv := serve(t, other)
	home := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo, "x/r": repo}}
	var target string
	useFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/o/r/git-upload-pack" {
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}
		home.ServeHTTP(w, r)
	}))

	for _, to := range []string{otherSrv.URL + "/o/r/git-upload-pack", "/x/r/git-upload-pack"} {
		target = to
		if _, _, err := fetch("https://github.com/o/r", "", DefaultLimits()); err == nil {
			t.Fatalf("Fetch() with packs redirected to %s: error = nil, want the redirect refused", to)
		}
	}
	for _, req := range append(other.requests(), home.requests()...) {
		if req.path != "/o/r/info/refs" {
			t.Fatalf("a redirected pack request reached %s, want it refused before sending", req.path)
		}
	}
	if _, err := fakeSession(t, otherSrv, "o/r").AdvertisedReferencesContext(context.Background()); err != nil || len(other.requests()) == 0 {
		t.Fatalf("a request straight to the other host: error = %v, requests = %+v, want it recorded", err, other.requests())
	}
}

// Every pack is asked of the repository a redirect ended on, though the
// redirect percent-encodes the slash before refs.
func TestFetchThroughAnEncodedRedirectAsksTheRepositoryItEndedOnForEachPack(t *testing.T) {
	repo, _ := newFakeRepo(t, oneFile(".mcp.json", mcpJSON))
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	useFake(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old/r/info/refs" {
			http.Redirect(w, r, "/o/r/info%2Frefs?service=git-upload-pack", http.StatusMovedPermanently)
			return
		}
		f.ServeHTTP(w, r)
	}))

	if _, _, err := fetch("https://github.com/old/r", "", DefaultLimits()); err != nil {
		t.Fatalf("Fetch() through a redirect to /o/r/info%%2Frefs: error = %v", err)
	}
	posts := 0
	for _, req := range f.requests() {
		if req.method != http.MethodPost {
			continue
		}
		if posts++; req.path != "/o/r/git-upload-pack" {
			t.Fatalf("a pack was asked of %s, want /o/r/git-upload-pack", req.path)
		}
	}
	if posts < 2 {
		t.Fatalf("the redirected fetch made %d pack request(s), want the trees and a round's blobs", posts)
	}
}
