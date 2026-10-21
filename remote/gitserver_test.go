package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
)

type fakeRepo struct {
	st     *memory.Storage
	head   string
	refs   map[string]plumbing.Hash
	peeled map[string]plumbing.Hash
	status int
	omit   plumbing.Hash
	extra  plumbing.Hash
}

type fakeRequest struct {
	method, path   string
	wants          []plumbing.Hash
	caps           []string
	deepen, filter string
	auth           string
	bytes          int
}

// fakeGit keys its repos and redirect maps "<owner>/<repo>"; a redirect
// value is a path or an absolute URL.
type fakeGit struct {
	repos        map[string]*fakeRepo
	redirect     map[string]string
	advDelay     time.Duration
	packDelay    time.Duration
	ignoreFilter bool

	mu      sync.Mutex
	log     []fakeRequest
	cache   map[string][]byte
	encodes int
}

const fakeStatusBody = "\x1b[31mthe fake's own words"

var fakeSignature = object.Signature{Name: "fake", Email: "fake@example.com", When: time.Unix(0, 0).UTC()}

func newEmptyRepo() *fakeRepo {
	return &fakeRepo{
		st:     memory.NewStorage(),
		head:   "refs/heads/main",
		refs:   map[string]plumbing.Hash{},
		peeled: map[string]plumbing.Hash{},
	}
}

func newFakeRepo(t testing.TB, fsys fs.FS) (*fakeRepo, plumbing.Hash) {
	t.Helper()
	repo := newEmptyRepo()
	commit := repo.commit(t, fsys)
	repo.refs["refs/heads/main"] = commit
	return repo, commit
}

func (r *fakeRepo) commit(t testing.TB, fsys fs.FS) plumbing.Hash {
	t.Helper()
	return r.commitTree(t, storeTree(t, r.st, entriesFromFS(t, r.st, fsys, ".")))
}

func (r *fakeRepo) commitTree(t testing.TB, tree plumbing.Hash) plumbing.Hash {
	t.Helper()
	return storeObject(t, r.st, &object.Commit{Author: fakeSignature, Committer: fakeSignature, Message: "fixture\n", TreeHash: tree})
}

func (r *fakeRepo) annotate(t testing.TB, name string, target plumbing.Hash) {
	t.Helper()
	tag := storeObject(t, r.st, &object.Tag{Name: name, Tagger: fakeSignature, Message: name + "\n", TargetType: plumbing.CommitObject, Target: target})
	r.refs["refs/tags/"+name] = tag
	r.peeled["refs/tags/"+name] = target
}

func storeObject(t testing.TB, st *memory.Storage, enc interface {
	Encode(plumbing.EncodedObject) error
}) plumbing.Hash {
	t.Helper()
	obj := st.NewEncodedObject()
	if err := enc.Encode(obj); err != nil {
		t.Fatal(err)
	}
	h, err := st.SetEncodedObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func storeBlob(t testing.TB, st *memory.Storage, data []byte) plumbing.Hash {
	t.Helper()
	obj := st.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	h, err := st.SetEncodedObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func storeTree(t testing.TB, st *memory.Storage, entries []object.TreeEntry) plumbing.Hash {
	t.Helper()
	gitName := func(e object.TreeEntry) string {
		if e.Mode == filemode.Dir {
			return e.Name + "/"
		}
		return e.Name
	}
	slices.SortFunc(entries, func(a, b object.TreeEntry) int { return strings.Compare(gitName(a), gitName(b)) })
	return storeObject(t, st, &object.Tree{Entries: entries})
}

// entriesFromFS leaves out what a git tree cannot hold, as a clone would.
func entriesFromFS(t testing.TB, st *memory.Storage, fsys fs.FS, dir string) []object.TreeEntry {
	t.Helper()
	dirents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		t.Fatal(err)
	}
	var entries []object.TreeEntry
	for _, d := range dirents {
		name := path.Join(dir, d.Name())
		info, err := d.Info()
		if err != nil {
			t.Fatal(err)
		}
		entry := object.TreeEntry{Name: d.Name()}
		switch mode := info.Mode(); {
		case mode&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(fsys, name)
			if err != nil {
				t.Fatal(err)
			}
			entry.Mode, entry.Hash = filemode.Symlink, storeBlob(t, st, []byte(target))
		case mode.IsDir():
			sub := entriesFromFS(t, st, fsys, name)
			if len(sub) == 0 {
				continue
			}
			entry.Mode, entry.Hash = filemode.Dir, storeTree(t, st, sub)
		case mode.IsRegular():
			data, err := fs.ReadFile(fsys, name)
			if err != nil {
				t.Fatal(err)
			}
			entry.Mode, entry.Hash = filemode.Regular, storeBlob(t, st, data)
			if mode&0o111 != 0 {
				entry.Mode = filemode.Executable
			}
		default:
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

func serve(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeGit) requests() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.log)
}

func (f *fakeGit) encodedBodies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.encodes
}

type countingWriter struct {
	http.ResponseWriter
	n int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += n
	return n, err
}

func (c *countingWriter) Flush() { c.ResponseWriter.(http.Flusher).Flush() }

func (f *fakeGit) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	req := fakeRequest{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization")}
	if r.Method == http.MethodPost {
		readUploadRequest(r.Body, &req)
	}
	f.mu.Lock()
	f.log = append(f.log, req)
	i := len(f.log) - 1
	f.mu.Unlock()
	w := &countingWriter{ResponseWriter: rw}
	defer func() {
		f.mu.Lock()
		f.log[i].bytes = w.n
		f.mu.Unlock()
	}()

	key, op := "", ""
	for _, suffix := range []string{"/info/refs", "/git-upload-pack"} {
		if repo, ok := strings.CutSuffix(r.URL.Path, suffix); ok {
			key, op = strings.TrimSuffix(strings.TrimPrefix(repo, "/"), ".git"), suffix
		}
	}
	if target, ok := f.redirect[key]; ok {
		location := target + op
		if op == "/info/refs" {
			location += "?service=" + transport.UploadPackServiceName
		}
		http.Redirect(w, r, location, http.StatusMovedPermanently)
		return
	}
	repo, ok := f.repos[key]
	switch {
	case !ok:
		http.NotFound(w, r)
	case repo.status != 0:
		http.Error(w, fakeStatusBody, repo.status)
	case op == "/info/refs" && r.Method == http.MethodGet && r.URL.Query().Get("service") == transport.UploadPackServiceName:
		f.advertise(w, r, key, repo)
	case op == "/git-upload-pack" && r.Method == http.MethodPost:
		f.uploadPack(w, r, key, repo, req)
	default:
		http.Error(w, "not a smart HTTP request", http.StatusBadRequest)
	}
}

func readUploadRequest(body io.Reader, req *fakeRequest) {
	s := pktline.NewScanner(body)
	for s.Scan() {
		verb, rest, _ := strings.Cut(strings.TrimSuffix(string(s.Bytes()), "\n"), " ")
		switch verb {
		case "want":
			fields := strings.Fields(rest)
			req.wants = append(req.wants, plumbing.NewHash(fields[0]))
			if len(req.wants) == 1 {
				req.caps = fields[1:]
			}
		case "deepen":
			req.deepen = rest
		case "filter":
			req.filter = rest
		}
	}
}

func (f *fakeGit) advertise(w http.ResponseWriter, r *http.Request, key string, repo *fakeRepo) {
	body, err := f.cached("advertise "+key, func() ([]byte, error) { return encodeAdvertisement(repo) })
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !stall(r, f.advDelay) {
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	_, _ = w.Write(body)
}

// cached keeps each body it encodes, so a repeated request costs the
// process no encoding while a test measures its allocations.
func (f *fakeGit) cached(key string, encode func() ([]byte, error)) ([]byte, error) {
	f.mu.Lock()
	body, ok := f.cache[key]
	f.mu.Unlock()
	if ok {
		return body, nil
	}
	body, err := encode()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.encodes++
	if f.cache == nil {
		f.cache = map[string][]byte{}
	}
	f.cache[key] = body
	f.mu.Unlock()
	return body, nil
}

func encodeAdvertisement(repo *fakeRepo) ([]byte, error) {
	ar := packp.NewAdvRefs()
	ar.Prefix = [][]byte{[]byte("# service=" + transport.UploadPackServiceName), pktline.Flush}
	for _, c := range []capability.Capability{
		capability.OFSDelta, capability.ThinPack, capability.Sideband64k, capability.Shallow,
		capability.Filter, capability.AllowReachableSHA1InWant, capability.NoProgress,
	} {
		_ = ar.Capabilities.Add(c)
	}
	if h, ok := repo.refs[repo.head]; ok {
		_ = ar.Capabilities.Add(capability.SymRef, "HEAD:"+repo.head)
		ar.Head = &h
	}
	maps.Copy(ar.References, repo.refs)
	maps.Copy(ar.Peeled, repo.peeled)
	var body bytes.Buffer
	err := ar.Encode(&body)
	return body.Bytes(), err
}

func (f *fakeGit) uploadPack(w http.ResponseWriter, r *http.Request, key string, repo *fakeRepo, req fakeRequest) {
	if f.ignoreFilter {
		req.filter = ""
	}
	body, err := f.cached(fmt.Sprint("upload-pack ", key, req.wants, req.deepen, req.filter), func() ([]byte, error) { return encodeUploadPack(repo, req) })
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	half := len(body) / 2
	_, _ = w.Write(body[:half])
	if f.packDelay > 0 {
		w.(http.Flusher).Flush()
	}
	if !stall(r, f.packDelay) {
		return
	}
	_, _ = w.Write(body[half:])
}

func encodeUploadPack(repo *fakeRepo, req fakeRequest) ([]byte, error) {
	var hashes []plumbing.Hash
	add := func(h plumbing.Hash) {
		if h != repo.omit && !slices.Contains(hashes, h) {
			hashes = append(hashes, h)
		}
	}
	for _, want := range req.wants {
		obj, err := repo.st.EncodedObject(plumbing.AnyObject, want)
		if err != nil {
			return nil, fmt.Errorf("not our ref %s", want)
		}
		add(want)
		if obj.Type() != plumbing.CommitObject {
			continue
		}
		commit, err := object.GetCommit(repo.st, want)
		if err != nil {
			return nil, err
		}
		add(commit.TreeHash)
		tree, err := commit.Tree()
		if err != nil {
			return nil, err
		}
		walker := object.NewTreeWalker(tree, true, nil)
		walker.SkipPathValidation()
		for {
			_, entry, err := walker.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				walker.Close()
				return nil, err
			}
			switch {
			case entry.Mode == filemode.Dir:
				add(entry.Hash)
			case entry.Mode == filemode.Submodule:
			case req.filter != string(packp.FilterBlobNone()):
				add(entry.Hash)
			}
		}
		walker.Close()
	}

	if !repo.extra.IsZero() && req.deepen == "" {
		add(repo.extra)
	}

	var body bytes.Buffer
	pe := pktline.NewEncoder(&body)
	if req.deepen != "" {
		for _, want := range req.wants {
			_ = pe.Encodef("shallow %s\n", want)
		}
		_ = pe.Flush()
	}
	_ = pe.Encodef("NAK\n")
	mux := chunked{w: sideband.NewMuxer(sideband.Sideband64k, &body), max: pktline.MaxPayloadSize - 1}
	if _, err := packfile.NewEncoder(mux, repo.st, false).Encode(hashes, 10); err != nil {
		return nil, err
	}
	_ = pe.Flush()
	return body.Bytes(), nil
}

// chunked splits writes for go-git's Muxer, which frames a large write in a
// pkt-line too long to hold it.
type chunked struct {
	w   io.Writer
	max int
}

func (c chunked) Write(p []byte) (int, error) {
	for wrote := 0; wrote < len(p); {
		n, err := c.w.Write(p[wrote:min(len(p), wrote+c.max)])
		wrote += n
		if err != nil {
			return wrote, err
		}
	}
	return len(p), nil
}

func stall(r *http.Request, d time.Duration) bool {
	if d == 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-r.Context().Done():
		return false
	}
}

func fakeSession(t *testing.T, srv *httptest.Server, repo string) transport.UploadPackSession {
	t.Helper()
	ep, err := transport.NewEndpoint(srv.URL + "/" + repo)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := githttp.NewClient(srv.Client()).NewUploadPackSession(ep, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func fetchInto(ctx context.Context, st *memory.Storage, sess transport.UploadPackSession, adv *packp.AdvRefs, shallow bool, wants ...plumbing.Hash) error {
	req := packp.NewUploadPackRequestFromCapabilities(adv.Capabilities)
	req.Wants = wants
	if shallow {
		_ = req.Capabilities.Set(capability.Shallow)
		_ = req.Capabilities.Set(capability.Filter)
		req.Depth = packp.DepthCommits(1)
		req.Filter = packp.FilterBlobNone()
	}
	resp, err := sess.UploadPack(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Close()
	return packfile.UpdateObjectStorage(st, sideband.NewDemuxer(sideband.Sideband64k, resp))
}

// go-git reads the advertisement as git's: HEAD resolves through its symref,
// a branch name may hold a slash, and an annotated tag peels to its commit.
// It drops thin-pack from the capabilities it reads.
func TestFakeGitAdvertisesRefsAsGoGitReadsThem(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{"a": {Data: []byte("a")}})
	repo.refs["refs/heads/feature/x"] = commit
	repo.refs["refs/tags/light"] = commit
	repo.annotate(t, "v1", commit)
	srv := serve(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})

	adv, err := fakeSession(t, srv, "o/r").AdvertisedReferencesContext(context.Background())
	if err != nil {
		t.Fatalf("AdvertisedReferencesContext() error = %v", err)
	}
	if adv.Head == nil || *adv.Head != commit {
		t.Fatalf("Head = %v, want %s", adv.Head, commit)
	}
	if got := adv.Capabilities.Get(capability.SymRef); !slices.Equal(got, []string{"HEAD:refs/heads/main"}) {
		t.Fatalf("symref = %v, want HEAD:refs/heads/main", got)
	}
	for _, name := range []string{"refs/heads/main", "refs/heads/feature/x", "refs/tags/light"} {
		if adv.References[name] != commit {
			t.Fatalf("References[%q] = %s, want %s", name, adv.References[name], commit)
		}
	}
	if tag := adv.References["refs/tags/v1"]; tag.IsZero() || tag == commit {
		t.Fatalf("References[refs/tags/v1] = %s, want the tag object, not %s", tag, commit)
	}
	if adv.Peeled["refs/tags/v1"] != commit {
		t.Fatalf("Peeled[refs/tags/v1] = %s, want %s", adv.Peeled["refs/tags/v1"], commit)
	}

	resp, err := srv.Client().Get(srv.URL + "/o/r/info/refs?service=" + transport.UploadPackServiceName)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Contains(raw, []byte("thin-pack")) {
		t.Fatalf("advertisement = %q, %v, want thin-pack offered", raw, err)
	}
	if adv.Capabilities.Supports(capability.ThinPack) {
		t.Fatal("go-git kept thin-pack in the capabilities it read")
	}
}

// A depth-1 blob:none request gets the commit and its trees without one
// blob, a later request gets exactly the blob it names, and the same want
// without the filter brings every blob.
func TestFakeGitServesTreesFirstAndThenTheBlobAskedFor(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{
		".mcp.json":  {Data: []byte("{}")},
		"bin/run.sh": {Data: []byte("#!/bin/sh\n"), Mode: 0o755},
		"link":       {Data: []byte("bin/run.sh"), Mode: fs.ModeSymlink},
		"empty":      {Mode: fs.ModeDir},
		"pipe":       {Mode: fs.ModeNamedPipe},
	})
	f := &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}}
	srv := serve(t, f)
	ctx := context.Background()
	sess := fakeSession(t, srv, "o/r")
	adv, err := sess.AdvertisedReferencesContext(ctx)
	if err != nil {
		t.Fatalf("AdvertisedReferencesContext() error = %v", err)
	}

	st := memory.NewStorage()
	if err := fetchInto(ctx, st, sess, adv, true, commit); err != nil {
		t.Fatalf("shallow fetch error = %v", err)
	}
	blobs := map[string]plumbing.Hash{}
	modes := map[string]filemode.FileMode{}
	c, err := object.GetCommit(st, commit)
	if err != nil {
		t.Fatalf("GetCommit() error = %v", err)
	}
	tree, err := c.Tree()
	if err != nil {
		t.Fatalf("Tree() error = %v", err)
	}
	walker := object.NewTreeWalker(tree, true, nil)
	for {
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("walking the fetched tree: %v", err)
		}
		modes[name] = entry.Mode
		if entry.Mode != filemode.Dir {
			blobs[name] = entry.Hash
		}
	}
	walker.Close()
	want := map[string]filemode.FileMode{".mcp.json": filemode.Regular, "bin": filemode.Dir, "bin/run.sh": filemode.Executable, "link": filemode.Symlink}
	if !maps.Equal(modes, want) {
		t.Fatalf("fetched tree = %v, want %v", modes, want)
	}
	for name, h := range blobs {
		if _, err := st.EncodedObject(plumbing.BlobObject, h); !errors.Is(err, plumbing.ErrObjectNotFound) {
			t.Fatalf("blob %s after a blob:none fetch: error = %v, want ErrObjectNotFound", name, err)
		}
	}

	if err := fetchInto(ctx, st, sess, adv, false, blobs[".mcp.json"]); err != nil {
		t.Fatalf("blob fetch error = %v", err)
	}
	for name, h := range blobs {
		_, err := st.EncodedObject(plumbing.BlobObject, h)
		if fetched := err == nil; fetched != (name == ".mcp.json") {
			t.Fatalf("blob %s after asking for .mcp.json alone: error = %v", name, err)
		}
	}

	full := memory.NewStorage()
	if err := fetchInto(ctx, full, sess, adv, false, commit); err != nil {
		t.Fatalf("unfiltered fetch error = %v", err)
	}
	thin := packp.NewUploadPackRequestFromCapabilities(adv.Capabilities)
	thin.Wants = []plumbing.Hash{commit}
	_ = thin.Capabilities.Set(capability.ThinPack)
	resp, err := sess.UploadPack(ctx, thin)
	if err != nil {
		t.Fatalf("thin-pack request error = %v", err)
	}
	resp.Close()
	for name, h := range blobs {
		if _, err := full.EncodedObject(plumbing.BlobObject, h); err != nil {
			t.Fatalf("blob %s after an unfiltered fetch: error = %v", name, err)
		}
	}

	log := f.requests()
	if len(log) != 5 || log[0].method != http.MethodGet || log[0].path != "/o/r/info/refs" {
		t.Fatalf("requests = %+v, want a GET of /o/r/info/refs and four POSTs", log)
	}
	if !slices.Contains(log[4].caps, "thin-pack") {
		t.Fatalf("last POST caps = %v, want the thin-pack the request set", log[4].caps)
	}
	if got := log[1]; !slices.Equal(got.wants, []plumbing.Hash{commit}) || got.deepen != "1" || got.filter != "blob:none" || !slices.Contains(got.caps, "shallow") {
		t.Fatalf("first POST = %+v, want the commit alone, deepen 1, filter blob:none", got)
	}
	if got := log[2]; !slices.Equal(got.wants, []plumbing.Hash{blobs[".mcp.json"]}) || got.deepen != "" || got.filter != "" {
		t.Fatalf("second POST = %+v, want the .mcp.json blob alone", got)
	}
}

// go-git maps a 401 and a 404 to its own sentinels, follows a redirect of
// the advertisement, sends credentials it is given, and fails on its
// context while a response stalls.
func TestFakeGitAnswersStatusRedirectAndDelay(t *testing.T) {
	repo, commit := newFakeRepo(t, fstest.MapFS{"a": {Data: []byte("a")}})
	repos := map[string]*fakeRepo{"o/r": repo, "o/private": {status: http.StatusUnauthorized}}

	t.Run("status", func(t *testing.T) {
		srv := serve(t, &fakeGit{repos: repos})
		for repo, want := range map[string]error{"o/private": transport.ErrAuthenticationRequired, "o/missing": transport.ErrRepositoryNotFound} {
			if _, err := fakeSession(t, srv, repo).AdvertisedReferencesContext(context.Background()); !errors.Is(err, want) {
				t.Fatalf("%s: error = %v, want %v", repo, err, want)
			}
		}
	})

	t.Run("redirect", func(t *testing.T) {
		f := &fakeGit{repos: repos, redirect: map[string]string{"old/r": "/o/r"}}
		srv := serve(t, f)
		adv, err := fakeSession(t, srv, "old/r").AdvertisedReferencesContext(context.Background())
		if err != nil {
			t.Fatalf("AdvertisedReferencesContext() error = %v", err)
		}
		if adv.Head == nil || *adv.Head != commit {
			t.Fatalf("Head = %v, want %s from the redirect target", adv.Head, commit)
		}
		if log := f.requests(); len(log) != 2 || log[0].path != "/old/r/info/refs" || log[1].path != "/o/r/info/refs" {
			t.Fatalf("requests = %+v, want /old/r/info/refs then /o/r/info/refs", log)
		}
	})

	t.Run("credentials", func(t *testing.T) {
		f := &fakeGit{repos: repos}
		srv := serve(t, f)
		ep, err := transport.NewEndpoint(srv.URL + "/o/r")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := githttp.NewClient(srv.Client()).NewUploadPackSession(ep, &githttp.BasicAuth{Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.AdvertisedReferencesContext(context.Background()); err != nil {
			t.Fatalf("AdvertisedReferencesContext() error = %v", err)
		}
		if log := f.requests(); len(log) != 1 || log[0].auth == "" {
			t.Fatalf("requests = %+v, want the Authorization header recorded", log)
		}
	})

	t.Run("delay", func(t *testing.T) {
		const deadline = 100 * time.Millisecond
		srv := serve(t, &fakeGit{repos: repos, advDelay: time.Minute})
		ctx, cancel := context.WithTimeout(context.Background(), deadline)
		defer cancel()
		if _, err := fakeSession(t, srv, "o/r").AdvertisedReferencesContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("advertisement past the deadline: error = %v, want context.DeadlineExceeded", err)
		}

		srv = serve(t, &fakeGit{repos: repos, packDelay: time.Minute})
		sess := fakeSession(t, srv, "o/r")
		adv, err := sess.AdvertisedReferencesContext(context.Background())
		if err != nil {
			t.Fatalf("AdvertisedReferencesContext() error = %v", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), deadline)
		defer cancel()
		req := packp.NewUploadPackRequestFromCapabilities(adv.Capabilities)
		req.Wants = []plumbing.Hash{commit}
		resp, err := sess.UploadPack(ctx, req)
		if err != nil {
			t.Fatalf("UploadPack() error = %v, want the response to start before the stall", err)
		}
		defer resp.Close()
		if _, err := io.Copy(io.Discard, resp); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("reading the pack past the deadline: error = %v, want context.DeadlineExceeded", err)
		}
	})
}
