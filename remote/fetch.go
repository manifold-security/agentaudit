package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"maps"
	"net/http"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/internal/report"
	"github.com/manifold-security/agentaudit/treefs"
)

var (
	// ErrNotFound reports a repository that is missing or private: GitHub
	// answers an anonymous request for either alike.
	ErrNotFound = errors.New("remote: repository not found or private")
	// ErrRef reports an unadvertised ref name, a served object that is not a
	// commit, or a /tree/ path that is no directory in the commit.
	ErrRef = errors.New("remote: no such ref or directory")
	// ErrTooLarge reports a repository past one of the fetch's Limits.
	ErrTooLarge = errors.New("remote: repository over a fetch limit")
)

var (
	githubBase    = "https://github.com"
	baseTransport = http.DefaultTransport
)

var hexSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

var collect = runtime.GC

// Fetch reads ref as a branch, tag or SHA, empty for the default branch or a
// /tree/ URL. It sets no timeout of its own; ctx bounds a slow server.
func Fetch(ctx context.Context, rawURL, ref string, s *agentaudit.Scanner, l Limits) (commit string, tree *treefs.FS, err error) {
	if err := l.validate(); err != nil {
		return "", nil, err
	}
	u, err := ParseURL(rawURL)
	if err != nil {
		return "", nil, err
	}
	if ref != "" && len(u.Tree) > 0 {
		return "", nil, fmt.Errorf("%w: a ref beside a /tree/ URL", ErrURL)
	}

	f := newFetcher(ctx, l)
	adv, err := f.open(u)
	if err != nil {
		return "", nil, err
	}
	return f.fetch(adv, u, ref, s)
}

func newFetcher(ctx context.Context, l Limits) *fetcher {
	return &fetcher{
		ctx:      ctx,
		l:        l,
		capped:   &cappedTransport{base: baseTransport, refs: l.RefsBytes, pack: l.PackBytes},
		st:       memory.NewStorage(),
		fetched:  map[plumbing.Hash]bool{},
		withheld: map[plumbing.Hash]bool{},
	}
}

func (f *fetcher) fetch(adv *packp.AdvRefs, u URL, ref string, s *agentaudit.Scanner) (string, *treefs.FS, error) {
	id, sub, err := resolve(adv, u.Tree, ref)
	if err != nil {
		return "", nil, err
	}
	if err := f.reopen(); err != nil {
		return "", nil, err
	}
	root, err := f.tree(id, sub)
	if err != nil {
		return "", nil, err
	}
	collect()
	b, oids, err := f.list(root)
	if err != nil {
		return "", nil, err
	}
	f.st = memory.NewStorage()
	r := &reader{st: f.st, oids: oids, misses: map[uint32]struct{}{}}
	collect()
	t := b.FS(r.read)
	if err := f.rounds(s, t, r); err != nil {
		return "", nil, err
	}
	t.Seal()
	return id.String(), t, nil
}

type fetcher struct {
	ctx    context.Context
	l      Limits
	capped *cappedTransport
	sess   transport.UploadPackSession
	caps   *capability.List
	st     *memory.Storage
	total  int64

	fetched  map[plumbing.Hash]bool
	withheld map[plumbing.Hash]bool
}

func (f *fetcher) open(u URL) (*packp.AdvRefs, error) {
	ep, err := transport.NewEndpoint(githubBase + "/" + u.Owner + "/" + u.Repo)
	if err != nil {
		return nil, fmt.Errorf("remote: %w", err)
	}
	if f.sess, err = f.session(ep); err != nil {
		return nil, err
	}
	adv, err := f.sess.AdvertisedReferencesContext(f.ctx)
	if err != nil {
		return nil, f.failed(err)
	}
	for _, c := range []capability.Capability{capability.Sideband64k, capability.Shallow, capability.Filter, capability.AllowReachableSHA1InWant} {
		if !adv.Capabilities.Supports(c) {
			return nil, fmt.Errorf("remote: the server does not offer %s", c)
		}
	}
	f.caps = adv.Capabilities
	return adv, nil
}

// reopen trades the session, which keeps the advertisement it decoded, for a
// fresh one at the endpoint the advertisement was served from once any
// redirect had moved it.
func (f *fetcher) reopen() error {
	ep, err := transport.NewEndpoint(f.capped.advertised)
	if err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	f.sess, err = f.session(ep)
	return err
}

func (f *fetcher) session(ep *transport.Endpoint) (transport.UploadPackSession, error) {
	client := &http.Client{Transport: f.capped, CheckRedirect: sameOrigin}
	sess, err := githttp.NewClient(client).NewUploadPackSession(ep, nil)
	if err != nil {
		return nil, fmt.Errorf("remote: %w", err)
	}
	return sess, nil
}

var errCrossOrigin = errors.New("remote: refusing a redirect to another scheme or host")

func sameOrigin(req *http.Request, via []*http.Request) error {
	if !strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return errCrossOrigin
	}
	return nil
}

// failed drops the body go-git quotes whole from a 401, 403 or 404 answer.
func (f *fetcher) failed(err error) error {
	switch {
	case errors.Is(err, ErrTooLarge):
		return err
	case errors.Is(err, transport.ErrAuthenticationRequired), errors.Is(err, transport.ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, transport.ErrAuthorizationFailed):
		return fmt.Errorf("remote: %w", transport.ErrAuthorizationFailed)
	}
	return serverError{err}
}

const maxErrorText = 256

// serverError carries text the server or its repository may have written,
// so it reaches Error escaped and cut to maxErrorText bytes.
type serverError struct{ err error }

func (e serverError) Error() string {
	msg := report.Escape(e.err.Error())
	if len(msg) > maxErrorText {
		msg = strings.ToValidUTF8(msg[:maxErrorText], "") + "..."
	}
	return "remote: " + msg
}

func (e serverError) Unwrap() error { return e.err }

func resolve(adv *packp.AdvRefs, tree []string, ref string) (plumbing.Hash, string, error) {
	switch {
	case len(tree) > 0:
		for k := len(tree); k > 0; k-- {
			if h, ok := named(adv, strings.Join(tree[:k], "/")); ok {
				return h, path.Join(tree[k:]...), nil
			}
		}
		if hexSHA.MatchString(tree[0]) {
			return plumbing.NewHash(tree[0]), path.Join(tree[1:]...), nil
		}
	case ref == "":
		if adv.Head != nil {
			return *adv.Head, "", nil
		}
	default:
		if h, ok := named(adv, ref); ok {
			return h, "", nil
		}
		if hexSHA.MatchString(ref) {
			return plumbing.NewHash(ref), "", nil
		}
	}
	return plumbing.ZeroHash, "", ErrRef
}

func named(adv *packp.AdvRefs, name string) (plumbing.Hash, bool) {
	if h, ok := adv.References["refs/heads/"+name]; ok {
		return h, true
	}
	if h, ok := adv.Peeled["refs/tags/"+name]; ok {
		return h, true
	}
	h, ok := adv.References["refs/tags/"+name]
	return h, ok
}

func (f *fetcher) tree(commit plumbing.Hash, sub string) (*object.Tree, error) {
	if err := f.store([]plumbing.Hash{commit}, true); err != nil {
		return nil, err
	}
	c, err := object.GetCommit(f.st, commit)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not a commit", ErrRef, commit)
	}
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("remote: %w", err)
	}
	if sub == "" {
		return tree, nil
	}
	entry, err := tree.FindEntry(sub)
	if err != nil || entry.Mode != filemode.Dir {
		return nil, fmt.Errorf("%w: no directory at the /tree/ path", ErrRef)
	}
	t, err := object.GetTree(f.st, entry.Hash)
	if err != nil {
		return nil, fmt.Errorf("remote: the tree at the /tree/ path: %w", err)
	}
	return t, nil
}

// maxTreePath is the longest path treefs accepts.
const maxTreePath = 4095

type pendingDir struct {
	at      int
	hash    plumbing.Hash
	pathLen int
	up      int
	name    string
}

// list lays the tree out a level at a time, so once treeRefs has checked
// TreeEntries, faults in the directories' entries are refused shallowest
// first. It leaves out a directory with only directories below it, and
// walks the tree itself because go-git's TreeWalker ends a walk silently at
// a subtree the store lacks.
func (f *fetcher) list(root *object.Tree) (*treefs.Builder, []plumbing.Hash, error) {
	b := treefs.NewBuilder()
	refs, hollow, err := treeRefs(f.st, root.Hash, f.l.TreeEntries)
	if err != nil {
		return nil, nil, err
	}
	queue := []pendingDir{{hash: root.Hash, up: -1}}
	var oids []plumbing.Hash
	var next uint32
	var kids []treefs.Kid
	seen := 0
	var pathBytes int64
	for head := 0; head < len(queue); head++ {
		dir := queue[head]
		t, err := object.GetTree(f.st, dir.hash)
		if err != nil {
			return nil, nil, serverError{fmt.Errorf("the tree at %q: %w", dirPath(queue, head), err)}
		}
		if refs[dir.hash]--; refs[dir.hash] == 0 {
			delete(f.st.Objects, dir.hash)
			delete(f.st.Trees, dir.hash)
		}
		for _, e := range t.Entries {
			if seen++; seen > f.l.TreeEntries {
				return nil, nil, fmt.Errorf("%w: more than %d tree entries", ErrTooLarge, f.l.TreeEntries)
			}
			if e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
				return nil, nil, serverError{fmt.Errorf("a tree entry named %q", e.Name)}
			}
			n := entryPathLen(dir, e.Name)
			if n > maxTreePath {
				return nil, nil, fmt.Errorf("remote: a path is %d bytes, over %d", n, maxTreePath)
			}
			if pathBytes += int64(n); pathBytes > f.l.PathBytes {
				return nil, nil, fmt.Errorf("%w: paths past %d bytes in all", ErrTooLarge, f.l.PathBytes)
			}
			if _, ok := kidMode(e.Mode); !ok {
				return nil, nil, fmt.Errorf("remote: unknown mode %v", e.Mode)
			}
		}
		slices.SortFunc(t.Entries, func(x, y object.TreeEntry) int { return strings.Compare(x.Name, y.Name) })
		kids = kids[:0]
		for _, e := range t.Entries {
			if e.Mode == filemode.Dir && hollow[e.Hash] {
				continue
			}
			mode, _ := kidMode(e.Mode)
			kid := treefs.Kid{Name: e.Name, Mode: mode}
			if !mode.IsDir() {
				kid.ID, next = next, next+1
				oids = append(oids, e.Hash)
			}
			kids = append(kids, kid)
		}
		first := -1
		if dir.at >= 0 {
			if first, err = b.Children(dir.at, kids); err != nil {
				return nil, nil, serverError{err}
			}
		}
		at := first
		for _, e := range t.Entries {
			pos := -1
			if e.Mode != filemode.Dir || !hollow[e.Hash] {
				pos, at = at, at+1
			}
			if e.Mode == filemode.Dir {
				queue = append(queue, pendingDir{at: pos, hash: e.Hash, pathLen: entryPathLen(dir, e.Name), up: head, name: e.Name})
			}
		}
	}
	return b, oids, nil
}

func entryPathLen(dir pendingDir, name string) int {
	if dir.up < 0 {
		return len(name)
	}
	return dir.pathLen + 1 + len(name)
}

func dirPath(queue []pendingDir, i int) string {
	var names []string
	for ; i > 0; i = queue[i].up {
		names = append(names, queue[i].name)
	}
	slices.Reverse(names)
	return path.Join(append([]string{"."}, names...)...)
}

func kidMode(m filemode.FileMode) (fs.FileMode, bool) {
	switch m {
	case filemode.Dir, filemode.Submodule:
		return fs.ModeDir | 0o755, true
	case filemode.Regular, filemode.Deprecated:
		return 0o644, true
	case filemode.Executable:
		return 0o755, true
	case filemode.Symlink:
		return fs.ModeSymlink | 0o777, true
	}
	return 0, false
}

// treeRefs must not count short of the listing: a shorter count frees a tree
// while a later directory still names it, so a tree listed below a repeated
// tree counts once per path, and a mode is read as go-git's decoding
// canonicalizes it. The trees it reads are each listed at least once, so past
// max entries in them it refuses as the listing would, before holding more.
func treeRefs(st *memory.Storage, root plumbing.Hash, max int) (map[plumbing.Hash]int, map[plumbing.Hash]bool, error) {
	subdirs := map[plumbing.Hash][]plumbing.Hash{}
	parents := map[plumbing.Hash]int{}
	hollow := map[plumbing.Hash]bool{}
	pending := []plumbing.Hash{root}
	var scratch []byte
	walked := 0
	for len(pending) > 0 {
		h := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		obj, err := st.EncodedObject(plumbing.TreeObject, h)
		if err != nil {
			continue
		}
		r, err := obj.Reader()
		if err != nil {
			continue
		}
		if size := int(obj.Size()); cap(scratch) < size {
			scratch = make([]byte, size)
		}
		data := scratch[:obj.Size()]
		_, err = io.ReadFull(r, data)
		_ = r.Close()
		if err != nil {
			continue
		}
		bare := true
		for {
			sp := bytes.IndexByte(data, ' ')
			if sp < 0 {
				break
			}
			nul := bytes.IndexByte(data[sp+1:], 0)
			if nul < 0 || len(data) < sp+1+nul+1+20 {
				break
			}
			if walked++; walked > max {
				return nil, nil, fmt.Errorf("%w: more than %d tree entries", ErrTooLarge, max)
			}
			var mode uint32
			for _, c := range data[:sp] {
				mode = mode<<3 | uint32(c-'0')
			}
			if mode&0o170000 == 0o040000 {
				sub := plumbing.Hash(data[sp+1+nul+1 : sp+1+nul+1+20])
				subdirs[h] = append(subdirs[h], sub)
				if parents[sub]++; parents[sub] == 1 {
					pending = append(pending, sub)
				}
			} else {
				bare = false
			}
			data = data[sp+1+nul+1+20:]
		}
		if bare {
			hollow[h] = true
		}
	}
	refs := map[plumbing.Hash]int{root: 1}
	ready := []plumbing.Hash{root}
	var order []plumbing.Hash
	for len(ready) > 0 {
		h := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		order = append(order, h)
		for _, sub := range subdirs[h] {
			refs[sub] = min(refs[sub]+refs[h], max+1)
			if parents[sub]--; parents[sub] == 0 {
				ready = append(ready, sub)
			}
		}
	}
	for _, h := range slices.Backward(order) {
		for _, sub := range subdirs[h] {
			if !hollow[sub] {
				delete(hollow, h)
				break
			}
		}
	}
	return refs, hollow, nil
}

type reader struct {
	st   *memory.Storage
	oids []plumbing.Hash

	mu     sync.Mutex
	misses map[uint32]struct{}
}

func (r *reader) read(id uint32) ([]byte, bool) {
	obj, err := r.st.EncodedObject(plumbing.BlobObject, r.oids[id])
	if err == nil {
		if data, err := readObject(obj); err == nil {
			return data, true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.misses[id] = struct{}{}
	return nil, false
}

func (r *reader) missed() []plumbing.Hash {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := slices.Sorted(maps.Keys(r.misses))
	clear(r.misses)
	hashes := make([]plumbing.Hash, len(ids))
	for i, id := range ids {
		hashes[i] = r.oids[id]
	}
	return hashes
}

func readObject(obj plumbing.EncodedObject) ([]byte, error) {
	rd, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

// rounds asks for the blobs the tree's reads refused. It never asks again
// for a blob it withheld: SelectContext reads a withheld path in every round.
func (f *fetcher) rounds(s *agentaudit.Scanner, t *treefs.FS, r *reader) error {
	for range f.l.Rounds {
		r.missed()
		if _, err := s.SelectContext(f.ctx, t); err != nil {
			return fmt.Errorf("remote: %w", err)
		}
		wants, err := f.wanted(slices.Values(r.missed()))
		if err != nil {
			return err
		}
		if len(wants) == 0 {
			return nil
		}
		if err := f.store(wants, false); err != nil {
			return err
		}
	}
	return nil
}

func (f *fetcher) wanted(missed iter.Seq[plumbing.Hash]) ([]plumbing.Hash, error) {
	var wants []plumbing.Hash
	queued := map[plumbing.Hash]bool{}
	for h := range missed {
		if f.fetched[h] || f.withheld[h] || queued[h] {
			continue
		}
		if len(f.fetched)+len(wants) >= f.l.Files {
			return nil, fmt.Errorf("%w: more than %d blobs", ErrTooLarge, f.l.Files)
		}
		queued[h] = true
		wants = append(wants, h)
	}
	return wants, nil
}

// store asks again without the blobs over FileBytes. An oversized blob it
// did not want fails the fetch, since dropping it would not shrink the next
// request.
func (f *fetcher) store(wants []plumbing.Hash, shallow bool) error {
	for len(wants) > 0 {
		pack, err := f.pack(wants, shallow)
		if err != nil {
			return err
		}
		total, over, err := prescan(f.ctx, pack, f.l, f.total)
		if err != nil {
			return f.failed(err)
		}
		if len(over) == 0 {
			if err := storePack(f.st, pack); err != nil {
				return fmt.Errorf("remote: %w", err)
			}
			f.total = total
			if !shallow {
				for _, h := range wants {
					f.fetched[h] = true
				}
			}
			return nil
		}
		for _, h := range over {
			if shallow || !slices.Contains(wants, h) {
				return fmt.Errorf("%w: a blob over %d bytes the fetch did not ask for", ErrTooLarge, f.l.FileBytes)
			}
			f.withheld[h] = true
		}
		wants = slices.DeleteFunc(wants, func(h plumbing.Hash) bool { return slices.Contains(over, h) })
	}
	return nil
}

func storePack(st *memory.Storage, pack []byte) error {
	rd := &dropReader{bytes.NewReader(pack)}
	defer rd.drop()
	return packfile.UpdateObjectStorage(st, rd)
}

func (f *fetcher) pack(wants []plumbing.Hash, shallow bool) ([]byte, error) {
	req := packp.NewUploadPackRequestFromCapabilities(f.caps)
	req.Wants = wants
	if f.caps.Supports(capability.NoProgress) {
		_ = req.Capabilities.Set(capability.NoProgress)
	}
	if shallow {
		_ = req.Capabilities.Set(capability.Shallow)
		_ = req.Capabilities.Set(capability.Filter)
		req.Depth = packp.DepthCommits(1)
		req.Filter = packp.FilterBlobNone()
	}
	resp, err := f.sess.UploadPack(f.ctx, req)
	if err != nil {
		return nil, f.failed(err)
	}
	defer resp.Close()
	pack, err := io.ReadAll(sideband.NewDemuxer(sideband.Sideband64k, resp))
	if err != nil {
		return nil, f.failed(err)
	}
	return pack, nil
}
