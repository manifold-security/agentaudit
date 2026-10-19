package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"

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

	f := &fetcher{
		ctx:      ctx,
		l:        l,
		capped:   &cappedTransport{base: baseTransport, refs: l.RefsBytes, pack: l.PackBytes},
		st:       memory.NewStorage(),
		fetched:  map[plumbing.Hash]bool{},
		withheld: map[plumbing.Hash]bool{},
	}
	if err := f.open(u); err != nil {
		return "", nil, err
	}
	id, sub, err := resolve(f.adv, u.Tree, ref)
	if err != nil {
		return "", nil, err
	}
	root, err := f.tree(id, sub)
	if err != nil {
		return "", nil, err
	}
	entries, err := f.list(root)
	if err != nil {
		return "", nil, err
	}
	t, err := treefs.New(entries, f.blob)
	if err != nil {
		return "", nil, serverError{err}
	}
	if err := f.rounds(s, t); err != nil {
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
	adv    *packp.AdvRefs
	st     *memory.Storage
	total  int64

	oids     map[string]plumbing.Hash
	fetched  map[plumbing.Hash]bool
	withheld map[plumbing.Hash]bool
}

func (f *fetcher) open(u URL) error {
	ep, err := transport.NewEndpoint(githubBase + "/" + u.Owner + "/" + u.Repo)
	if err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	client := &http.Client{Transport: f.capped, CheckRedirect: sameOrigin}
	f.sess, err = githttp.NewClient(client).NewUploadPackSession(ep, nil)
	if err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	if f.adv, err = f.sess.AdvertisedReferencesContext(f.ctx); err != nil {
		return f.failed(err)
	}
	for _, c := range []capability.Capability{capability.Sideband64k, capability.Shallow, capability.Filter, capability.AllowReachableSHA1InWant} {
		if !f.adv.Capabilities.Supports(c) {
			return fmt.Errorf("remote: the server does not offer %s", c)
		}
	}
	return nil
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

// maxTreePath is the longest path treefs.New accepts.
const maxTreePath = 4095

// list walks the tree itself because go-git's TreeWalker ends a walk
// silently at a subtree the store lacks.
func (f *fetcher) list(root *object.Tree) ([]treefs.Entry, error) {
	f.oids = map[string]plumbing.Hash{}
	var entries []treefs.Entry
	seen := 0
	var pathBytes int64
	var walk func(dir string, t *object.Tree) error
	walk = func(dir string, t *object.Tree) error {
		for _, e := range t.Entries {
			if seen++; seen > f.l.TreeEntries {
				return fmt.Errorf("%w: more than %d tree entries", ErrTooLarge, f.l.TreeEntries)
			}
			if e.Name == "." || e.Name == ".." || strings.Contains(e.Name, "/") {
				return serverError{fmt.Errorf("a tree entry named %q", e.Name)}
			}
			p := path.Join(dir, e.Name)
			if len(p) > maxTreePath {
				return fmt.Errorf("remote: a path is %d bytes, over %d", len(p), maxTreePath)
			}
			if pathBytes += int64(len(p)); pathBytes > f.l.PathBytes {
				return fmt.Errorf("%w: paths past %d bytes in all", ErrTooLarge, f.l.PathBytes)
			}
			var mode fs.FileMode
			switch e.Mode {
			case filemode.Dir:
				sub, err := object.GetTree(f.st, e.Hash)
				if err != nil {
					return serverError{fmt.Errorf("the tree at %q: %w", p, err)}
				}
				if err := walk(p, sub); err != nil {
					return err
				}
				continue
			case filemode.Regular, filemode.Deprecated:
				mode = 0o644
			case filemode.Executable:
				mode = 0o755
			case filemode.Symlink:
				mode = fs.ModeSymlink | 0o777
			case filemode.Submodule:
				entries = append(entries, treefs.Entry{Path: p, Mode: fs.ModeDir | 0o755})
				continue
			default:
				return fmt.Errorf("remote: unknown mode %v", e.Mode)
			}
			entries = append(entries, treefs.Entry{Path: p, Mode: mode})
			f.oids[p] = e.Hash
		}
		return nil
	}
	if err := walk(".", root); err != nil {
		return nil, err
	}
	return entries, nil
}

func (f *fetcher) blob(p string) ([]byte, bool) {
	h, ok := f.oids[p]
	if !ok {
		return nil, false
	}
	obj, err := f.st.EncodedObject(plumbing.BlobObject, h)
	if err != nil {
		return nil, false
	}
	r, err := obj.Reader()
	if err != nil {
		return nil, false
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	return data, err == nil
}

// rounds never asks again for a blob it withheld: Select reads a withheld
// path in every round.
func (f *fetcher) rounds(s *agentaudit.Scanner, t *treefs.FS) error {
	for range f.l.Rounds {
		asked, err := s.Select(t)
		if err != nil {
			return fmt.Errorf("remote: %w", err)
		}
		wants, err := f.wanted(slices.Values(asked))
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

func (f *fetcher) wanted(asked iter.Seq[string]) ([]plumbing.Hash, error) {
	var wants []plumbing.Hash
	queued := map[plumbing.Hash]bool{}
	for p := range asked {
		h, ok := f.oids[p]
		if !ok || f.fetched[h] || f.withheld[h] || queued[h] {
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
			if err := packfile.UpdateObjectStorage(f.st, bytes.NewReader(pack)); err != nil {
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

func (f *fetcher) pack(wants []plumbing.Hash, shallow bool) ([]byte, error) {
	req := packp.NewUploadPackRequestFromCapabilities(f.adv.Capabilities)
	req.Wants = wants
	if f.adv.Capabilities.Supports(capability.NoProgress) {
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
