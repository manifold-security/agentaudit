package remote

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrURL reports a URL outside the accepted GitHub grammar.
var ErrURL = errors.New("remote: not a GitHub repository URL")

// URL is a GitHub repository URL. Tree holds the segments after /tree/
// unresolved, since a ref may itself contain a slash.
type URL struct {
	Owner, Repo string
	Tree        []string
}

var (
	ownerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	repoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// ParseURL accepts https://github.com/<owner>/<repo>[/tree/<ref>[/<path>]]
// and wraps ErrURL around a refusal.
func ParseURL(raw string) (URL, error) {
	// url.Parse would decode a %-escape into the path these checks read.
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] == 0x7f {
			return URL{}, fmt.Errorf("%w: control character or space at byte %d", ErrURL, i)
		}
	}
	const scheme = "https://"
	if len(raw) < len(scheme) || !strings.EqualFold(raw[:len(scheme)], scheme) {
		return URL{}, fmt.Errorf("%w: want an https URL", ErrURL)
	}
	host, rest, _ := strings.Cut(raw[len(scheme):], "/")
	if !strings.EqualFold(host, "github.com") {
		return URL{}, fmt.Errorf("%w: want the host github.com", ErrURL)
	}
	if strings.ContainsAny(rest, "?#%") {
		return URL{}, fmt.Errorf("%w: query, fragment or escape in the path", ErrURL)
	}
	segs := strings.Split(rest, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return URL{}, fmt.Errorf("%w: empty, . or .. path segment", ErrURL)
		}
	}
	if len(segs) < 2 || !ownerPattern.MatchString(segs[0]) {
		return URL{}, fmt.Errorf("%w: want an owner and a repository", ErrURL)
	}
	repo := segs[1]
	if !repoPattern.MatchString(repo) || strings.HasSuffix(strings.ToLower(repo), ".git") {
		return URL{}, fmt.Errorf("%w: invalid repository name", ErrURL)
	}
	u := URL{Owner: segs[0], Repo: repo}
	if len(segs) == 2 {
		return u, nil
	}
	if segs[2] != "tree" || len(segs) == 3 {
		return URL{}, fmt.Errorf("%w: want nothing after the repository but /tree/<ref>", ErrURL)
	}
	u.Tree = segs[3:]
	return u, nil
}
