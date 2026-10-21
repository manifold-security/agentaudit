package remote

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Owner and repo keep their case; the scheme and host match in any case.
func TestParseURLAcceptsTheGrammar(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	owner39, repo100 := strings.Repeat("o", 39), strings.Repeat("r", 100)

	for _, tc := range []struct {
		raw  string
		want URL
	}{
		{"https://github.com/o/r", URL{Owner: "o", Repo: "r"}},
		{"HTTPS://GitHub.COM/o/r", URL{Owner: "o", Repo: "r"}},
		{"https://github.com/Owner/Re.po_x-1", URL{Owner: "Owner", Repo: "Re.po_x-1"}},
		{"https://github.com/o-x/r", URL{Owner: "o-x", Repo: "r"}},
		{"https://github.com/" + owner39 + "/" + repo100, URL{Owner: owner39, Repo: repo100}},
		{"https://github.com/o/r/tree/main", URL{Owner: "o", Repo: "r", Tree: []string{"main"}}},
		{"https://github.com/o/r/tree/feature/x/sub/dir", URL{Owner: "o", Repo: "r", Tree: []string{"feature", "x", "sub", "dir"}}},
		{"https://github.com/o/r/tree/main/.claude", URL{Owner: "o", Repo: "r", Tree: []string{"main", ".claude"}}},
		{"https://github.com/o/r/tree/" + sha, URL{Owner: "o", Repo: "r", Tree: []string{sha}}},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ParseURL(tc.raw)
			if err != nil {
				t.Fatalf("ParseURL(%q) error = %v, want nil", tc.raw, err)
			}
			if got.Owner != tc.want.Owner || got.Repo != tc.want.Repo || !slices.Equal(got.Tree, tc.want.Tree) {
				t.Fatalf("ParseURL(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

// Each row is refused on its raw bytes.
func TestParseURLRefusesOutsideTheGrammar(t *testing.T) {
	for _, raw := range []string{
		"",
		"http://github.com/o/r",
		"ssh://git@github.com/o/r",
		"file:///etc",
		"ext::sh -c id",
		"git@github.com:o/r",
		"https://github.com",
		"https://github.com/",
		"https://github.com/o",
		"https://www.github.com/o/r",
		"https://github.com.evil.example/o/r",
		"https://user@github.com/o/r",
		"https://user:pw@github.com/o/r",
		"https://github.com:443/o/r",
		"https://github.com/o/r/blob/main/a.md",
		"https://github.com/o/r/issues",
		"https://github.com/o/r.git",
		"https://github.com/o/r.GIT",
		"https://github.com/o/r?q",
		"https://github.com/o/r#f",
		"https://github.com/o/r/",
		"https://github.com/o//r",
		"https://github.com/o/r/tree",
		"https://github.com/o/r/tree/",
		"https://github.com/o/r/tree/main/./x",
		"https://github.com/o/r/tree/main/../x",
		"https://github.com/o/r/tree/%6Dain",
		" https://github.com/o/r",
		"https://github.com/o/r\n",
		"https://github.com/o/r/tree/ma in",
		"https://github.com/o/r/tree/main\tx",
		"https://github.com/o/r/tree/main\x7fx",
		"https://github.com/-o/r",
		"https://github.com/" + strings.Repeat("o", 40) + "/r",
		"https://github.com/o/" + strings.Repeat("r", 101),
		"https://github.com/o/r!",
		"https://github.com/o/.",
		"https://github.com/o/..",
	} {
		t.Run(raw, func(t *testing.T) {
			got, err := ParseURL(raw)
			if !errors.Is(err, ErrURL) {
				t.Fatalf("ParseURL(%q) = %+v, %v, want an error wrapping ErrURL", raw, got, err)
			}
		})
	}
}
