package main

import (
	"bytes"
	"cmp"
	"context"
	stdjson "encoding/json"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/remote"
	"github.com/manifold-security/agentaudit/treefs"
)

const (
	testURL    = "https://github.com/o/r"
	testCommit = "0123456789abcdef0123456789abcdef01234567"
)

type fetchCall struct {
	rawURL, ref string
	limits      remote.Limits
	deadline    time.Time
	hasDeadline bool
}

func withFetch(t *testing.T, serve func(s *agentaudit.Scanner) (*treefs.FS, error)) *[]fetchCall {
	t.Helper()
	calls := &[]fetchCall{}
	original := fetch
	fetch = func(ctx context.Context, rawURL, ref string, s *agentaudit.Scanner, l remote.Limits) (string, *treefs.FS, error) {
		deadline, ok := ctx.Deadline()
		*calls = append(*calls, fetchCall{rawURL: rawURL, ref: ref, limits: l, deadline: deadline, hasDeadline: ok})
		tree, err := serve(s)
		if err != nil {
			return "", nil, err
		}
		return testCommit, tree, nil
	}
	t.Cleanup(func() { fetch = original })
	return calls
}

func sealedTree(t *testing.T, fsys fs.FS, withheld ...string) *treefs.FS {
	t.Helper()
	var entries []treefs.Entry
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			entries = append(entries, treefs.Entry{Path: p, Mode: d.Type()})
		}
		return err
	})
	if err != nil {
		t.Fatalf("fs.WalkDir: %v", err)
	}
	tree, err := treefs.New(entries, func(p string) ([]byte, bool) {
		if slices.Contains(withheld, p) {
			return nil, false
		}
		data, err := fs.ReadFile(fsys, p)
		return data, err == nil
	})
	if err != nil {
		t.Fatalf("treefs.New: %v", err)
	}
	tree.Seal()
	return tree
}

func serveTree(t *testing.T, fsys fs.FS, withheld ...string) func(*agentaudit.Scanner) (*treefs.FS, error) {
	return func(*agentaudit.Scanner) (*treefs.FS, error) { return sealedTree(t, fsys, withheld...), nil }
}

var refusedURLs = []struct {
	arg, reason, redacted string
}{
	{"http://github.com/o/r", "want an https URL", ""},
	{"ftp://x/y", "want an https URL", ""},
	{"file:///etc", "want an https URL", ""},
	{"https://gitlab.com/o/r", "want the host github.com", ""},
	{"https://github.com/o", "want an owner and a repository", ""},
	{"https://github.com/o/r/blob/main/x", "want nothing after the repository but /tree/<ref>", ""},
	{"https://x-access-token:ghs_secret@github.com/o/r", "want the host github.com", "https://***@github.com/o/r"},
	{"https://user@github.com/o/r", "want the host github.com", "https://***@github.com/o/r"},
	{"https://user@github.com", "want the host github.com", "https://***@github.com"},
	{"https://user:p@ss@github.com/o/r", "want the host github.com", "https://***@github.com/o/r"},
	{"https://github.com/o/r/blob/a@b", "want nothing after the repository but /tree/<ref>", ""},
}

func refusalLine(arg, reason, redacted string) string {
	return "agentaudit: " + cmp.Or(redacted, arg) + ": " + remote.ErrURL.Error() + ": " + reason + "\n"
}

func runArgs(args ...string) (stdout, stderr string, code int) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func jsonPaths(t *testing.T, stdout string) []string {
	t.Helper()
	var docs []struct {
		Path string `json:"path"`
	}
	if err := stdjson.Unmarshal([]byte(stdout), &docs); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v, stdout: %s", err, stdout)
	}
	paths := make([]string, len(docs))
	for i, d := range docs {
		paths[i] = d.Path
	}
	return paths
}

// A URL reaches fetch and never openTarget, and a path the reverse; each arm
// counts both seams.
func TestRun_RoutesAURLToFetchAndAPathToOpenTarget(t *testing.T) {
	for _, tc := range []struct {
		arg            string
		fetches, opens int
	}{
		{testURL, 1, 0},
		{"tgt", 0, 1},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			calls := withFetch(t, serveTree(t, fstest.MapFS{}))
			opener := withCountingOpener(t, map[string]fs.FS{"tgt": fstest.MapFS{}})
			if _, stderr, code := runArgs(tc.arg); code != 0 {
				t.Fatalf("run(%q) = %d, want 0\nstderr: %s", tc.arg, code, stderr)
			}
			if len(*calls) != tc.fetches || opener.opens != tc.opens {
				t.Fatalf("run(%q): %d fetches, %d opens, want %d and %d", tc.arg, len(*calls), opener.opens, tc.fetches, tc.opens)
			}
			if tc.fetches > 0 && ((*calls)[0].rawURL != tc.arg || (*calls)[0].ref != "") {
				t.Errorf("fetch got URL %q and ref %q, want %q verbatim and no ref", (*calls)[0].rawURL, (*calls)[0].ref, tc.arg)
			}
		})
	}
}

// An argument outside the URL grammar exits 2 with remote.ParseURL's reason,
// echoing the URL with *** in place of its userinfo, before any fetch; the
// grammar's own form is the arm that fetches.
func TestRun_RefusesAURLOutsideTheGrammarBeforeFetching(t *testing.T) {
	for _, tc := range refusedURLs {
		t.Run(tc.arg, func(t *testing.T) {
			calls := withFetch(t, serveTree(t, fstest.MapFS{}))
			withCountingOpener(t, map[string]fs.FS{})
			_, stderr, code := runArgs(tc.arg)
			if code != 2 || len(*calls) != 0 {
				t.Fatalf("run(%q) = %d after %d fetches, want 2 and none\nstderr: %s", tc.arg, code, len(*calls), stderr)
			}
			if want := refusalLine(tc.arg, tc.reason, tc.redacted); stderr != want {
				t.Errorf("stderr = %q, want exactly %q", stderr, want)
			}
		})
	}
	t.Run(testURL, func(t *testing.T) {
		calls := withFetch(t, serveTree(t, fstest.MapFS{}))
		if _, stderr, code := runArgs(testURL); code != 0 || len(*calls) != 1 {
			t.Fatalf("run(%q) = %d after %d fetches, want 0 and one\nstderr: %s", testURL, code, len(*calls), stderr)
		}
	})
}

// A limit flag's value is refused before the URL is fetched; a valid value
// is the arm that fetches.
func TestRun_ParsesTheLimitFlagsBeforeFetching(t *testing.T) {
	for _, tc := range []struct {
		value   string
		code    int
		fetches int
	}{
		{"bogus", 2, 0},
		{"1MiB", 0, 1},
	} {
		t.Run(tc.value, func(t *testing.T) {
			calls := withFetch(t, serveTree(t, fstest.MapFS{}))
			_, stderr, code := runArgs("--max-file-size", tc.value, testURL)
			if code != tc.code || len(*calls) != tc.fetches {
				t.Fatalf("run(--max-file-size %s) = %d after %d fetches, want %d and %d\nstderr: %s", tc.value, code, len(*calls), tc.code, tc.fetches, stderr)
			}
			if tc.code == 2 && !strings.Contains(stderr, "is not a valid --max-file-size value") {
				t.Errorf("stderr = %q, want the flag's own refusal", stderr)
			}
		})
	}
}

// A URL as --scan-dir exits 2 without a fetch; the same URL as PATH is the
// arm that fetches.
func TestRun_RefusesAURLAsScanDir(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		code    int
		fetches int
	}{
		{[]string{"--scan-dir", testURL}, 2, 0},
		{[]string{"--scan-dir", "HTTPS://github.com/o/r"}, 2, 0},
		{[]string{testURL}, 0, 1},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			calls := withFetch(t, serveTree(t, fstest.MapFS{}))
			withCountingOpener(t, map[string]fs.FS{})
			_, stderr, code := runArgs(tc.args...)
			if code != tc.code || len(*calls) != tc.fetches {
				t.Fatalf("run(%v) = %d after %d fetches, want %d and %d\nstderr: %s", tc.args, code, len(*calls), tc.code, tc.fetches, stderr)
			}
			if tc.code == 2 && !strings.Contains(stderr, "--scan-dir takes a directory") {
				t.Errorf("stderr = %q, want it to say --scan-dir takes a directory", stderr)
			}
		})
	}
}

func TestRun_UnionsAURLPathWithScanDirDirectories(t *testing.T) {
	withFetch(t, serveTree(t, fstest.MapFS{}))
	withCountingOpener(t, map[string]fs.FS{"tgt": fstest.MapFS{}})
	stdout, stderr, code := runArgs(testURL, "--scan-dir", "tgt", "-o", "json")
	if code != 0 {
		t.Fatalf("run() = %d, want 0\nstderr: %s", code, stderr)
	}
	if got, want := jsonPaths(t, stdout), []string{"github.com/o/r@0123456789ab", "tgt"}; !slices.Equal(got, want) {
		t.Errorf("block paths = %q, want %q", got, want)
	}
}

// The display path names the host github.com whatever case the URL typed it
// in, and the commit the fetch resolved.
func TestRun_URLDisplayPath(t *testing.T) {
	nested := fstest.MapFS{"sub/.mcp.json": {Data: []byte(`{"mcpServers":{"fs":{"command":"npx"}}}`)}}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"repository", []string{testURL}, "github.com/o/r@0123456789ab"},
		{"tree", []string{"https://github.com/o/r/tree/feat/x/sub"}, "github.com/o/r/tree/feat/x/sub@0123456789ab"},
		{"upper-case scheme and host", []string{"HTTPS://GitHub.COM/o/r"}, "github.com/o/r@0123456789ab"},
		{"recursive project", []string{"-r", testURL}, "github.com/o/r@0123456789ab/sub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFetch(t, serveTree(t, nested))
			stdout, stderr, code := runArgs(slices.Concat([]string{"-o", "json"}, tc.args)...)
			if code == 2 {
				t.Fatalf("run(%v) = 2\nstderr: %s", tc.args, stderr)
			}
			if got := jsonPaths(t, stdout); !slices.Contains(got, tc.want) {
				t.Errorf("block paths = %q, want one to be %q", got, tc.want)
			}
		})
	}
}

// Under -r the fetch asks for what ScanRecursive reads and the final scan is
// recursive; without it, neither.
func TestRun_RecursiveFetchesAndScansRecursively(t *testing.T) {
	const nested = "sub/.claude/settings.json"
	for _, tc := range []struct {
		args      []string
		recursive bool
	}{
		{[]string{"-r", testURL}, true},
		{[]string{testURL}, false},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var asked []string
			withFetch(t, func(s *agentaudit.Scanner) (*treefs.FS, error) {
				tree, err := treefs.New([]treefs.Entry{{Path: nested}}, func(string) ([]byte, bool) { return nil, false })
				if err != nil {
					return nil, err
				}
				if asked, err = s.Select(tree); err != nil {
					return nil, err
				}
				tree.Seal()
				return tree, nil
			})
			var plain, recursive bool
			withScan(t, func(fs.FS, func(error)) (finding.Report, error) {
				plain = true
				return finding.NewReport(nil), nil
			})
			withScanRecursive(t, func(fs.FS, func(error)) ([]agentaudit.ProjectReport, error) {
				recursive = true
				return nil, nil
			})
			if _, stderr, code := runArgs(tc.args...); code != 0 {
				t.Fatalf("run(%v) = %d, want 0\nstderr: %s", tc.args, code, stderr)
			}
			if got := slices.Contains(asked, nested); got != tc.recursive {
				t.Errorf("fetch asked for %s = %v, want %v (asked %q)", nested, got, tc.recursive, asked)
			}
			if recursive != tc.recursive || plain == tc.recursive {
				t.Errorf("final scan: recursive = %v, plain = %v, want recursive %v", recursive, plain, tc.recursive)
			}
		})
	}
}

// A fetch error exits 2 with the bare error and no hint; the "file size by
// URL" subtest of TestRun_LimitHintNamesTheFlagsWhoseLimitRefused is the arm
// where a URL scan prints one.
func TestRun_AFetchErrorExitsTwoWithTheBareError(t *testing.T) {
	for _, err := range []error{
		remote.ErrNotFound,
		fmt.Errorf("%w: no directory at the /tree/ path", remote.ErrRef),
		fmt.Errorf("%w: more than 2000000 tree entries", remote.ErrTooLarge),
		fmt.Errorf("remote: %w", context.DeadlineExceeded),
	} {
		t.Run(err.Error(), func(t *testing.T) {
			withFetch(t, func(*agentaudit.Scanner) (*treefs.FS, error) { return nil, err })
			stdout, stderr, code := runArgs(testURL)
			if code != 2 {
				t.Fatalf("run() = %d, want 2\nstderr: %s", code, stderr)
			}
			if want := "agentaudit: " + testURL + ": " + err.Error() + "\n"; stderr != want {
				t.Errorf("stderr = %q, want exactly %q", stderr, want)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want no report", stdout)
			}
		})
	}
}

// A file the fetch withheld fails the scan like a limit refusal; the same
// tree held whole is the arm that passes.
func TestRun_AWithheldFileFailsAURLScan(t *testing.T) {
	const settings = ".claude/settings.json"
	tree := fstest.MapFS{settings: {Data: []byte("{}")}}
	for _, recursive := range []bool{false, true} {
		args := []string{testURL}
		if recursive {
			args = []string{"-r", testURL}
		}
		for _, tc := range []struct {
			name     string
			withheld []string
			code     int
		}{
			{"withheld", []string{settings}, 1},
			{"held", nil, 0},
		} {
			t.Run(strings.Join(args, " ")+" "+tc.name, func(t *testing.T) {
				withFetch(t, serveTree(t, tree, tc.withheld...))
				stdout, stderr, code := runArgs(args...)
				if code != tc.code {
					t.Fatalf("run(%v) = %d, want %d\nstdout: %s\nstderr: %s", args, code, tc.code, stdout, stderr)
				}
				incomplete := strings.Contains(stdout, "SCAN INCOMPLETE")
				named := strings.Contains(stderr, "warning: ") && strings.Contains(stderr, settings)
				if withheld := tc.withheld != nil; incomplete != withheld || named != withheld {
					t.Errorf("SCAN INCOMPLETE = %v, warning naming %s = %v, want both %v\nstdout: %s\nstderr: %s", incomplete, settings, named, withheld, stdout, stderr)
				}
			})
		}
	}
}

func TestRun_BoundsTheFetchByFetchTimeout(t *testing.T) {
	original := fetchTimeout
	fetchTimeout = 37 * time.Minute
	t.Cleanup(func() { fetchTimeout = original })
	calls := withFetch(t, serveTree(t, fstest.MapFS{}))

	before := time.Now()
	if _, stderr, code := runArgs(testURL); code != 0 {
		t.Fatalf("run() = %d, want 0\nstderr: %s", code, stderr)
	}
	after := time.Now()
	if len(*calls) != 1 || !(*calls)[0].hasDeadline {
		t.Fatalf("fetch calls = %+v, want one carrying a deadline", *calls)
	}
	if d := (*calls)[0].deadline; d.Before(before.Add(fetchTimeout)) || d.After(after.Add(fetchTimeout)) {
		t.Errorf("deadline = %v, want fetchTimeout after the run started (%v to %v)", d, before.Add(fetchTimeout), after.Add(fetchTimeout))
	}
}

// --global-config refuses a URL PATH before a fetch; the URL alone is the arm
// that fetches.
func TestRun_GlobalConfigRefusesAURLPath(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		code    int
		fetches int
	}{
		{[]string{"--global-config", testURL}, 2, 0},
		{[]string{testURL}, 0, 1},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			calls := withFetch(t, serveTree(t, fstest.MapFS{}))
			_, stderr, code := runArgs(tc.args...)
			if code != tc.code || len(*calls) != tc.fetches {
				t.Fatalf("run(%v) = %d after %d fetches, want %d and %d\nstderr: %s", tc.args, code, len(*calls), tc.code, tc.fetches, stderr)
			}
			if tc.code == 2 && !strings.Contains(stderr, "cannot be combined with PATH") {
				t.Errorf("stderr = %q, want the --global-config conflict", stderr)
			}
		})
	}
}

// The Scanner that fetch's rounds use carries each limit flag: a plugin
// manifest the flag refuses in round 2 leaves the hooks files it names
// unasked, and under a roomier limit round 2 asks for them.
func TestRun_TheFetchScannerCarriesTheLimitFlags(t *testing.T) {
	const (
		manifest  = ".claude-plugin/plugin.json"
		hooks     = "x/hooks.json"
		moreHooks = "y/hooks.json"
	)
	declared := []byte(`{"name":"p","hooks":"./x/hooks.json"}`)
	padded := func(size int) []byte {
		return append(slices.Clip(declared), bytes.Repeat([]byte(" "), size-len(declared))...)
	}
	twoHooks := []byte(`{"name":"p","hooks":["./x/hooks.json","./y/hooks.json"]}`)

	for _, tc := range []struct {
		manifest []byte
		args     []string
		want     []string
	}{
		{padded(600 << 10), []string{testURL}, []string{}},
		{padded(600 << 10), []string{"--max-file-size", "0", testURL}, []string{hooks}},
		{padded(2 << 10), []string{"--max-read-bytes", "1KiB", testURL}, []string{}},
		{padded(2 << 10), []string{testURL}, []string{hooks}},
		{twoHooks, []string{"--max-entities", "1", testURL}, []string{}},
		{twoHooks, []string{testURL}, []string{hooks, moreHooks}},
	} {
		files := map[string][]byte{manifest: tc.manifest, hooks: []byte(`{"hooks":{}}`), moreHooks: []byte(`{"hooks":{}}`)}
		t.Run(fmt.Sprintf("%d B %s", len(tc.manifest), strings.Join(tc.args, " ")), func(t *testing.T) {
			var first, second []string
			withFetch(t, func(s *agentaudit.Scanner) (*treefs.FS, error) {
				held := map[string]bool{}
				tree, err := treefs.New([]treefs.Entry{{Path: manifest}, {Path: hooks}, {Path: moreHooks}}, func(p string) ([]byte, bool) {
					if !held[p] {
						return nil, false
					}
					return files[p], true
				})
				if err != nil {
					return nil, err
				}
				if first, err = s.Select(tree); err != nil {
					return nil, err
				}
				for _, p := range first {
					held[p] = true
				}
				if second, err = s.Select(tree); err != nil {
					return nil, err
				}
				tree.Seal()
				return tree, nil
			})
			if _, stderr, code := runArgs(tc.args...); code == 2 {
				t.Fatalf("run(%v) = 2\nstderr: %s", tc.args, stderr)
			}
			if !slices.Contains(first, manifest) {
				t.Fatalf("premise: round 1 asked %q, want %s among them", first, manifest)
			}
			if !slices.Equal(second, tc.want) {
				t.Errorf("round 2 asked %q, want %q", second, tc.want)
			}
		})
	}
}

func TestURLLimitsAreTheApprovedValues(t *testing.T) {
	want := remote.Limits{
		Rounds:      8,
		TreeEntries: 2_000_000,
		PathBytes:   160 << 20,
		Files:       8_000,
		RefsBytes:   128 << 20,
		PackBytes:   64 << 20,
		FileBytes:   64 << 20,
		TotalBytes:  192 << 20,
	}
	if urlLimits != want {
		t.Errorf("urlLimits = %+v, want %+v", urlLimits, want)
	}
}

func TestFetchTimeoutIsTwoMinutes(t *testing.T) {
	if fetchTimeout != 120*time.Second {
		t.Errorf("fetchTimeout = %v, want 2m0s", fetchTimeout)
	}
}

func TestRun_HandsFetchTheCLILimits(t *testing.T) {
	calls := withFetch(t, serveTree(t, fstest.MapFS{}))
	if _, stderr, code := runArgs(testURL); code != 0 || len(*calls) != 1 {
		t.Fatalf("run() = %d after %d fetches, want 0 and one\nstderr: %s", code, len(*calls), stderr)
	}
	if got := (*calls)[0].limits; got != urlLimits || got == remote.DefaultLimits() {
		t.Errorf("fetch limits = %+v, want urlLimits %+v, not remote.DefaultLimits() %+v", got, urlLimits, remote.DefaultLimits())
	}
}

// Every urlLimits field is at or above its remote.DefaultLimits value.
func TestURLLimitsAreNoTighterThanTheDefaults(t *testing.T) {
	cli, defaults := reflect.ValueOf(urlLimits), reflect.ValueOf(remote.DefaultLimits())
	inspected := 0
	for i := range cli.NumField() {
		inspected++
		if cli.Field(i).Int() < defaults.Field(i).Int() {
			t.Errorf("urlLimits.%s = %d, below the default %d", cli.Type().Field(i).Name, cli.Field(i).Int(), defaults.Field(i).Int())
		}
	}
	if inspected == 0 {
		t.Fatal("inspected no remote.Limits field; this guard would check nothing")
	}
}

func TestRun_EscapesAHostileFetchError(t *testing.T) {
	withFetch(t, func(*agentaudit.Scanner) (*treefs.FS, error) {
		return nil, fmt.Errorf("%w: \x1b[31m\a\u202e", remote.ErrRef)
	})
	_, stderr, code := runArgs(testURL)
	if code != 2 {
		t.Fatalf("run() = %d, want 2\nstderr: %q", code, stderr)
	}
	if !strings.Contains(stderr, `\x1b[31m\a\u202e`) || strings.ContainsAny(stderr, "\x1b\a\u202e") {
		t.Errorf("stderr = %q, want the control and bidi characters escaped", stderr)
	}
}

func TestIsURL(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want bool
	}{
		{"https://github.com/o/r", true},
		{"ftp://x", true},
		{"git+ssh://x", true},
		{"ab://x", true},
		{"C://dir", false},
		{"c://x", false},
		{"./https://x", false},
		{"1a://x", false},
	} {
		if got := isURL(tc.arg); got != tc.want {
			t.Errorf("isURL(%q) = %v, want %v", tc.arg, got, tc.want)
		}
	}
}
