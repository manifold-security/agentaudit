package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/limits"
)

const twoHookSettings = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"a"},{"type":"command","command":"b"}]}]}}`

func runOverTree(t *testing.T, tree fs.FS, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	const home = "/agentaudit-test-home"
	t.Setenv("HOME", home)
	withCountingOpener(t, map[string]fs.FS{"tgt": tree, home: tree})
	withFetch(t, serveTree(t, tree))
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

// A limit flag bounds every scan path alike; the same run without the flag is
// the arm showing nothing else refused the file.
func TestRun_EachLimitFlagReachesEveryScanPath(t *testing.T) {
	tree := fstest.MapFS{".claude/settings.json": {Data: []byte(twoHookSettings)}}
	for _, path := range []struct {
		name string
		args []string
	}{
		{"plain", []string{"tgt"}},
		{"recursive", []string{"-r", "tgt"}},
		{"global", []string{"--global-config"}},
		{"url", []string{testURL}},
		{"url recursive", []string{"-r", testURL}},
	} {
		for _, limit := range []struct {
			flag, value, refusal string
		}{
			{"--max-file-size", "8", ".claude/settings.json: over the 8 B limit for one file; not scanned"},
			{"--max-read-bytes", "8", "past the scan's 8 B read budget; not scanned"},
			{"--max-entities", "1", ".claude/settings.json: would take the scan past 1 entities; not scanned"},
		} {
			t.Run(path.name+" "+limit.flag, func(t *testing.T) {
				args := slices.Concat(path.args, []string{limit.flag, limit.value})
				if _, stderr, _ := runOverTree(t, tree, args...); !strings.Contains(stderr, limit.refusal) {
					t.Errorf("run(%v) stderr = %q, want a warning naming %q", args, stderr, limit.refusal)
				}
				if _, stderr, _ := runOverTree(t, tree, path.args...); strings.Contains(stderr, "not scanned") {
					t.Errorf("run(%v) stderr = %q, want no refusal without %s", path.args, stderr, limit.flag)
				}
			})
		}
	}
}

// Zero lifts a limit: a file its default refuses is scanned with the flag at
// 0, and the run without the flag is the arm showing the default refuses it.
func TestRun_ZeroTurnsEachLimitFlagOff(t *testing.T) {
	oneFile := []byte(strings.Repeat(" ", 512<<10))
	overBudget := fstest.MapFS{".claude/agents/z.md": {Data: []byte(" ")}}
	for i := range 128 {
		overBudget[fmt.Sprintf(".claude/agents/a%03d.md", i)] = &fstest.MapFile{Data: oneFile}
	}
	commandHooks := strings.TrimSuffix(strings.Repeat(`{"type":"command","command":"x"},`, 10001), ",")
	overEntities := `{"hooks":{"PreToolUse":[{"hooks":[` + commandHooks + `]}]}}`

	for _, tc := range []struct {
		flag    string
		tree    fstest.MapFS
		refusal string
		code    int
	}{
		{"--max-file-size", fstest.MapFS{".claude/settings.json": {Data: append([]byte("{}"), oneFile...)}}, "over the 512 KiB limit for one file", 0},
		{"--max-read-bytes", overBudget, "past the scan's 64 MiB read budget", 0},
		{"--max-entities", fstest.MapFS{".claude/settings.json": {Data: []byte(overEntities)}}, "would take the scan past 10000 entities", 1},
	} {
		for _, target := range [][]string{{"tgt"}, {testURL}, {"-r", testURL}} {
			t.Run(tc.flag+" "+strings.Join(target, " "), func(t *testing.T) {
				if _, stderr, _ := runOverTree(t, tc.tree, target...); !strings.Contains(stderr, tc.refusal) {
					t.Fatalf("premise: stderr = %q, want the default to refuse with %q", stderr, tc.refusal)
				}
				if _, stderr, code := runOverTree(t, tc.tree, slices.Concat([]string{tc.flag, "0"}, target)...); code != tc.code || strings.Contains(stderr, "not scanned") {
					t.Errorf("exit code = %d, stderr = %q, want %d and no refusal with %s 0", code, stderr, tc.code, tc.flag)
				}
			})
		}
	}
}

// A negative limit is a usage error that stops before any scan; 0 is the arm
// showing the same flag parses and scans.
func TestRun_ANegativeLimitIsAUsageError(t *testing.T) {
	scanned := false
	withScan(t, func(fs.FS, func(error)) (finding.Report, error) {
		scanned = true
		return finding.NewReport(nil), nil
	})
	for _, flag := range []string{"--max-file-size", "--max-read-bytes", "--max-entities"} {
		t.Run(flag, func(t *testing.T) {
			scanned = false
			var stdout, stderr bytes.Buffer
			if got := run([]string{flag, "-1"}, &stdout, &stderr); got != 2 {
				t.Fatalf("run(%s -1) = %d, want 2\nstderr: %s", flag, got, stderr.String())
			}
			if want := " is not a valid " + flag + " value"; !strings.Contains(stderr.String(), "-1") || !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want it to name -1 and contain %q", stderr.String(), want)
			}
			if scanned || stdout.Len() != 0 {
				t.Errorf("run(%s -1) scanned = %v, stdout = %q, want no scan and no report", flag, scanned, stdout.String())
			}

			if got := run([]string{flag, "0"}, &stdout, &stderr); got != 0 || !scanned || stdout.Len() == 0 {
				t.Errorf("run(%s 0) = %d, scanned = %v, stdout = %q, want 0, a scan and a report", flag, got, scanned, stdout.String())
			}
		})
	}
}

// The hint, printed after every warning, names the flag of each limit that
// refused a file, and stays silent when no refusal came from a limit with a
// flag.
func TestRun_LimitHintNamesTheFlagsWhoseLimitRefused(t *testing.T) {
	var laughs strings.Builder
	laughs.WriteString("---\nname: a\nl0: &l0 [" + strings.Repeat("x, ", 9) + "x]\n")
	for i := 1; i <= 7; i++ {
		fmt.Fprintf(&laughs, "l%d: &l%d [%s*l%d]\n", i, i, strings.Repeat(fmt.Sprintf("*l%d, ", i-1), 9), i-1)
	}
	laughs.WriteString("---\n")
	aliasAgent := fstest.MapFS{".claude/agents/a.md": {Data: []byte(laughs.String())}}

	deep := []byte(`{"z":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`)
	settings := fstest.MapFS{".claude/settings.json": {Data: []byte(twoHookSettings)}}

	const (
		fileSizeHint   = "hint: raise --max-file-size to scan the files it refused; 0 turns it off"
		readBudgetHint = "hint: raise --max-read-bytes to scan the files it refused; 0 turns it off"
		entitiesHint   = "hint: raise --max-entities to scan the files it refused; 0 turns it off"
	)
	for _, tc := range []struct {
		name string
		tree fstest.MapFS
		args []string
		code int
		hint string
	}{
		{"file size", settings, []string{"--max-file-size", "8"}, 1, fileSizeHint},
		{"read budget", settings, []string{"--max-read-bytes", "8"}, 1, readBudgetHint},
		{"entities", settings, []string{"--max-entities", "1"}, 1, entitiesHint},
		{"aliases past the entity budget", aliasAgent, nil, 1, entitiesHint},
		{"file size and entities", fstest.MapFS{
			".claude/settings.json": {Data: []byte(twoHookSettings + strings.Repeat(" ", 200))},
			".mcp.json":             {Data: []byte(`{"mcpServers":{"a":{"command":"x"},"b":{"command":"y"}}}`)},
		}, []string{"--max-file-size", "200", "--max-entities", "1"}, 1, "hint: raise --max-file-size and --max-entities to scan the files they refused; 0 turns each off"},
		{"depth beside file size", fstest.MapFS{
			".claude/settings.json": {Data: deep},
			".mcp.json":             {Data: []byte(`{"mcpServers":{}}` + strings.Repeat(" ", 40000))},
		}, []string{"--max-file-size", "30000"}, 1, fileSizeHint},
		{"depth alone", fstest.MapFS{".claude/settings.json": {Data: deep}}, nil, 1, ""},
		{"alias ceiling alone", aliasAgent, []string{"--max-entities", "0"}, 1, ""},
		{"malformed", fstest.MapFS{".claude/settings.json": {Data: []byte("{not valid json")}}, nil, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runOverTree(t, tc.tree, slices.Concat(tc.args, []string{"tgt"})...)
			if code != tc.code {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tc.code, stderr)
			}
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			if tc.hint != "" {
				if got := lines[len(lines)-1]; got != tc.hint {
					t.Errorf("last stderr line = %q, want %q", got, tc.hint)
				}
				lines = lines[:len(lines)-1]
			}
			for _, line := range lines {
				if !strings.HasPrefix(line, "warning: ") {
					t.Errorf("stderr line %q, want every line but the hint to be a warning\nstderr: %s", line, stderr)
				}
			}
			if strings.Contains(stdout, "hint:") {
				t.Errorf("stdout = %q, want the hint on stderr alone", stdout)
			}
		})
	}
	t.Run("file size by URL", func(t *testing.T) {
		_, stderr, code := runOverTree(t, settings, "--max-file-size", "8", testURL)
		lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
		if code != 1 || lines[len(lines)-1] != fileSizeHint {
			t.Errorf("exit code = %d, last stderr line = %q, want 1 and %q", code, lines[len(lines)-1], fileSizeHint)
		}
	})
}

// A report file that fails to write after a refusal still leaves the hint
// closing the warnings, ahead of the error line that sets exit 2.
func TestRun_LimitHintSurvivesAFailedReportWrite(t *testing.T) {
	original := createFile
	createFile = func(string) (io.WriteCloser, error) { return nil, errors.New("refused by the test") }
	t.Cleanup(func() { createFile = original })
	tree := fstest.MapFS{".claude/settings.json": {Data: []byte(twoHookSettings)}}

	_, stderr, code := runOverTree(t, tree, "--max-file-size", "8", "-O", "json", "tgt")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2\nstderr: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("stderr = %q, want warnings, the hint and the write error", stderr)
	}
	if got, want := lines[len(lines)-2], "hint: raise --max-file-size to scan the files it refused; 0 turns it off"; got != want {
		t.Errorf("line before the error = %q, want %q\nstderr: %s", got, want, stderr)
	}
	if got := lines[len(lines)-1]; !strings.HasPrefix(got, "agentaudit: ") {
		t.Errorf("last stderr line = %q, want the write error", got)
	}
	for _, line := range lines[:len(lines)-2] {
		if !strings.HasPrefix(line, "warning: ") {
			t.Errorf("stderr line %q, want every line before the hint to be a warning\nstderr: %s", line, stderr)
		}
	}
}

func helpLine(t *testing.T, flag string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--help"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run(--help) = %d, want 0\nstderr: %s", got, stderr.String())
	}
	i := strings.Index(stdout.String(), flag)
	if i < 0 {
		t.Fatalf("help = %q, want a line for %q", stdout.String(), flag)
	}
	line, _, _ := strings.Cut(stdout.String()[i:], "\n")
	return line
}

// --help shows each limit flag's default in human units and that 0 lifts it,
// and names the suffixes on the byte flags alone.
func TestRun_HelpShowsEachLimitFlagsDefault(t *testing.T) {
	const suffixes = "in bytes or with a KiB, MiB or GiB suffix"
	for _, tc := range []struct {
		flag, def string
		suffixes  bool
	}{
		{"--max-file-size bytes", "(default 512KiB)", true},
		{"--max-read-bytes bytes", "(default 64MiB)", true},
		{"--max-entities int", "(default 10000)", false},
	} {
		line := helpLine(t, tc.flag)
		if !strings.HasSuffix(line, "0 turns it off "+tc.def) {
			t.Errorf("help line = %q, want it to end %q", line, "0 turns it off "+tc.def)
		}
		if got := strings.Contains(line, suffixes); got != tc.suffixes {
			t.Errorf("help line = %q, naming %q = %v, want %v", line, suffixes, got, tc.suffixes)
		}
	}
}

// The default a byte flag's help prints is a value the flag accepts, and it
// parses back to the library's default.
func TestRun_EachByteFlagsHelpDefaultParsesToTheLibraryDefault(t *testing.T) {
	for flag, want := range map[string]int64{
		"--max-file-size":  limits.DefaultFileSize,
		"--max-read-bytes": limits.DefaultReadBytes,
	} {
		_, def, _ := strings.Cut(helpLine(t, flag+" bytes"), "(default ")
		def = strings.TrimSuffix(def, ")")
		if got, ok := parseBytes(def); !ok || got != want {
			t.Errorf("parseBytes(%q) from %s's help = %d, %v, want %d, true", def, flag, got, ok, want)
		}
	}
}

// A byte count is decimal digits, optionally followed by KiB, MiB or GiB in
// any case, whose value fits an int64.
func TestParseBytes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true},
		{"0KiB", 0, true},
		{"1", 1, true},
		{"010", 10, true},
		{"524288", 512 << 10, true},
		{"512KiB", 512 << 10, true},
		{"2MiB", 2 << 20, true},
		{"1GiB", 1 << 30, true},
		{"2mib", 2 << 20, true},
		{"1KIB", 1 << 10, true},
		{"9223372036854775807", math.MaxInt64, true},
		{"8589934591GiB", 8589934591 << 30, true},
		{"", 0, false},
		{"KiB", 0, false},
		{"-1", 0, false},
		{"-1KiB", 0, false},
		{"+1", 0, false},
		{"1.5MiB", 0, false},
		{"2 MiB", 0, false},
		{" 2MiB", 0, false},
		{"2KB", 0, false},
		{"2MB", 0, false},
		{"2k", 0, false},
		{"2M", 0, false},
		{"2B", 0, false},
		{"2TiB", 0, false},
		{"0x10", 0, false},
		{"1e3", 0, false},
		{"\uff11KiB", 0, false},
		{"2\u212aiB", 0, false},
		{"9223372036854775808", 0, false},
		{"8589934592GiB", 0, false},
		{"9007199254740992GiB", 0, false},
	} {
		if got, ok := parseBytes(tc.in); got != tc.want || ok != tc.ok {
			t.Errorf("parseBytes(%q) = %d, %v, want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// A suffix scales a byte flag by its power of 1024, so 1KiB refuses what 2KiB
// admits, and 0 with a suffix lifts the limit as a bare 0 does.
func TestRun_ByteFlagSuffixesScaleTheLimit(t *testing.T) {
	padded := fstest.MapFS{".claude/settings.json": {Data: []byte(twoHookSettings + strings.Repeat(" ", 1500))}}
	overDefault := fstest.MapFS{".claude/settings.json": {Data: []byte("{}" + strings.Repeat(" ", 512<<10))}}
	for _, tc := range []struct {
		name    string
		tree    fstest.MapFS
		args    []string
		refusal string
	}{
		{"file size of 1KiB", padded, []string{"--max-file-size", "1KiB"}, "over the 1 KiB limit for one file"},
		{"read budget of 1KiB", padded, []string{"--max-read-bytes", "1KiB"}, "past the scan's 1 KiB read budget"},
		{"file size of 2KiB", padded, []string{"--max-file-size", "2KiB"}, ""},
		{"read budget of 2kib", padded, []string{"--max-read-bytes", "2kib"}, ""},
		{"file size at its default", overDefault, nil, "over the 512 KiB limit for one file"},
		{"file size of 0MiB", overDefault, []string{"--max-file-size", "0MiB"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := runOverTree(t, tc.tree, slices.Concat(tc.args, []string{"tgt"})...)
			if code == 2 {
				t.Fatalf("exit code = 2, want a scan\nstderr: %s", stderr)
			}
			if tc.refusal == "" && strings.Contains(stderr, "not scanned") {
				t.Errorf("stderr = %q, want no refusal", stderr)
			}
			if tc.refusal != "" && !strings.Contains(stderr, tc.refusal) {
				t.Errorf("stderr = %q, want a warning naming %q", stderr, tc.refusal)
			}
		})
	}
}

// A byte flag value the parser refuses is a usage error that names the
// accepted forms and stops before any scan; 2MiB is the arm showing the flag
// parses and scans.
func TestRun_AByteFlagRefusesAnUnacceptedForm(t *testing.T) {
	scanned := false
	withScan(t, func(fs.FS, func(error)) (finding.Report, error) {
		scanned = true
		return finding.NewReport(nil), nil
	})
	for _, flag := range []string{"--max-file-size", "--max-read-bytes"} {
		for _, value := range []string{"1.5MiB", "2KB", "0x10", "8589934592GiB"} {
			t.Run(flag+" "+value, func(t *testing.T) {
				scanned = false
				var stdout, stderr bytes.Buffer
				if got := run([]string{flag, value}, &stdout, &stderr); got != 2 {
					t.Fatalf("run(%s %s) = %d, want 2\nstderr: %s", flag, value, got, stderr.String())
				}
				want := fmt.Sprintf("agentaudit: %q is not a valid %s value (want a whole number of bytes, optionally followed by KiB, MiB or GiB; 0 turns the limit off)\n", value, flag)
				if stderr.String() != want {
					t.Errorf("stderr = %q, want %q", stderr.String(), want)
				}
				if scanned || stdout.Len() != 0 {
					t.Errorf("scanned = %v, stdout = %q, want no scan and no report", scanned, stdout.String())
				}
			})
		}
		t.Run(flag+" 2MiB", func(t *testing.T) {
			scanned = false
			var stdout, stderr bytes.Buffer
			if got := run([]string{flag, "2MiB"}, &stdout, &stderr); got != 0 || !scanned || stdout.Len() == 0 {
				t.Errorf("run(%s 2MiB) = %d, scanned = %v, stdout = %q, want 0, a scan and a report\nstderr: %s", flag, got, scanned, stdout.String(), stderr.String())
			}
		})
	}
}
