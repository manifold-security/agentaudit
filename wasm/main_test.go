//go:build js && wasm

package main

import (
	"io/fs"
	"slices"
	"strings"
	"syscall/js"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/memfs"
)

const statusLineSettings = `{"statusLine": {"type": "command", "command": "statusline.sh"}}`

const benignSettings = `{"permissions": {"defaultMode": "default"}}`

// hiddenTreeFS answers a declared name yet enumerates an empty root, so a
// walk from "." visits nothing the host declared.
type hiddenTreeFS struct {
	declared fstest.MapFS
	root     fstest.MapFS
}

func (h hiddenTreeFS) Open(name string) (fs.File, error) {
	if name == "." {
		return h.root.Open(".")
	}
	return h.declared.Open(name)
}

// unreadableDirFS refuses one directory the walk descends into, the shape a
// host filesystem takes when it declares a file under a directory it cannot
// enumerate.
type unreadableDirFS struct {
	tree   fstest.MapFS
	refuse string
}

func (u unreadableDirFS) Open(name string) (fs.File, error) {
	if name == u.refuse {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return u.tree.Open(name)
}

// A declared file set reaches the rule engine and the findings it produces
// come back as a decoded report document, not as rendered text.
func TestScanRendersTheFindingsOfADeclaredFileSet(t *testing.T) {
	res := callScan(t, jsFileSet(t, map[string][]byte{
		".claude/settings.json": []byte(statusLineSettings),
	}))

	if !res.Get("ok").Bool() {
		t.Fatalf("ok = false, error = %q", res.Get("error").String())
	}
	ids := ruleIDs(res.Get("report"))
	if !slices.Contains(ids, "claude.statusline.command") {
		t.Fatalf("report rule ids = %v, want it to include %q", ids, "claude.statusline.command")
	}
	if got := res.Get("report").Get("counts").Get("findings").Int(); got != len(ids) {
		t.Fatalf("counts.findings = %d, want %d", got, len(ids))
	}
}

// Only one object argument is accepted; anything else is fatal rather than
// indexed into.
func TestScanRefusesAnArgumentListItCannotRead(t *testing.T) {
	cases := []struct {
		name string
		args []any
	}{
		{name: "no argument", args: nil},
		{name: "two arguments", args: []any{js.Global().Get("Object").New(), js.Global().Get("Object").New()}},
		{name: "a number", args: []any{42}},
		{name: "null", args: []any{js.Null()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn := install()
			defer fn.Release()

			res := js.Global().Get(namespace).Call("scan", tc.args...)

			if res.Get("ok").Bool() {
				t.Fatalf("ok = true, want a refusal of %v", tc.args)
			}
		})
	}
}

// A string value yields a fatal envelope naming the type it refused.
func TestScanRefusesAStringPayloadInsteadOfCoercingIt(t *testing.T) {
	files := js.Global().Get("Object").New()
	files.Set(".claude/settings.json", statusLineSettings)

	res := callScan(t, files)

	if res.Get("ok").Bool() {
		t.Fatalf("ok = true, want a refusal of a string payload")
	}
	if got := res.Get("error").String(); !strings.Contains(got, "string") {
		t.Fatalf("error = %q, want it to name the rejected JS type", got)
	}
}

// A file set io/fs cannot name is fatal, and the envelope carries no report
// to read.
func TestScanReportsAnUnbuildableFileSetAsFatal(t *testing.T) {
	res := callScan(t, jsFileSet(t, map[string][]byte{
		"/absolute/settings.json": []byte(statusLineSettings),
	}))

	if res.Get("ok").Bool() {
		t.Fatalf("ok = true, want a refusal of an unrooted-path violation")
	}
	if got := res.Get("error").String(); !strings.Contains(got, "/absolute/settings.json") {
		t.Fatalf("error = %q, want it to name the refused path", got)
	}
	if !res.Get("report").IsUndefined() {
		t.Fatalf("report = %v, want it absent from a fatal envelope", res.Get("report"))
	}
	if got := res.Get("warnings"); got.Type() != js.TypeObject || got.Length() != 0 {
		t.Fatalf("warnings = %v, want an empty array a caller can iterate", got)
	}
}

// A refusal of an unbuildable set names the path as the host declared it,
// not as the project root would have rebased it.
func TestAnUnbuildableFileSetIsRefusedUnderItsDeclaredNames(t *testing.T) {
	const declared = "myrepo/.claude/settings.json"
	res := callScan(t, jsFileSet(t, map[string][]byte{
		declared:         []byte(statusLineSettings),
		"myrepo/.claude": []byte("a file where a folder is declared"),
	}))

	if res.Get("ok").Bool() {
		t.Fatalf("ok = true, want a refusal of %q", declared)
	}
	if got := res.Get("error").String(); !strings.Contains(got, `"`+declared+`"`) {
		t.Fatalf("error = %q, want it to name %q", got, declared)
	}
}

// The warning channel and the fatal error both route a hostile name through
// report.Escape. A page renders what it is handed, and a bidi
// override in a scanned name reorders the text printed around it.
func TestHostileNamesReachTheEnvelopeEscaped(t *testing.T) {
	const override = "\u202e"
	const escaped = `\u202e`

	t.Run("warning", func(t *testing.T) {
		skill := ".claude/skills/" + override + "demo/SKILL.md"
		res := callScan(t, jsFileSet(t, map[string][]byte{skill: []byte("---\nname: demo\n")}))

		if !res.Get("ok").Bool() {
			t.Fatalf("ok = false, error = %q", res.Get("error").String())
		}
		assertEscaped(t, strings.Join(jsStrings(res.Get("warnings")), " "), override, escaped)
	})

	t.Run("fatal", func(t *testing.T) {
		files := js.Global().Get("Object").New()
		files.Set(".claude/"+override+"settings.json", statusLineSettings)

		res := callScan(t, files)

		if res.Get("ok").Bool() {
			t.Fatalf("ok = true, want a refusal of a string payload")
		}
		assertEscaped(t, res.Get("error").String(), override, escaped)
	})
}

func assertEscaped(t *testing.T, got, raw, want string) {
	t.Helper()

	if strings.Contains(got, raw) {
		t.Fatalf("%q carries the hostile rune unescaped", got)
	}
	if !strings.Contains(got, want) {
		t.Fatalf("%q does not carry %s", got, want)
	}
}

// A source the scanner could not parse is named in the envelope, and a
// well-formed one leaves it empty.
func TestWarningsFromADegradedScanReachTheEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		want     bool
	}{
		{name: "truncated json", settings: `{"statusLine": `, want: true},
		{name: "well-formed json", settings: statusLineSettings, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callScan(t, jsFileSet(t, map[string][]byte{
				".claude/settings.json": []byte(tc.settings),
			}))

			if !res.Get("ok").Bool() {
				t.Fatalf("ok = false, error = %q", res.Get("error").String())
			}
			warnings := res.Get("warnings")
			if got := warnings.Length() > 0; got != tc.want {
				t.Fatalf("warnings = %v, want any = %v", jsStrings(warnings), tc.want)
			}
			if !tc.want {
				return
			}
			if got := warnings.Index(0).String(); !strings.Contains(got, ".claude/settings.json") {
				t.Fatalf("warnings[0] = %q, want it to name the source", got)
			}
		})
	}
}

// A host filesystem whose declared files no walk can reach is fatal, and the
// same files through a sound one are not.
func TestAHostFilesystemHidingItsDeclaredFilesIsFatalRatherThanClean(t *testing.T) {
	files := map[string][]byte{".claude/settings.json": []byte(statusLineSettings)}

	sound, err := memfs.New(files)
	if err != nil {
		t.Fatalf("memfs.New() error = %v", err)
	}
	hidden := hiddenTreeFS{
		declared: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(statusLineSettings)}},
		root:     fstest.MapFS{},
	}

	if got := envelope(hidden, files); got["ok"] != false {
		t.Fatalf("envelope over an unenumerable tree = %v, want a fatal", got)
	} else if msg, _ := got["error"].(string); !strings.Contains(msg, "blind") {
		t.Fatalf("error = %q, want it to name the scan as blind", msg)
	}
	if got := envelope(sound, files); got["ok"] != true {
		t.Fatalf("envelope over the same files through a sound filesystem = %v, want ok", got)
	}
}

// A set declared under a picked project folder scans as that project, even
// when a depth-agnostic plugin manifest beside its config matches under the
// prefix too.
func TestAPickedProjectFolderScansAsTheProjectItself(t *testing.T) {
	res := callScan(t, jsFileSet(t, map[string][]byte{
		"chosen-dir/.claude/settings.json":      []byte(statusLineSettings),
		"chosen-dir/.claude-plugin/plugin.json": []byte(`{"name": "demo"}`),
	}))

	if !res.Get("ok").Bool() {
		t.Fatalf("ok = false, error = %q", res.Get("error").String())
	}
	findings := res.Get("report").Get("findings")
	for i := range findings.Length() {
		capability := findings.Index(i).Get("capability")
		if findings.Index(i).Get("ruleId").String() != "claude.statusline.command" {
			continue
		}
		if got := capability.Get("file").String(); got != ".claude/settings.json" {
			t.Fatalf("statusline finding file = %q, want it relative to the picked folder", got)
		}
		return
	}
	t.Fatalf("report rule ids = %v, want the prefixed settings scanned", ruleIDs(res.Get("report")))
}

// A set holding no agent config under any root scans clean with no agent
// scanned, the document the CLI renders for a config-less tree, and a set
// holding config names the agent it scanned.
func TestAConfigLessSetReportsThatNoAgentConfigWasRead(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string][]byte
		agents   int
		findings bool
	}{
		{name: "config-less", files: map[string][]byte{"myrepo/README.md": []byte("# demo\n")}},
		{name: "configured", files: map[string][]byte{"myrepo/.claude/settings.json": []byte(statusLineSettings)}, agents: 1, findings: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callScan(t, jsFileSet(t, tc.files))

			if !res.Get("ok").Bool() {
				t.Fatalf("ok = false, error = %q", res.Get("error").String())
			}
			report := res.Get("report")
			if got := report.Get("scannedAgents").Length(); got != tc.agents {
				t.Fatalf("scannedAgents = %d entries, want %d", got, tc.agents)
			}
			if got := report.Get("findings").Length(); (got > 0) != tc.findings {
				t.Fatalf("findings = %d, want any = %v", got, tc.findings)
			}
		})
	}
}

// A set whose project root cannot be settled is fatal rather than a report
// that reads as complete.
func TestADeclaredSetWithAnUnsettledRootIsFatal(t *testing.T) {
	cases := []struct {
		name  string
		files map[string][]byte
	}{
		{name: "config below the root", files: map[string][]byte{"projects/myrepo/.claude/settings.json": []byte(statusLineSettings)}},
		{name: "config at two roots", files: map[string][]byte{
			".claude/settings.json":         []byte(benignSettings),
			".claude/.claude/settings.json": []byte(statusLineSettings),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callScan(t, jsFileSet(t, tc.files))

			if res.Get("ok").Bool() {
				t.Fatalf("ok = true, want a refusal (report = %v)", ruleIDs(res.Get("report")))
			}
			if got := res.Get("error").String(); !strings.Contains(got, "project root") {
				t.Fatalf("error = %q, want it to name the unsettled project root", got)
			}
			if !res.Get("report").IsUndefined() {
				t.Fatalf("report = %v, want it absent from a fatal envelope", res.Get("report"))
			}
		})
	}
}

// A fatal envelope still carries the warnings the scan emitted before it
// failed, and still declares the host's blind spots.
func TestAFatalEnvelopeCarriesTheWarningsAndTheLimits(t *testing.T) {
	files := map[string][]byte{".claude/settings.json": []byte(statusLineSettings)}
	fsys := unreadableDirFS{
		tree: fstest.MapFS{
			".claude/settings.json": &fstest.MapFile{Data: []byte(statusLineSettings)},
		},
		refuse: ".claude",
	}

	got := envelope(fsys, files)

	if got["ok"] != false {
		t.Fatalf("envelope over an unenumerable directory = %v, want a fatal", got)
	}
	warnings, _ := got["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("warnings = %v, want the refused directory named", got["warnings"])
	}
	limits, _ := got["limits"].([]any)
	if len(limits) == 0 {
		t.Fatalf("limits = %v, want the host blind spots declared on a fatal too", got["limits"])
	}
}

// Declaring no file at all is fatal.
func TestScanRefusesAnEmptyFileSet(t *testing.T) {
	res := callScan(t, js.Global().Get("Object").New())

	if res.Get("ok").Bool() {
		t.Fatalf("ok = true, want a refusal of a file set holding nothing")
	}
}

// The envelope declares what the host structurally cannot observe.
func TestTheEnvelopeDeclaresTheHostBlindSpots(t *testing.T) {
	res := callScan(t, jsFileSet(t, map[string][]byte{
		".claude/settings.json": []byte(statusLineSettings),
	}))

	limits := res.Get("limits")
	if limits.Length() == 0 {
		t.Fatalf("limits = [], want the execute-bit blind spot declared")
	}
	var ids []string
	for i := range limits.Length() {
		ids = append(ids, limits.Index(i).Get("id").String())
	}
	if !slices.Contains(ids, executableBitLimit) {
		t.Fatalf("limit ids = %v, want it to include %q", ids, executableBitLimit)
	}
}

// callScan drives the entry point the way a host page does, through the
// global install publishes rather than through the Go function directly.
func callScan(t *testing.T, files js.Value) js.Value {
	t.Helper()

	fn := install()
	defer fn.Release()
	return js.Global().Get(namespace).Call("scan", files)
}

func jsFileSet(t *testing.T, files map[string][]byte) js.Value {
	t.Helper()

	obj := js.Global().Get("Object").New()
	for name, data := range files {
		buf := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(buf, data)
		obj.Set(name, buf)
	}
	return obj
}

func ruleIDs(report js.Value) []string {
	findings := report.Get("findings")
	ids := make([]string, findings.Length())
	for i := range findings.Length() {
		ids[i] = findings.Index(i).Get("ruleId").String()
	}
	return ids
}

func jsStrings(arr js.Value) []string {
	out := make([]string, arr.Length())
	for i := range arr.Length() {
		out[i] = arr.Index(i).String()
	}
	return out
}
