package agentaudit

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

type stubGlobalScopedAdapter struct {
	agent       adapter.AgentID
	sigs        []adapter.Signature
	entries     []string
	parseEnts   []ir.Entity
	globalEnts  []ir.Entity
	globalErr   error
	globalCalls *int
}

func (s stubGlobalScopedAdapter) Agent() adapter.AgentID          { return s.agent }
func (s stubGlobalScopedAdapter) Signatures() []adapter.Signature { return s.sigs }

func (s stubGlobalScopedAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return s.parseEnts, nil, nil
}

func (s stubGlobalScopedAdapter) GlobalConfig() adapter.GlobalConfig {
	return adapter.GlobalConfig{Base: adapter.BaseHome, Entries: s.entries}
}

func (s stubGlobalScopedAdapter) ParseGlobal(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	if s.globalCalls != nil {
		*s.globalCalls++
	}
	return s.globalEnts, nil, s.globalErr
}

var _ adapter.GlobalScoped = stubGlobalScopedAdapter{}

type stubPlainAdapter struct {
	agent adapter.AgentID
	sigs  []adapter.Signature
	ents  []ir.Entity
}

func (s stubPlainAdapter) Agent() adapter.AgentID          { return s.agent }
func (s stubPlainAdapter) Signatures() []adapter.Signature { return s.sigs }
func (s stubPlainAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return s.ents, nil, nil
}

var _ adapter.Adapter = stubPlainAdapter{}

func entityNames(ents []ir.Entity) []string {
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Identity()
	}
	return names
}

// anyMCPApprovalRule lets a test see which entities reached the rule engine.
const anyMCPApprovalRule = `[
  {
    "id": "test.mcpapproval.any",
    "name": "Test: any mcpApproval",
    "description": "Synthetic rule matching any mcpApproval with a non-empty Setting.",
    "category": ["code-execution"],
    "appliesTo": [],
    "target": "mcpApproval",
    "match": {"condition": "and", "rules": [{"field": "setting", "op": "exists"}]},
    "message": "test finding",
    "examples": [{"setting": "x", "value": "y"}],
    "negative_examples": [{"setting": ""}]
  }
]`

func anyMCPApprovalRuleFS() fstest.MapFS {
	return fstest.MapFS{"testrules/any.json": &fstest.MapFile{Data: []byte(anyMCPApprovalRule)}}
}

func TestScanGlobal_EntitiesAreUnionOfParseAndParseGlobal(t *testing.T) {
	calls := 0
	a := stubGlobalScopedAdapter{
		agent:       "stub-global",
		sigs:        []adapter.Signature{{Dir: ".", File: "marker"}},
		entries:     []string{".claude"},
		parseEnts:   []ir.Entity{ir.MCPApproval{Setting: "from-parse", Value: "x"}},
		globalEnts:  []ir.Entity{ir.MCPApproval{Setting: "from-global", Value: "y"}},
		globalCalls: &calls,
	}
	fsys := fstest.MapFS{"marker": &fstest.MapFile{}}

	s := New(withRulesFS(anyMCPApprovalRuleFS(), "testrules"), withAdapters(a))
	report, err := s.ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("ParseGlobal calls = %d, want exactly 1", calls)
	}

	gotSettings := map[string]bool{}
	for _, f := range report.Findings() {
		if app, ok := f.Capability.Entity.(ir.MCPApproval); ok {
			gotSettings[app.Setting] = true
		}
	}
	want := map[string]bool{"from-parse": true, "from-global": true}
	if len(gotSettings) != len(want) || !gotSettings["from-parse"] || !gotSettings["from-global"] {
		t.Fatalf("findings' entity Settings = %v, want the union %v", gotSettings, want)
	}
}

// The fault degrades that one source loudly: warned and counted, not dropped.
func TestScanGlobal_ParseGlobalErrorDoesNotDiscardParseEntities(t *testing.T) {
	a := stubGlobalScopedAdapter{
		agent:     "stub-global",
		sigs:      []adapter.Signature{{Dir: ".", File: "marker"}},
		entries:   []string{".claude"},
		parseEnts: []ir.Entity{ir.MCPApproval{Setting: "from-parse", Value: "x"}},
		globalErr: errors.New("boom"),
	}
	fsys := fstest.MapFS{"marker": &fstest.MapFile{}}

	var warned []error
	s := New(
		withRulesFS(anyMCPApprovalRuleFS(), "testrules"),
		withAdapters(a),
		WithWarnFunc(func(err error) { warned = append(warned, err) }),
	)
	report, err := s.ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if len(warned) != 1 {
		t.Fatalf("warnings = %v, want exactly one naming the ParseGlobal fault", warned)
	}
	if !strings.Contains(warned[0].Error(), "boom") {
		t.Fatalf("warning = %q, want it to carry the ParseGlobal error text", warned[0])
	}

	var sawFromParse bool
	for _, f := range report.Findings() {
		if app, ok := f.Capability.Entity.(ir.MCPApproval); ok && app.Setting == "from-parse" {
			sawFromParse = true
		}
	}
	if !sawFromParse {
		t.Fatalf("Findings() = %+v, want the Parse-derived finding to survive a ParseGlobal error", report.Findings())
	}
	if report.UnreadableSources() != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1 (the ParseGlobal fault must still count)", report.UnreadableSources())
	}
}

func TestGlobalPass_ActivatesOnSignatureMatchAlone(t *testing.T) {
	p := globalPass{}
	fsys := fstest.MapFS{}
	a := stubGlobalScopedAdapter{agent: "stub", entries: []string{"nowhere"}}
	if !p.activates(a, fsys, true) {
		t.Fatalf("activates(matched=true) = false, want true (discovery arm)")
	}
}

func TestGlobalPass_ActivatesOnDeclaredEntryPresenceAlone(t *testing.T) {
	p := globalPass{}
	fsys := fstest.MapFS{".claude": &fstest.MapFile{}}
	a := stubGlobalScopedAdapter{agent: "stub", entries: []string{".claude"}}
	if !p.activates(a, fsys, false) {
		t.Fatalf("activates(matched=false) = false, want true: the declared entry is present")
	}
}

func TestGlobalPass_InactiveWhenNeitherArmHolds(t *testing.T) {
	p := globalPass{}
	fsys := fstest.MapFS{}
	a := stubGlobalScopedAdapter{agent: "stub", entries: []string{".claude"}}
	if p.activates(a, fsys, false) {
		t.Fatalf("activates(matched=false) = true, want false: no signature match and no entry present")
	}
}

func TestGlobalPass_NonGlobalScopedAdapterActivatesOnMatchedOnly(t *testing.T) {
	p := globalPass{}
	fsys := fstest.MapFS{}
	a := stubPlainAdapter{agent: "stub"}
	if p.activates(a, fsys, false) {
		t.Fatalf("activates(matched=false) = true, want false for a non-GlobalScoped adapter")
	}
	if !p.activates(a, fsys, true) {
		t.Fatalf("activates(matched=true) = false, want true for a non-GlobalScoped adapter")
	}
}

func TestGlobalPass_EntitiesNeverCallsParseGlobalOnANonGlobalScopedAdapter(t *testing.T) {
	p := globalPass{}
	a := stubPlainAdapter{agent: "stub", ents: []ir.Entity{ir.MCPApproval{Setting: "s", Value: "v"}}}
	if _, ok := any(a).(adapter.GlobalScoped); ok {
		t.Fatal("stubPlainAdapter satisfies adapter.GlobalScoped, which makes this test vacuous")
	}
	ents, _, err := p.entities(a, fstest.MapFS{})
	if err != nil {
		t.Fatalf("entities() error = %v, want nil", err)
	}
	if got := entityNames(ents); len(got) != 1 {
		t.Fatalf("entities() = %v, want exactly Parse's own entity", got)
	}
}

func TestGlobalPass_EntitiesShortCircuitsBeforeParseGlobalOnParseError(t *testing.T) {
	p := globalPass{}
	calls := 0
	a := stubGlobalScopedAdapter{
		agent:       "stub",
		globalCalls: &calls,
	}
	_, _, err := p.entities(stubFailingParseAdapter{a}, fstest.MapFS{})
	if err == nil {
		t.Fatalf("entities() error = nil, want the Parse error propagated")
	}
	if calls != 0 {
		t.Fatalf("ParseGlobal calls = %d, want 0 when Parse itself failed", calls)
	}
}

// stubFailingParseAdapter isolates globalPass.entities' early return on a
// Parse error from ParseGlobal's own behavior.
type stubFailingParseAdapter struct {
	stubGlobalScopedAdapter
}

func (stubFailingParseAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, fs.ErrClosed
}

func TestAnyEntryPresent(t *testing.T) {
	t.Run("declared entry present", func(t *testing.T) {
		fsys := fstest.MapFS{".claude": &fstest.MapFile{}}
		if !anyEntryPresent(fsys, []string{".claude"}) {
			t.Fatalf("anyEntryPresent() = false, want true")
		}
	})

	t.Run("no declared entry present", func(t *testing.T) {
		fsys := fstest.MapFS{}
		if anyEntryPresent(fsys, []string{".claude"}) {
			t.Fatalf("anyEntryPresent() = true, want false")
		}
	})

	t.Run("a non-ErrNotExist Stat failure counts as present", func(t *testing.T) {
		fsys := statFaultMapFS{m: fstest.MapFS{}, failPath: ".claude"}
		if !anyEntryPresent(fsys, []string{".claude"}) {
			t.Fatalf("anyEntryPresent() = false, want true: a permission fault must degrade honestly, not vanish")
		}
	})
}

// A project scan never surfaces a finding whose provenance names a global-only
// source, even when the adapter is active anyway through its own signature.
func TestScan_DoesNotReadGlobalOnlySources(t *testing.T) {
	calls := 0
	a := stubGlobalScopedAdapter{
		agent:   adapter.AgentClaudeCode,
		sigs:    []adapter.Signature{{Dir: ".claude", File: "settings.json"}},
		entries: []string{".claude"},
		parseEnts: []ir.Entity{
			ir.MCPApproval{Setting: "settings-derived", Value: "true", Location: ir.Location{File: ".claude/settings.json"}},
		},
		globalEnts: []ir.Entity{
			ir.MCPApproval{Setting: "global-only", Value: "true", Location: ir.Location{File: ".claude.json"}},
		},
		globalCalls: &calls,
	}
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{},
		".claude.json":          &fstest.MapFile{},
	}

	s := New(withAdapters(a))
	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var sawSettings, sawGlobalOnly bool
	for _, f := range report.Findings() {
		switch f.Capability.Provenance.File {
		case ".claude/settings.json":
			sawSettings = true
		case ".claude.json":
			sawGlobalOnly = true
		}
	}
	if !sawSettings {
		t.Fatalf("no finding attributed to .claude/settings.json; the positive half never ran, so the negative half proves nothing")
	}
	if sawGlobalOnly {
		t.Fatalf("a finding was attributed to .claude.json; Scan must never read a global-only source")
	}
	if calls != 0 {
		t.Fatalf("ParseGlobal calls = %d, want 0 from Scan()", calls)
	}
}

// Against the real Claude adapter, a subdirectory containing only
// .claude.json is never promoted to its own project. See
// TestSignatures_ClaudeJSONMatchesNoSignature for why.
func TestScanRecursive_SubdirectoryHoldingOnlyClaudeJSONYieldsNoReport(t *testing.T) {
	container := fstest.MapFS{
		"sub/.claude.json": &fstest.MapFile{},
	}
	s := New()
	reports, err := s.ScanRecursive(container)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	for _, r := range reports {
		if r.Path == "sub" {
			t.Fatalf("ScanRecursive() reported a project at %q, want .claude.json alone to promote no project root", r.Path)
		}
	}
}

func TestScanGlobal_EmbeddedMCPRulesFireEndToEnd(t *testing.T) {
	fsys := fstest.MapFS{
		".claude.json": &fstest.MapFile{Data: []byte(`{
			"mcpServers": {"top": {"command": "npx"}},
			"projects": {
				"/repo/x": {
					"mcpServers": {"proj-server": {"command": "npx"}},
					"enabledMcpjsonServers": ["proj-approved"]
				}
			}
		}`)},
	}

	s := New()
	report, err := s.ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}

	want := map[string]bool{
		"claude.mcp.server\x00mcpServers.top":                                  false,
		"claude.mcp.server\x00projects./repo/x.mcpServers.proj-server":         false,
		"claude.mcp.auto-approve\x00projects./repo/x.enabledMcpjsonServers[0]": false,
	}
	for _, f := range report.Findings() {
		key := f.RuleID + "\x00" + f.Capability.Provenance.Key
		if _, expected := want[key]; expected {
			want[key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("finding %q not found in %+v", k, report.Findings())
		}
	}
}

// A plugin manifest under $HOME surfaces exactly once, from the cache
// directory Claude Code installs into, carrying that agent and that path.
func TestScanGlobal_AClaudePluginManifestUnderHomeSurfacesOnce(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/plugins/cache/p/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte(`{"name":"claude-side","version":"1.0.0"}`)},
	}

	report, err := New().ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}

	var files []string
	for _, f := range report.Findings() {
		if strings.Contains(f.RuleID, ".plugin.") {
			files = append(files, f.Agent+" "+f.Capability.Provenance.File)
		}
	}

	want := []string{string(adapter.AgentClaudeCode) + " .claude/plugins/cache/p/.claude-plugin/plugin.json"}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("plugin findings = %v, want %v", files, want)
	}
}

// readFaultMapFS holds MapFS in a field rather than embedding it, so it does
// not inherit MapFS's own Sub or Glob.
type readFaultMapFS struct {
	m        fstest.MapFS
	failPath string
}

func (f readFaultMapFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f readFaultMapFS) ReadFile(name string) ([]byte, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrPermission}
	}
	return f.m.ReadFile(name)
}

// An unreadable source degrades alone, the rest of the scan surviving it. The
// real Claude adapter runs here so Parse and ParseGlobal both contribute.
func TestScanGlobal_UnreadableClaudeJSONDegradesThatSourceAlone(t *testing.T) {
	fsys := readFaultMapFS{
		m: fstest.MapFS{
			".claude/settings.json": &fstest.MapFile{Data: []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"notify.sh"}]}]}}`)},
			".claude.json":          &fstest.MapFile{Data: []byte(`{"mcpServers":{}}`)},
		},
		failPath: ".claude.json",
	}

	var warnings []error
	s := New(WithWarnFunc(func(e error) { warnings = append(warnings, e) }))
	report, err := s.ScanGlobal(fsys)
	if err != nil {
		t.Fatalf("ScanGlobal() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly 1", warnings)
	}
	if !strings.Contains(warnings[0].Error(), ".claude.json") {
		t.Fatalf("warning = %q, want it to name .claude.json", warnings[0])
	}
	if report.UnreadableSources() != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1", report.UnreadableSources())
	}

	var sawSettingsFinding bool
	for _, f := range report.Findings() {
		if f.Capability.Provenance.File == ".claude/settings.json" {
			sawSettingsFinding = true
		}
	}
	if !sawSettingsFinding {
		t.Fatalf("Findings() = %+v, want a finding from .claude/settings.json even though .claude.json is unreadable", report.Findings())
	}
}

type statFaultMapFS struct {
	m        fstest.MapFS
	failPath string
}

func (f statFaultMapFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f statFaultMapFS) Stat(name string) (fs.FileInfo, error) {
	if name == f.failPath {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
	}
	return f.m.Stat(name)
}
