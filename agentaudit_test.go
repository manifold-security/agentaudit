package agentaudit_test

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/report/pretty"
)

// validStubSettings is a well-formed .claude/settings.json the Claude adapter
// decodes into one ir.Hook{Event: "PreToolUse", Command: "audit.sh"}.
const validStubSettings = `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"audit.sh"}]}]}}`

func hookScanFS() fstest.MapFS {
	return fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}
}

// syntheticHookRule is never shipped in rules/claude. Its examples are
// validated by ruleeng.Load, so a bad one fails the load, not the assertion.
const syntheticHookRule = `[
  {
    "id": "test.hook.pretooluse",
    "name": "Test hook fires on PreToolUse",
    "description": "Synthetic rule used only by agentaudit_test to exercise the Scan pipeline.",
    "category": ["test"],
    "appliesTo": [],
    "target": "hook",
    "match": {
      "condition": "and",
      "rules": [
        {"field": "event", "op": "equals", "value": "PreToolUse"}
      ]
    },
    "message": "hook fires on PreToolUse",
    "references": ["https://example.invalid/test-rule"],
    "examples": [{"event": "PreToolUse", "command": "audit.sh"}],
    "negative_examples": [{"event": "PostToolUse", "command": "audit.sh"}]
  }
]`

func syntheticRulesFS() fstest.MapFS {
	return fstest.MapFS{
		"testrules/hook.json": &fstest.MapFile{Data: []byte(syntheticHookRule)},
	}
}

// syntheticEmptyMessageRule carries an empty message on purpose; ValidateRule
// accepts it.
const syntheticEmptyMessageRule = `[
  {
    "id": "test.hook.emptymessage",
    "name": "Test hook with empty message",
    "description": "Synthetic rule used only by agentaudit_test to exercise the empty-Message skip+warn branch.",
    "category": ["test"],
    "appliesTo": [],
    "target": "hook",
    "match": {
      "condition": "and",
      "rules": [
        {"field": "event", "op": "equals", "value": "PreToolUse"}
      ]
    },
    "message": "",
    "references": [],
    "examples": [{"event": "PreToolUse", "command": "audit.sh"}],
    "negative_examples": [{"event": "PostToolUse", "command": "audit.sh"}]
  }
]`

func emptyMessageRulesFS() fstest.MapFS {
	return fstest.MapFS{
		"testrules/hook.json": &fstest.MapFile{Data: []byte(syntheticEmptyMessageRule)},
	}
}

// failingDiscoverFS forces ReadDir to error for one directory, driving
// discovery.Discover into a genuine fs.FS I/O failure.
type failingDiscoverFS struct {
	m       fstest.MapFS
	failDir string
}

func (f failingDiscoverFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f failingDiscoverFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failDir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("simulated read error")}
	}
	return f.m.ReadDir(name)
}

func (f failingDiscoverFS) ReadFile(name string) ([]byte, error)   { return f.m.ReadFile(name) }
func (f failingDiscoverFS) Stat(name string) (fs.FileInfo, error)  { return f.m.Stat(name) }
func (f failingDiscoverFS) Lstat(name string) (fs.FileInfo, error) { return fs.Lstat(f.m, name) }
func (f failingDiscoverFS) ReadLink(name string) (string, error)   { return fs.ReadLink(f.m, name) }

// multiFailDiscoverFS fails several directories at once: with only one,
// routing every warning and routing merely the first are indistinguishable.
type multiFailDiscoverFS struct {
	m        fstest.MapFS
	failDirs map[string]bool
}

func (f multiFailDiscoverFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f multiFailDiscoverFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.failDirs[name] {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("simulated read error")}
	}
	return f.m.ReadDir(name)
}

func (f multiFailDiscoverFS) ReadFile(name string) ([]byte, error)   { return f.m.ReadFile(name) }
func (f multiFailDiscoverFS) Stat(name string) (fs.FileInfo, error)  { return f.m.Stat(name) }
func (f multiFailDiscoverFS) Lstat(name string) (fs.FileInfo, error) { return fs.Lstat(f.m, name) }
func (f multiFailDiscoverFS) ReadLink(name string) (string, error)   { return fs.ReadLink(f.m, name) }

// Provenance is carried from the entity's own Location rather than rebuilt at
// report time, so a finding names the file the capability was read from.
func TestScanEndToEndFindingWithProvenance(t *testing.T) {
	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() len = %d, want 1: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.RuleID != "test.hook.pretooluse" {
		t.Errorf("RuleID = %q, want %q", f.RuleID, "test.hook.pretooluse")
	}
	if f.Agent != string(agentaudit.AgentClaudeCode) {
		t.Errorf("Agent = %q, want %q", f.Agent, string(agentaudit.AgentClaudeCode))
	}

	wantProv := finding.Provenance{File: ".claude/settings.json", Key: "hooks.PreToolUse[0].hooks[0]"}
	if f.Capability.Provenance != wantProv {
		t.Errorf("Provenance = %+v, want %+v", f.Capability.Provenance, wantProv)
	}
}

// mirrorAdapter proves two adapters over one identical entity each attribute
// a Finding rather than one silently dropping the other's. Its Parse reports
// only the file its own sig declares, so its provenance is honest.
type mirrorAdapter struct{ sig adapter.Signature }

func (mirrorAdapter) Agent() adapter.AgentID { return adapter.AgentID("mirror-agent") }

func (m mirrorAdapter) Signatures() []adapter.Signature { return []adapter.Signature{m.sig} }

func (m mirrorAdapter) Parse(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	p := path.Join(m.sig.Dir, m.sig.File)
	if _, err := fs.ReadFile(fsys, p); err != nil {
		return nil, nil, err
	}
	return []ir.Entity{ir.Hook{
		Event: "PreToolUse", Command: "audit.sh",
		Location: ir.Location{File: p, Key: "hooks.PreToolUse[0].hooks[0]"},
	}}, nil, nil
}

func TestScanWithTwoAdaptersAttributesEachFinding(t *testing.T) {
	t.Run("both agents surface a finding", func(t *testing.T) {
		var warnings []error
		s := agentaudit.New(
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAdapters(claude.Adapter{}, mirrorAdapter{sig: adapter.Signature{Dir: ".claude", File: "settings.json"}}),
			agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
		)

		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}

		findings := report.Findings()
		if len(findings) != 2 {
			t.Fatalf("Findings() len = %d, want 2: %+v", len(findings), findings)
		}

		if findings[0].ID() != findings[1].ID() {
			t.Fatalf("test premise invalid: findings[0].ID() != findings[1].ID(): %q vs %q (the fake must produce an identical ID() to claude's for this test to prove anything)", findings[0].ID(), findings[1].ID())
		}

		gotAgents := map[string]bool{findings[0].Agent: true, findings[1].Agent: true}
		wantAgents := map[string]bool{"claude-code": true, "mirror-agent": true}
		if !reflect.DeepEqual(gotAgents, wantAgents) {
			t.Fatalf("Agents = %v, want %v", gotAgents, wantAgents)
		}

		if got := report.UnreadableSources(); got != 0 {
			t.Fatalf("UnreadableSources() = %d, want 0", got)
		}
		if len(warnings) != 0 {
			t.Fatalf("warnings = %v, want none", warnings)
		}
	})

	t.Run("fake absent from the fixture yields one finding and zero warnings", func(t *testing.T) {
		var warnings []error
		s := agentaudit.New(
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAdapters(claude.Adapter{}, mirrorAdapter{sig: adapter.Signature{Dir: ".mirror", File: "settings.json"}}),
			agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
		)

		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}

		findings := report.Findings()
		if len(findings) != 1 {
			t.Fatalf("Findings() len = %d, want 1: %+v", len(findings), findings)
		}
		if findings[0].Agent != "claude-code" {
			t.Fatalf("Agent = %q, want %q", findings[0].Agent, "claude-code")
		}
		if len(warnings) != 0 {
			t.Fatalf("warnings = %v, want none (the active filter must exclude the fake, not attempt and fail its Parse)", warnings)
		}
	})
}

// Guards against toFinding hardcoding "claude-code".
func TestScanWithSingleNonClaudeAdapterAttributesItsOwnAgent(t *testing.T) {
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithAdapters(mirrorAdapter{sig: adapter.Signature{Dir: ".claude", File: "settings.json"}}),
	)

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() len = %d, want 1: %+v", len(findings), findings)
	}
	if findings[0].Agent != "mirror-agent" {
		t.Fatalf("Agent = %q, want %q", findings[0].Agent, "mirror-agent")
	}
}

func TestScanWithAgentsFilters(t *testing.T) {
	t.Run("named agent runs", func(t *testing.T) {
		s := agentaudit.New(
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAgents(agentaudit.AgentClaudeCode),
		)

		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}
		if !report.HasFindings() {
			t.Fatalf("HasFindings() = false, want true (named agent should run)")
		}
	})

	t.Run("unknown agent excluded", func(t *testing.T) {
		s := agentaudit.New(
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAgents(agentaudit.AgentID("no-such-agent")),
		)

		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}
		if report.HasFindings() {
			t.Fatalf("HasFindings() = true, want false (unknown agent excluded)")
		}
	})

	t.Run("empty means all", func(t *testing.T) {
		s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}
		if !report.HasFindings() {
			t.Fatalf("HasFindings() = false, want true (no WithAgents means all)")
		}
	})
}

// Guards against the WithAdapters seam silently disabling WithAgents.
func TestScanWithAdaptersSeamStillHonorsWithAgents(t *testing.T) {
	adapters := []agentaudit.Option{
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithAdapters(claude.Adapter{}, mirrorAdapter{sig: adapter.Signature{Dir: ".claude", File: "settings.json"}}),
	}

	unfiltered := agentaudit.New(adapters...)
	premise, err := unfiltered.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := len(premise.Findings()); got != 2 {
		t.Fatalf("test premise invalid: unfiltered Findings() len = %d, want 2 (both adapters must produce a finding for WithAgents to prove anything)", got)
	}

	s := agentaudit.New(append(adapters, agentaudit.WithAgents(agentaudit.AgentClaudeCode))...)

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() len = %d, want 1 (WithAgents must still filter the WithAdapters seam set): %+v", len(findings), findings)
	}
	if findings[0].Agent != "claude-code" {
		t.Fatalf("Agent = %q, want %q", findings[0].Agent, "claude-code")
	}
}

func TestScanLoadsEmbeddedDefaultRules(t *testing.T) {
	s := agentaudit.New()

	report, err := s.Scan(fstest.MapFS{})
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil (embedded rules must load)", err)
	}
	if report.HasFindings() {
		t.Fatalf("HasFindings() = true, want false (empty fs.FS has no sources to parse)")
	}
}

// A malformed source is recovered per file, not by discarding the whole
// adapter: the sibling's entities still surface and Scan returns nil.
func TestScanMalformedSourceWarnsAndContinues(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json":       &fstest.MapFile{Data: []byte(`not json`)},
		".claude/settings.local.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Scan() panicked: %v", r)
		}
	}()

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("WarnFunc was never called, want >=1 call for malformed source")
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() len = %d, want 1 (sibling settings.local.json's hook must still fire): %+v", len(findings), findings)
	}
	wantProv := finding.Provenance{File: ".claude/settings.local.json", Key: "hooks.PreToolUse[0].hooks[0]"}
	if findings[0].Capability.Provenance != wantProv {
		t.Errorf("Provenance = %+v, want %+v", findings[0].Capability.Provenance, wantProv)
	}
}

// A readable but malformed source hides nothing, yet what it declared was
// discarded: the report is not the clean picture it would otherwise read as.
func TestScanCountsMalformedSourceAsUnparsedNotUnreadable(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`not json`)},
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("WarnFunc was never called, want >=1 call for the malformed source")
	}
	if got := report.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() = %d, want 0 (malformed but readable source hides nothing)", got)
	}
	if got := report.UnparsedSources(); got != 1 {
		t.Fatalf("UnparsedSources() = %d, want 1 (the file was read, and everything it declared was discarded)", got)
	}
}

// Wrapping a non-object mcpServers in adapter.Unreadable would misname a
// value the user can see and fix. It is still a hole: mcpServers is the whole
// of what .mcp.json declares, and none of it reached the report.
func TestScanNonObjectMCPServersCountsAsUnparsedNotUnreadable(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":[1,2,3]}`)},
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if len(warnings) == 0 {
		t.Fatalf("WarnFunc was never called, want >=1 call for the non-object mcpServers value")
	}
	if got := report.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() = %d, want 0 (the file was read; only one value inside it was unusable)", got)
	}
	if got := report.UnparsedSources(); got != 1 {
		t.Fatalf("UnparsedSources() = %d, want 1 (the declaration the file exists to carry was discarded)", got)
	}
}

// An unread source was never handed to a parser: it raises one count, not both.
func TestScanCountsUnreadableSourceWithoutUnparsed(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(validStubSettings)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := report.UnreadableSources(); got == 0 {
		t.Fatalf("UnreadableSources() = %d, want >0 for the unread directory", got)
	}
	if got := report.UnparsedSources(); got != 0 {
		t.Fatalf("UnparsedSources() = %d, want 0 (an unread source was never handed to a parser)", got)
	}
}

// The two degradations are independent facts; neither folds into the other.
func TestScanCountsUnreadableAndUnparsedIndependently(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(`not json`)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := report.UnreadableSources(); got != 1 {
		t.Fatalf("UnreadableSources() = %d, want 1 (the unread directory)", got)
	}
	if got := report.UnparsedSources(); got != 1 {
		t.Fatalf("UnparsedSources() = %d, want 1 (the malformed settings.json)", got)
	}
}

// parseWarnAdapter reports one fixed parse Warning, so two of them can be
// pointed at the identical fault two real walkers would reach.
type parseWarnAdapter struct {
	id  adapter.AgentID
	sig adapter.Signature
	w   adapter.Warning
}

func (a parseWarnAdapter) Agent() adapter.AgentID { return a.id }

func (a parseWarnAdapter) Signatures() []adapter.Signature { return []adapter.Signature{a.sig} }

func (a parseWarnAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, []adapter.Warning{a.w}, nil
}

// The key that collapses a duplicated unreadable fault collapses an unparsed
// one too.
func TestScanDeduplicatesUnparsedWarningsByRawFileAndError(t *testing.T) {
	shared := adapter.Warning{File: ".claude/settings.json", Err: errors.New("unusable value")}
	sig := adapter.Signature{Dir: ".claude", File: "settings.json"}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithAdapters(
			parseWarnAdapter{id: "first-agent", sig: sig, w: shared},
			parseWarnAdapter{id: "second-agent", sig: sig, w: shared},
		),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %d (%v), want exactly 1 (both adapters observe the identical raw fault)", len(warnings), warnings)
	}
	if got := report.UnparsedSources(); got != 1 {
		t.Fatalf("UnparsedSources() = %d, want 1", got)
	}
	if got := report.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() = %d, want 0", got)
	}
}

func TestScanSkipsEmptyMessageHitAndWarns(t *testing.T) {
	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(emptyMessageRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if report.HasFindings() {
		t.Fatalf("HasFindings() = true, want false (empty-Message Hit must be skipped)")
	}
	if len(warnings) == 0 {
		t.Fatalf("WarnFunc was never called, want >=1 call for the skipped empty-Message Hit")
	}
}

// Exercises the real embedded rules/claude ruleset, not a synthetic override.
func TestScanMapFSFixtureProducesThreeFindingsWithProvenance(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{
			"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.sh"}]}]},
			"statusLine": {"type": "command", "command": "statusline.sh"},
			"apiKeyHelper": "get-key.sh"
		}`)},
	}

	s := agentaudit.New()
	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	findings := report.Findings()
	if len(findings) != 3 {
		t.Fatalf("Findings() len = %d, want 3: %+v", len(findings), findings)
	}

	wantByRule := map[string]struct {
		categories []finding.Category
		key        string
	}{
		"claude.hook.command":              {[]finding.Category{"code-execution"}, "hooks.PreToolUse[0].hooks[0]"},
		"claude.statusline.command":        {[]finding.Category{"code-execution"}, "statusLine.command"},
		"claude.credential.api-key-helper": {[]finding.Category{"code-execution"}, "apiKeyHelper"},
	}

	seen := map[string]bool{}
	for _, f := range findings {
		want, ok := wantByRule[f.RuleID]
		if !ok {
			t.Fatalf("unexpected RuleID %q", f.RuleID)
		}
		seen[f.RuleID] = true

		if f.Capability.Provenance.File != ".claude/settings.json" {
			t.Errorf("%s: Provenance.File = %q, want %q", f.RuleID, f.Capability.Provenance.File, ".claude/settings.json")
		}
		if f.Capability.Provenance.Key != want.key {
			t.Errorf("%s: Provenance.Key = %q, want %q", f.RuleID, f.Capability.Provenance.Key, want.key)
		}
		if len(f.Categories) != len(want.categories) {
			t.Fatalf("%s: Categories = %v, want %v", f.RuleID, f.Categories, want.categories)
		}
		for i, c := range want.categories {
			if f.Categories[i] != c {
				t.Errorf("%s: Categories[%d] = %q, want %q", f.RuleID, i, f.Categories[i], c)
			}
		}
	}
	for id := range wantByRule {
		if !seen[id] {
			t.Errorf("expected rule %q did not fire", id)
		}
	}
}

type statFailFS struct {
	m fstest.MapFS
}

func (f statFailFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f statFailFS) Stat(name string) (fs.FileInfo, error) {
	if name == "." {
		return nil, errors.New("simulated stat failure")
	}
	return f.m.Stat(name)
}

func (f statFailFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }
func (f statFailFS) ReadFile(name string) ([]byte, error)       { return f.m.ReadFile(name) }
func (f statFailFS) Lstat(name string) (fs.FileInfo, error)     { return fs.Lstat(f.m, name) }
func (f statFailFS) ReadLink(name string) (string, error)       { return fs.ReadLink(f.m, name) }

// A walk failure strictly below the scan root degrades to a WarnFunc call,
// never a silently discarded Report.
func TestScanWarnsAndContinuesOnSubRootDiscoveryFailure(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(validStubSettings)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil (a below-root discovery failure must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("Scan() WarnFunc was never called, want >=1 call for the unreadable unrelated-dir")
	}
	if !report.HasFindings() {
		t.Fatal("Scan() report has no findings, want the .claude/settings.json hook to still fire despite the unrelated unreadable directory")
	}
}

// A failure to stat the scan root stays fatal through the facade: never "no
// capabilities found" at a clean exit for a repo that was never actually
// read. WarnFunc stays out of it, making its doc claim about fatal errors
// testable rather than aspirational.
func TestScanRootDiscoveryFailureStaysFatal(t *testing.T) {
	fsys := statFailFS{m: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)}}}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(fsys)
	if err == nil {
		t.Fatal("Scan() error = nil, want non-nil (a root discovery failure must stay fatal)")
	}
	if report.HasFindings() {
		t.Fatalf("Scan() report = %+v, want zero Report on a root discovery error", report)
	}
	for _, w := range warnings {
		if w.Error() == err.Error() {
			t.Fatalf("WarnFunc received the fatal error %q, want it routed only as Scan's return value", w)
		}
	}
}

// A consumer that sets no warn callback must still detect a degraded scan.
func TestScanRecordsUnreadableSourcesWithoutWarnFunc(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(validStubSettings)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := report.UnreadableSources(); got == 0 {
		t.Fatalf("UnreadableSources() = %d, want >0 (no WithWarnFunc was set, but the count must still reflect the unread directory)", got)
	}
}

// Two walkers failing on one directory with a byte-identical error is one
// fault: one routed warning, and a count that agrees with it.
func TestScanDeduplicatesWarningsByRawFileAndError(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(validStubSettings)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var named []error
	for _, w := range warnings {
		if strings.Contains(w.Error(), "unrelated-dir") {
			named = append(named, w)
		}
	}
	if len(named) != 1 {
		t.Fatalf("warnings naming %q = %d (%v), want exactly 1 (discovery and pluginRoots both observe the identical raw fault and must collapse)", "unrelated-dir", len(named), named)
	}
	if got := report.UnreadableSources(); got != len(named) {
		t.Fatalf("UnreadableSources() = %d, want it to equal the routed warning count %d", got, len(named))
	}
	if got := report.UnparsedSources(); got != 0 {
		t.Fatalf("UnparsedSources() = %d, want 0 (one fault lands in one count, never both)", got)
	}
}

func TestScanCleanReportsZeroUnreadableSources(t *testing.T) {
	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))

	report, err := s.Scan(hookScanFS())
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	if got := report.UnreadableSources(); got != 0 {
		t.Fatalf("UnreadableSources() = %d, want 0 for a scan with no read failures", got)
	}
}

// A plain non-empty warnings check cannot show the discWarnings routing loop
// ran: the Claude adapter's pluginRoots reaches the same failing directory on
// its own. Hence the filter on the "agentaudit: discover: " prefix.
func TestScanRoutesDiscoveryWarningsThroughWarnFunc(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json":  &fstest.MapFile{Data: []byte(validStubSettings)},
			"unrelated-dir/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "unrelated-dir",
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	if _, err := s.Scan(fsys); err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	var discoveryWarnings []error
	for _, w := range warnings {
		if strings.Contains(w.Error(), "agentaudit: discover: ") {
			discoveryWarnings = append(discoveryWarnings, w)
		}
	}
	if len(discoveryWarnings) == 0 {
		t.Fatalf("no WarnFunc call carried the %q prefix, want >=1 (agentaudit.go's discWarnings routing loop must run); all warnings: %v", "agentaudit: discover: ", warnings)
	}
	if !strings.Contains(discoveryWarnings[0].Error(), "unrelated-dir") {
		t.Errorf("discovery warning = %q, want it to name the offending path %q", discoveryWarnings[0].Error(), "unrelated-dir")
	}
}

// Grouped pretty output follows registration order, not name order. Since
// "claude-code" < "mirror-agent", only the reversed-registration subtest can
// tell first-appearance ordering from a sort-by-name implementation.
func TestScanWithTwoAdaptersRendersOneHeadingPerProducingAgent(t *testing.T) {
	fake := mirrorAdapter{sig: adapter.Signature{Dir: ".claude", File: "settings.json"}}

	render := func(t *testing.T, opts ...agentaudit.Option) string {
		t.Helper()
		s := agentaudit.New(opts...)
		report, err := s.Scan(hookScanFS())
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}
		if got := len(report.Findings()); got != 2 {
			t.Fatalf("test premise invalid: Findings() len = %d, want 2 (both adapters must produce a finding for this test to prove anything)", got)
		}

		var buf strings.Builder
		if err := pretty.Write(&buf, report, pretty.Meta{Path: "."}); err != nil {
			t.Fatalf("pretty.Write() error = %v, want nil", err)
		}
		return buf.String()
	}

	t.Run("registration order claude then mirror", func(t *testing.T) {
		out := render(t,
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAdapters(claude.Adapter{}, fake),
		)

		claudeIdx := strings.Index(out, "(claude-code)")
		mirrorIdx := strings.Index(out, "(mirror-agent)")
		if claudeIdx == -1 || mirrorIdx == -1 {
			t.Fatalf("out = %q, want both headings present", out)
		}
		if claudeIdx >= mirrorIdx {
			t.Fatalf("out = %q, want \"(claude-code)\" before \"(mirror-agent)\" (registration order)", out)
		}
		if strings.Count(out, "(claude-code)") != 1 || strings.Count(out, "(mirror-agent)") != 1 {
			t.Fatalf("out = %q, want each heading exactly once", out)
		}
		if !strings.Contains(out, "2 capabilities · 1 file · 1 category") {
			t.Fatalf("out = %q, want footer \"2 capabilities · 1 file · 1 category\"", out)
		}
	})

	t.Run("registration order mirror then claude", func(t *testing.T) {
		out := render(t,
			agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
			agentaudit.WithAdapters(fake, claude.Adapter{}),
		)

		claudeIdx := strings.Index(out, "(claude-code)")
		mirrorIdx := strings.Index(out, "(mirror-agent)")
		if claudeIdx == -1 || mirrorIdx == -1 {
			t.Fatalf("out = %q, want both headings present", out)
		}
		if mirrorIdx >= claudeIdx {
			t.Fatalf("out = %q, want \"(mirror-agent)\" before \"(claude-code)\" (registration order reversed)", out)
		}
	})
}

// A truncated routing loop would drop faults after the earliest directory.
func TestScanRoutesEveryDiscoveryWarning(t *testing.T) {
	fsys := multiFailDiscoverFS{
		m: fstest.MapFS{
			".claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
			"broken-one/file.txt":   &fstest.MapFile{Data: []byte("x")},
			"broken-two/file.txt":   &fstest.MapFile{Data: []byte("x")},
		},
		failDirs: map[string]bool{"broken-one": true, "broken-two": true},
	}

	var warnings []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err) }),
	)

	if _, err := s.Scan(fsys); err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	for _, want := range []string{"broken-one", "broken-two"} {
		found := false
		for _, w := range warnings {
			if strings.Contains(w.Error(), "agentaudit: discover: ") && strings.Contains(w.Error(), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no discovery warning named %q; Scan must route every accumulated warning, not just the first. all warnings: %v", want, warnings)
		}
	}
}
