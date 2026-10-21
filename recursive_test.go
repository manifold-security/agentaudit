package agentaudit_test

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
)

// enoentDirFS reproduces a directory that vanishes mid-walk.
type enoentDirFS struct {
	m       fstest.MapFS
	failDir string
}

func (f enoentDirFS) Open(name string) (fs.File, error) { return f.m.Open(name) }

func (f enoentDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failDir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	return f.m.ReadDir(name)
}

func (f enoentDirFS) ReadFile(name string) ([]byte, error)   { return f.m.ReadFile(name) }
func (f enoentDirFS) Stat(name string) (fs.FileInfo, error)  { return f.m.Stat(name) }
func (f enoentDirFS) Lstat(name string) (fs.FileInfo, error) { return fs.Lstat(f.m, name) }
func (f enoentDirFS) ReadLink(name string) (string, error)   { return fs.ReadLink(f.m, name) }

func projectReportPaths(reports []agentaudit.ProjectReport) []string {
	paths := make([]string, len(reports))
	for i, r := range reports {
		paths[i] = r.Path
	}
	return paths
}

func TestScanRecursive_SiblingProjectsYieldOneEntryEachNoContainer(t *testing.T) {
	fsys := fstest.MapFS{
		"proj-a/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
		"proj-b/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	want := []string{"proj-a", "proj-b"}
	if paths := projectReportPaths(got); !reflect.DeepEqual(paths, want) {
		t.Fatalf("ScanRecursive() paths = %v, want %v", paths, want)
	}
}

func TestScanRecursive_EmptyContainerYieldsSingleContainerEntry(t *testing.T) {
	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fstest.MapFS{})
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("ScanRecursive() = %v, want exactly one entry", got)
	}
	if got[0].Path != "." {
		t.Fatalf("ScanRecursive()[0].Path = %q, want %q", got[0].Path, ".")
	}
	if got[0].Report.HasFindings() {
		t.Fatalf("ScanRecursive()[0].Report = %+v, want no findings for an empty container", got[0].Report)
	}
}

func TestScanRecursive_ContainerCarryingItsOwnMarkerYieldsContainerEntryToo(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json":        &fstest.MapFile{Data: []byte(validStubSettings)},
		"nested/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	paths := projectReportPaths(got)
	want := []string{".", "nested"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("ScanRecursive() paths = %v, want %v", paths, want)
	}
}

func TestScanRecursive_UnreadableDirectoryDegradesContainerNotTheReadableProject(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			"good/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
			"broken/file.txt":            &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "broken",
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}

	var container, good *agentaudit.ProjectReport
	for i := range got {
		switch got[i].Path {
		case ".":
			container = &got[i]
		case "good":
			good = &got[i]
		}
	}
	if container == nil {
		t.Fatalf("ScanRecursive() = %v, want a %q entry", got, ".")
	}
	if good == nil {
		t.Fatalf("ScanRecursive() = %v, want a %q entry", got, "good")
	}

	// The one fault beneath "broken" is reachable by both the enumeration
	// walk and the container's own rescan, so pin the count, not its sign.
	if got := container.Report.UnreadableSources(); got != 1 {
		t.Fatalf("container UnreadableSources() = %d, want exactly 1 (one fault reached by both the enumeration and the container's own scan, counted once)", got)
	}
	if container.Report.HasFindings() {
		t.Fatalf("container Report = %+v, want no findings", container.Report)
	}
	if !good.Report.HasFindings() {
		t.Fatalf("good Report = %+v, want good's own hook finding still reported", good.Report)
	}
	if got := good.Report.UnreadableSources(); got != 0 {
		t.Fatalf("good UnreadableSources() = %d, want 0 (the fault lies outside good's own subtree)", got)
	}
}

func TestScanRecursive_WarningsThatHideNothingConjureNoContainerEntry(t *testing.T) {
	tests := []struct {
		name string
		fsys fs.FS
	}{
		{
			name: "dangling in-tree symlink",
			fsys: fstest.MapFS{
				"good/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
				"ghost":                      &fstest.MapFile{Data: []byte("missingdir"), Mode: fs.ModeSymlink},
			},
		},
		{
			name: "ReadDir failure wrapping fs.ErrNotExist",
			fsys: enoentDirFS{
				m: fstest.MapFS{
					"good/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
					"vanished/file.txt":          &fstest.MapFile{Data: []byte("x")},
				},
				failDir: "vanished",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
			got, err := s.ScanRecursive(tt.fsys)
			if err != nil {
				t.Fatalf("ScanRecursive() error = %v, want nil", err)
			}
			paths := projectReportPaths(got)
			want := []string{"good"}
			if !reflect.DeepEqual(paths, want) {
				t.Fatalf("ScanRecursive() paths = %v, want %v", paths, want)
			}
		})
	}
}

func TestScanRecursive_FindingProvenanceIsProjectRelative(t *testing.T) {
	fsys := fstest.MapFS{
		"proj-a/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("ScanRecursive() = %v, want exactly one entry", got)
	}
	findings := got[0].Report.Findings()
	if len(findings) != 1 {
		t.Fatalf("Findings() = %v, want exactly one", findings)
	}
	if want, got := ".claude/settings.json", findings[0].Capability.Provenance.File; got != want {
		t.Fatalf("Provenance.File = %q, want %q (project-relative, not prefixed by %q)", got, want, "proj-a")
	}
}

func TestScanRecursive_WithAgentsExcludingTheOwningAdapterYieldsContainerOnly(t *testing.T) {
	fsys := fstest.MapFS{
		"proj-a/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
	}

	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithAgents(agentaudit.AgentID("no-such-agent")),
	)
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	paths := projectReportPaths(got)
	want := []string{"."}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("ScanRecursive() paths = %v, want %v", paths, want)
	}
}

func TestScanRecursive_OneFaultRoutesExactlyOneEnumerateWarning(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			"broken/file.txt": &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "broken",
	}

	var routed []error
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { routed = append(routed, err) }),
	)
	if _, err := s.ScanRecursive(fsys); err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}

	var named []error
	for _, w := range routed {
		if strings.Contains(w.Error(), "broken") {
			named = append(named, w)
		}
	}
	if len(named) != 1 {
		t.Fatalf("warnings naming %q = %d (%v), want exactly 1 (enumeration and the container's own rescan share one sink and must collapse)", "broken", len(named), named)
	}
	if !strings.Contains(named[0].Error(), "agentaudit: enumerate: ") {
		t.Fatalf("the single routed warning = %q, want it prefixed %q (enumeration observes the fault before the container's own rescan)", named[0].Error(), "agentaudit: enumerate: ")
	}
}

func TestScanRecursive_UnreadableRootReturnsNilSliceAndPrefixedError(t *testing.T) {
	fsys := statFailFS{m: fstest.MapFS{".claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)}}}

	s := agentaudit.New(agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"))
	got, err := s.ScanRecursive(fsys)
	if err == nil {
		t.Fatal("ScanRecursive() error = nil, want non-nil for an unreadable root")
	}
	if !strings.Contains(err.Error(), "agentaudit: enumerate: ") {
		t.Fatalf("ScanRecursive() error = %q, want it prefixed %q", err.Error(), "agentaudit: enumerate: ")
	}
	if got != nil {
		t.Fatalf("ScanRecursive() = %v, want a nil slice, never an empty non-nil one", got)
	}
}

func TestScanRecursive_LoadsEmbeddedDefaultRulesAgainstAnEnumeratedProject(t *testing.T) {
	fsys := fstest.MapFS{
		"proj-a/.mcp.json": &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"npx","args":["mcp-fs"]}}}`)},
	}

	s := agentaudit.New()
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil (embedded rules must load)", err)
	}
	if len(got) != 1 {
		t.Fatalf("ScanRecursive() = %v, want exactly one entry", got)
	}
	if !got[0].Report.HasFindings() {
		t.Fatalf("ScanRecursive()[0].Report = %+v, want the shipped ruleset to flag proj-a's mcp stdio server", got[0].Report)
	}
}

// blockingOpenFS stands in for a symlink whose target is a FIFO.
type blockingOpenFS struct {
	m fstest.MapFS
}

const blockingOpenSentinel = "open would block forever"

func (f blockingOpenFS) Open(name string) (fs.File, error) {
	if file := f.m[name]; file != nil && file.Mode&(fs.ModeNamedPipe|fs.ModeSymlink) != 0 {
		return nil, &fs.PathError{Op: "open", Path: name, Err: errors.New(blockingOpenSentinel)}
	}
	return f.m.Open(name)
}

func (f blockingOpenFS) Stat(name string) (fs.FileInfo, error)      { return f.m.Stat(name) }
func (f blockingOpenFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.m.ReadDir(name) }
func (f blockingOpenFS) ReadFile(name string) ([]byte, error)       { return f.m.ReadFile(name) }
func (f blockingOpenFS) Lstat(name string) (fs.FileInfo, error)     { return fs.Lstat(f.m, name) }
func (f blockingOpenFS) ReadLink(name string) (string, error)       { return fs.ReadLink(f.m, name) }

// A nested project is reached through subtree, not fs.Sub, so fs.Stat still
// resolves a symlink instead of falling back to an Open that would block.
func TestScanRecursive_NestedProjectResolvesSymlinksByStatNotOpen(t *testing.T) {
	fsys := blockingOpenFS{
		m: fstest.MapFS{
			".claude/settings.json":        &fstest.MapFile{Data: []byte(validStubSettings)},
			"nested/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
			"nested/pipe":                  &fstest.MapFile{Mode: fs.ModeNamedPipe},
			"nested/pipelink":              &fstest.MapFile{Data: []byte("pipe"), Mode: fs.ModeSymlink},
		},
	}

	var warnings []string
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err.Error()) }),
	)
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}

	var nested *agentaudit.ProjectReport
	for i := range got {
		if got[i].Path == "nested" {
			nested = &got[i]
		}
	}
	if nested == nil {
		t.Fatalf("ScanRecursive() paths = %v, want an entry for %q", projectReportPaths(got), "nested")
	}

	// Execution proof: the assertions below cannot pass on an empty report.
	if !nested.Report.HasFindings() {
		t.Fatalf("nested Report = %+v, want the stub adapter's finding from its own settings.json", nested.Report)
	}
	if got := nested.Report.UnreadableSources(); got != 0 {
		t.Fatalf("nested UnreadableSources() = %d, want 0 (a symlink resolved by Stat is readable; falling back to Open counts it unreadable)", got)
	}
	for _, w := range warnings {
		if strings.Contains(w, blockingOpenSentinel) {
			t.Fatalf("warning %q opened the symlink, want it resolved with Stat; all warnings: %v", w, warnings)
		}
	}
}

// A warning spelled container-relative rather than project-relative would
// break provenance for anyone reading a nested project's own warnings.
func TestScanRecursive_NestedProjectWarningPathsStayProjectRelative(t *testing.T) {
	fsys := failingDiscoverFS{
		m: fstest.MapFS{
			"nested/.claude/settings.json": &fstest.MapFile{Data: []byte(validStubSettings)},
			"nested/blocked/file.txt":      &fstest.MapFile{Data: []byte("x")},
		},
		failDir: "nested/blocked",
	}

	var warnings []string
	s := agentaudit.New(
		agentaudit.WithRulesFS(syntheticRulesFS(), "testrules"),
		agentaudit.WithWarnFunc(func(err error) { warnings = append(warnings, err.Error()) }),
	)
	got, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}

	var nested *agentaudit.ProjectReport
	for i := range got {
		if got[i].Path == "nested" {
			nested = &got[i]
		}
	}
	if nested == nil {
		t.Fatalf("ScanRecursive() paths = %v, want an entry for %q", projectReportPaths(got), "nested")
	}
	if got := nested.Report.UnreadableSources(); got != 1 {
		t.Fatalf("nested UnreadableSources() = %d, want 1 (the fault lies inside nested's own subtree)", got)
	}

	// Execution proof: the spelling assertion cannot pass on an empty list.
	var nestedWarning string
	for _, w := range warnings {
		if strings.Contains(w, "blocked") {
			nestedWarning = w
		}
	}
	if nestedWarning == "" {
		t.Fatalf("warnings = %v, want one naming the blocked directory", warnings)
	}
	if strings.Contains(nestedWarning, "nested/blocked") {
		t.Fatalf("warning = %q, want every path project-relative (%q), not container-relative (%q)", nestedWarning, "blocked", "nested/blocked")
	}
}
