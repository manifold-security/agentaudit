package discovery

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestProjects_TwoSiblingProjectsBothFound(t *testing.T) {
	fsys := fstest.MapFS{
		"a/.claude/settings.json": &fstest.MapFile{Data: []byte("{}")},
		"b/.mcp.json":             &fstest.MapFile{Data: []byte("{}")},
	}

	got, warnings, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Projects() warnings = %v, want none", warnings)
	}
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_NestedProjectYieldsBothUnpruned(t *testing.T) {
	fsys := fstest.MapFS{
		"outer/.mcp.json":       &fstest.MapFile{Data: []byte("{}")},
		"outer/inner/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
		"outer/inner/README.md": &fstest.MapFile{Data: []byte("x")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"outer", "outer/inner"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_ContainerCarryingOwnMarkerIncludesDot(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_ProjectThreeLevelsBeneathRootIsFound(t *testing.T) {
	fsys := fstest.MapFS{
		"a/b/c/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"a/b/c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

type pluginManifestAdapter struct{}

func (pluginManifestAdapter) Agent() adapter.AgentID { return adapter.AgentClaudeCode }
func (pluginManifestAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{{Dir: ".claude-plugin", File: "plugin.json", AnyDepth: true}}
}
func (pluginManifestAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

func TestProjects_ManifestOnlyDirectoryIsAProject(t *testing.T) {
	fsys := fstest.MapFS{
		"plugin-only/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{pluginManifestAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"plugin-only"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_ManifestAtContainerRootIsAProject(t *testing.T) {
	fsys := fstest.MapFS{
		".claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{pluginManifestAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_MarkerSubtreeIsNotDescended(t *testing.T) {
	fsys := fstest.MapFS{
		"proj/.claude/settings.json":         &fstest.MapFile{Data: []byte("{}")},
		"proj/.claude/skills/tool/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"proj"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v (the nested .mcp.json under .claude must not surface)", got, want)
	}
}

func TestProjects_ClaudeAsAFileIsStillAMarker(t *testing.T) {
	fsys := fstest.MapFS{
		"a/.claude": &fstest.MapFile{Data: []byte("not a directory")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_McpJsonAsADirectoryIsStillAMarker(t *testing.T) {
	fsys := fstest.MapFS{
		"a/.mcp.json/nested.txt": &fstest.MapFile{Data: []byte("x")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_EmptyContainerYieldsNone(t *testing.T) {
	fsys := fstest.MapFS{
		"README.md": &fstest.MapFile{Data: []byte("x")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("Projects() = %v, want empty", got)
	}
}

// Walk order visits "a/z" before the sibling "a-b" (it descends "a" before
// ever reaching "a-b"), but '-' (0x2D) sorts before '/' (0x2F), so the
// lexical order of the returned roots is the reverse of walk order.
func TestProjects_RootsAreLexicallySortedNotWalkOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"a/z/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
		"a-b/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"a-b", "a/z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v (lexically sorted)", got, want)
	}
}

// otherRootedAdapter's marker is honoured only if the project marker set is
// derived from Signatures() rather than a hand-written list.
type otherRootedAdapter struct{}

func (otherRootedAdapter) Agent() adapter.AgentID { return adapter.AgentID("other-agent") }
func (otherRootedAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{{Dir: ".other-agent", File: "config.json"}}
}
func (otherRootedAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

func TestProjects_MarkerSetIsDerivedFromActiveAdaptersSignatures(t *testing.T) {
	fsys := fstest.MapFS{
		"c/.other-agent/config.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{otherRootedAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v (marker must be derived from the adapter's own Signatures())", got, want)
	}
}

// A relative symlink to an in-tree directory is descended: a marker nested
// inside the resolved target is found as a project rooted under the symlink's
// own path.
func TestProjects_SymlinkedDirectoryRevealsNestedMarker(t *testing.T) {
	fsys := fstest.MapFS{
		"real-target/proj/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
		"linked-dir":                 &fstest.MapFile{Data: []byte("real-target"), Mode: fs.ModeSymlink},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}

	found := false
	for _, root := range got {
		if root == "linked-dir/proj" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Projects() = %v, want linked-dir/proj found through the resolved symlink", got)
	}
}

// The skip-subtree invariant holds when the marker itself is reached through
// a symlink: a project root's own ".claude" symlinked to an in-tree directory
// holding a nested .mcp.json must not promote that nested marker into a
// project of its own.
func TestProjects_SymlinkedMarkerSubtreeIsNotDescended(t *testing.T) {
	fsys := fstest.MapFS{
		"real-claude/settings.json":         &fstest.MapFile{Data: []byte("{}")},
		"real-claude/skills/tool/.mcp.json": &fstest.MapFile{Data: []byte("{}")},
		"proj/.claude":                      &fstest.MapFile{Data: []byte("../real-claude"), Mode: fs.ModeSymlink},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	// real-claude/skills/tool is independently a real project root reached
	// without ever going through the symlink, so it legitimately appears. What
	// must not appear is a second root promoted through proj's symlinked
	// .claude.
	for _, root := range got {
		if root == "proj/.claude/skills/tool" {
			t.Fatalf("Projects() = %v, want no promoted root reached through the symlinked .claude", got)
		}
	}
	want := []string{"proj", "real-claude/skills/tool"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

type projectsFailingFS struct {
	m       fstest.MapFS
	failDir string
}

func (f projectsFailingFS) Open(name string) (fs.File, error)      { return f.m.Open(name) }
func (f projectsFailingFS) Stat(name string) (fs.FileInfo, error)  { return f.m.Stat(name) }
func (f projectsFailingFS) Lstat(name string) (fs.FileInfo, error) { return f.m.Lstat(name) }
func (f projectsFailingFS) ReadLink(name string) (string, error)   { return f.m.ReadLink(name) }

func (f projectsFailingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failDir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("simulated read error")}
	}
	return f.m.ReadDir(name)
}

// Projects' below-root degradation: a warning instead of an error, and the
// sibling project past the failing directory still found.
func TestProjects_BelowRootFailureWarnsAndContinues(t *testing.T) {
	fsys := projectsFailingFS{
		m: fstest.MapFS{
			"broken/file.txt": &fstest.MapFile{Data: []byte("x")},
			"b/.mcp.json":     &fstest.MapFile{Data: []byte("{}")},
		},
		failDir: "broken",
	}

	got, warnings, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil (a below-root failure must warn, never abort)", err)
	}
	if len(warnings) == 0 {
		t.Fatal("Projects() warnings = none, want a warning for the unreadable broken/ directory")
	}
	want := []string{"b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

func TestProjects_RootFailureIsFatalWithNoPartialResult(t *testing.T) {
	fsys := statFailWalkFS{m: fstest.MapFS{"b/.mcp.json": &fstest.MapFile{Data: []byte("{}")}}, failPath: "."}

	got, _, err := Projects(fsys, []adapter.Adapter{stubAdapter{}})
	if err == nil {
		t.Fatal("Projects() error = nil, want a fatal error for an unreadable root")
	}
	if len(got) != 0 {
		t.Fatalf("Projects() = %v, want no partial result on a fatal root failure", got)
	}
}

func TestProjects_ClaudeJSONIsNotAProjectMarker(t *testing.T) {
	fsys := fstest.MapFS{
		"sub/.claude.json":     &fstest.MapFile{Data: []byte("{}")},
		".claude/.claude.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{claude.New()})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v: the .claude directory is the marker, the .claude.json file inside it is not", got, want)
	}
}

// unanchoredManifestAdapter is what forces projectMarkers to tell an anchored
// manifest declaration apart from an unanchored one.
type unanchoredManifestAdapter struct{}

func (unanchoredManifestAdapter) Agent() adapter.AgentID { return adapter.AgentCursor }
func (unanchoredManifestAdapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{File: "plugin.json"},
		{Dir: ".cursor-plugin", File: "plugin.json", AnyDepth: true},
	}
}
func (unanchoredManifestAdapter) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}

// An unanchored manifest name marks no project of its own. The adapter here
// declares the manifest both ways, so one tree reaches both arms of the skip.
func TestProjects_UnanchoredManifestNameMarksNoProject(t *testing.T) {
	fsys := fstest.MapFS{
		"tools/myplug/.claude-plugin/plugin.json": &fstest.MapFile{Data: []byte("{}")},
		"tools/cur/.cursor-plugin/plugin.json":    &fstest.MapFile{Data: []byte("{}")},
		"vendor/grafana-panel/plugin.json":        &fstest.MapFile{Data: []byte("{}")},
		"node_modules/panel/plugin.json":          &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{pluginManifestAdapter{}, unanchoredManifestAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{"tools/cur", "tools/myplug"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}

// A signature whose joined path carries no directory still marks its own
// parent, at the container root and nested alike, while an unanchored
// manifest name declared beside it marks nothing. Both derive the same
// bare-filename shape, so that shape is not what the skip reads.
func TestProjects_BareFilenameMarkerSurvivesBesideTheManifestName(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json":                &fstest.MapFile{Data: []byte("{}")},
		"svc/.mcp.json":            &fstest.MapFile{Data: []byte("{}")},
		"vendor/panel/plugin.json": &fstest.MapFile{Data: []byte("{}")},
	}

	got, _, err := Projects(fsys, []adapter.Adapter{claude.New(), unanchoredManifestAdapter{}})
	if err != nil {
		t.Fatalf("Projects() error = %v, want nil", err)
	}
	want := []string{".", "svc"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Projects() = %v, want %v", got, want)
	}
}
