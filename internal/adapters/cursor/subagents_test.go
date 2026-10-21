package cursor

import (
	"errors"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

const probeAgentFile = projectAgentsDir + "/probe.md"

func subagentNamed(name, mode, file string) ir.Entity {
	return ir.Subagent{
		Name:           name,
		PermissionMode: mode,
		Location:       ir.Location{File: file, Key: "name"},
	}
}

// A YAML boolean reader answers some of these rows the other way, and the
// costly direction is the one that shows a subagent Cursor runs
// write-enabled as restricted.
func TestAProjectSubagentCarriesTheWritePostureCursorWouldGiveIt(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"readonly omitted", "---\nname: deployer\ndescription: ships releases\n---\n\ndelegates work.\n", subagentWriteEnabled},
		{"readonly false", "---\nname: deployer\nreadonly: false\n---\n\ndelegates work.\n", subagentWriteEnabled},
		{"readonly true", "---\nname: deployer\nreadonly: true\n---\n\ndelegates work.\n", subagentReadonly},
		{"readonly true with a trailing comment", "---\nname: deployer\nreadonly: true # keep it honest\n---\n\ndelegates work.\n", subagentWriteEnabled},
		{"readonly yes", "---\nname: deployer\nreadonly: yes\n---\n\ndelegates work.\n", subagentWriteEnabled},
		{"readonly is not a boolean", "---\nname: deployer\nreadonly: sometimes\n---\n\ndelegates work.\n", subagentWriteEnabled},
		{"readonly key is capitalised", "---\nname: deployer\nReadonly: true\n---\n\ndelegates work.\n", subagentReadonly},
		{"readonly value is upper case", "---\nname: deployer\nreadonly: TRUE\n---\n\ndelegates work.\n", subagentReadonly},
		{"readonly value is padded", "---\nname: deployer\nreadonly:    true   \n---\n\ndelegates work.\n", subagentReadonly},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{probeAgentFile: {Data: []byte(tt.body)}}

			got, warnings := projectSubagentEntities(fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			want := []ir.Entity{subagentNamed("deployer", tt.want, probeAgentFile)}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
			}
		})
	}
}

// Cursor falls back to the file name when the frontmatter declares none, so
// a file with no name key is a live subagent rather than a broken one, and
// dropping it hides a capability the editor delegates to.
func TestAProjectSubagentWithoutANameKeyIsNamedAfterItsFile(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
		want string
	}{
		{"no name key", "deployer.md", "---\ndescription: ships releases\n---\n\ndelegates work.\n", "deployer"},
		{"empty name", "deployer.md", "---\nname: \"\"\n---\n\ndelegates work.\n", "deployer"},
		{"underscores become dashes", "ship_it_now.mdc", "---\ndescription: x\n---\n\ndelegates work.\n", "ship-it-now"},
		{"spaces become dashes", "ship it.markdown", "---\ndescription: x\n---\n\ndelegates work.\n", "ship-it"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := projectAgentsDir + "/" + tt.file
			fsys := fstest.MapFS{file: {Data: []byte(tt.body)}}

			got, warnings := projectSubagentEntities(fsys)
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
			want := []ir.Entity{subagentNamed(tt.want, subagentWriteEnabled, file)}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
			}
		})
	}
}

// A file the scanner could put no name to is a subagent it did not report,
// and something has to say so.
func TestAProjectSubagentFileNamingNothingDegradesToAWarning(t *testing.T) {
	tests := []struct {
		name string
		file string
		body string
	}{
		{"no frontmatter fence", "probe.md", "Prose about the team's agents.\n"},
		{"unterminated fence", "probe.md", "---\nname: deployer\n"},
		{"the file name is nothing but an extension", ".md", "---\ndescription: x\n---\n\ndelegates work.\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := projectAgentsDir + "/" + tt.file
			fsys := fstest.MapFS{file: {Data: []byte(tt.body)}}

			got, warnings := projectSubagentEntities(fsys)
			if len(got) != 0 {
				t.Fatalf("projectSubagentEntities() = %+v, want none", got)
			}
			if len(warnings) != 1 || warnings[0].File != file {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, file)
			}
		})
	}
}

// Cursor's agents scan is a directory walk, not a listing, so a subagent
// filed in a subdirectory is one it loads. Reading only the root would leave
// that file discovered by the signature and read by nothing.
func TestSubagentsNestedBelowTheAgentsRootAreReported(t *testing.T) {
	const nested = projectAgentsDir + "/team/release/deployer.md"
	const top = projectAgentsDir + "/auditor.md"
	fsys := fstest.MapFS{
		nested: {Data: []byte("---\nname: deployer\n---\n\ndelegates work.\n")},
		top:    {Data: []byte("---\nname: auditor\nreadonly: true\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{
		subagentNamed("auditor", subagentReadonly, top),
		subagentNamed("deployer", subagentWriteEnabled, nested),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
	}
}

// A markdown file inside a directory Cursor's walk skips is not a subagent,
// and the file beside that directory still is.
func TestADirectoryCursorsScanSkipsIsPassedOverInSilence(t *testing.T) {
	for name := range unwalkedAgentDirs {
		t.Run(name, func(t *testing.T) {
			skipped := projectAgentsDir + "/" + name
			const survivor = projectAgentsDir + "/auditor.md"
			fsys := fstest.MapFS{
				skipped + "/planted.md": {Data: []byte("---\nname: planted\n---\n\ndelegates work.\n")},
				survivor:                {Data: []byte("---\nname: auditor\n---\n\ndelegates work.\n")},
			}

			got, warnings := projectSubagentEntities(fsys)
			want := []ir.Entity{subagentNamed("auditor", subagentWriteEnabled, survivor)}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %+v, want none", warnings)
			}
		})
	}
}

// Cursor's walk stops at a bounded depth, so a file below it is not a
// subagent either, and it is passed over on the same terms.
func TestADirectoryBelowCursorsDepthLimitIsPassedOverInSilence(t *testing.T) {
	var segments []string
	for i := 1; i <= maxAgentDepth+1; i++ {
		segments = append(segments, "d"+strconv.Itoa(i))
	}
	reached := path.Join(append([]string{projectAgentsDir}, segments[:maxAgentDepth]...)...)
	refused := path.Join(append([]string{projectAgentsDir}, segments...)...)

	fsys := fstest.MapFS{
		reached + "/deployer.md": {Data: []byte("---\nname: deployer\n---\n\ndelegates work.\n")},
		refused + "/too-deep.md": {Data: []byte("---\nname: too-deep\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	want := []ir.Entity{subagentNamed("deployer", subagentWriteEnabled, reached+"/deployer.md")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
}

// Cursor loads a fixed set of markdown extensions, so a file carrying
// another one is not a subagent, and warning over it would name
// configuration that is not there.
func TestAnEntryOutsideCursorsMarkdownSetIsSkippedSilently(t *testing.T) {
	const loaded = projectAgentsDir + "/deployer.mdc"
	fsys := fstest.MapFS{
		loaded:                          {Data: []byte("---\nname: deployer\n---\n\ndelegates work.\n")},
		projectAgentsDir + "/NOTES.txt": {Data: []byte("---\nname: notes\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
	want := []ir.Entity{subagentNamed("deployer", subagentWriteEnabled, loaded)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
	}
}

// The sibling beside a refused entry still reports. fsguard.CheckRegular's
// doc owns why the link itself is refused.
func TestAnIrregularProjectSubagentEntryIsRefusedAndItsSiblingSurvives(t *testing.T) {
	const link = projectAgentsDir + "/linked.md"
	const real = projectAgentsDir + "/real.md"
	fsys := fstest.MapFS{
		link: {Mode: fs.ModeSymlink, Data: []byte("../../elsewhere.md")},
		real: {Data: []byte("---\nname: survivor\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	want := []ir.Entity{subagentNamed("survivor", subagentWriteEnabled, real)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// A link standing where a subdirectory would be is refused as an entry.
func TestAnIrregularDirectoryInsideTheAgentsRootIsRefused(t *testing.T) {
	const link = projectAgentsDir + "/team"
	const survivor = projectAgentsDir + "/auditor.md"
	fsys := fstest.MapFS{
		link:                  {Mode: fs.ModeSymlink, Data: []byte("../../offtree")},
		survivor:              {Data: []byte("---\nname: auditor\n---\n\ndelegates work.\n")},
		"offtree/deployer.md": {Data: []byte("---\nname: deployer\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	want := []ir.Entity{subagentNamed("auditor", subagentWriteEnabled, survivor)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectSubagentEntities() = %+v, want %+v", got, want)
	}
	if len(warnings) != 1 || warnings[0].File != link {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, link)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// A root this scanner refuses to walk is a set of subagents nothing read, and
// a silent return there prints a clean report over them.
func TestAnIrregularProjectAgentsRootWarnsRatherThanGoingSilent(t *testing.T) {
	fsys := fstest.MapFS{
		projectAgentsDir:      {Mode: fs.ModeSymlink, Data: []byte("../offtree")},
		"offtree/deployer.md": {Data: []byte("---\nname: deployer\n---\n\ndelegates work.\n")},
	}

	got, warnings := projectSubagentEntities(fsys)
	if len(got) != 0 {
		t.Fatalf("projectSubagentEntities() = %+v, want none", got)
	}
	if len(warnings) != 1 || warnings[0].File != projectAgentsDir {
		t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, projectAgentsDir)
	}
	if !errors.Is(warnings[0].Err, adapter.ErrUnreadable) {
		t.Fatalf("warning %v is not an adapter.ErrUnreadable", warnings[0].Err)
	}
}

// An absent agents root stays silent, for the reason skillEntities' doc
// gives.
func TestAProjectWithoutAnAgentsRootSurfacesNothing(t *testing.T) {
	fsys := fstest.MapFS{".cursor/mcp.json": {Data: []byte(`{"mcpServers":{}}`)}}

	got, warnings := projectSubagentEntities(fsys)
	if len(got) != 0 || len(warnings) != 0 {
		t.Fatalf("projectSubagentEntities() = %+v, %+v, want nothing", got, warnings)
	}
}

// The silence unwalkedAgentDirs' doc justifies holds only while this
// scanner declines exactly where Cursor declines. These are the vendor's own
// values, read from its agent binary's bundled index.js: the skipDirectories
// default of the directory walker its subagent scan calls, and that walker's
// maxDepth default. Trimming either without the vendor trimming it turns
// that silence into a blind spot.
func TestTheAgentsWalkDeclinesExactlyWhereCursorDeclines(t *testing.T) {
	wantDirs := []string{
		".cache", ".git", ".hg", ".next", ".nuxt", ".svn",
		"__pycache__", "build", "dist", "node_modules",
	}
	const wantDepth = 10

	var gotDirs []string
	for name := range unwalkedAgentDirs {
		gotDirs = append(gotDirs, name)
	}
	sort.Strings(gotDirs)
	if !reflect.DeepEqual(gotDirs, wantDirs) {
		t.Errorf("unwalkedAgentDirs = %q, want %q", gotDirs, wantDirs)
	}
	if maxAgentDepth != wantDepth {
		t.Errorf("maxAgentDepth = %d, want %d", maxAgentDepth, wantDepth)
	}
}
