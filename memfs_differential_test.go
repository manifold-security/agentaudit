package agentaudit_test

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/memfs"
)

// One engine reads a synthesized flat path-to-bytes set and a real directory
// alike, so each fixture tree yields the same findings in the same order and
// the same degradation tallies through both.
func TestScanThroughMemFSMatchesTheSameTreeThroughOSDirFS(t *testing.T) {
	projects := differentialProjects(t)
	compared := 0

	for _, project := range projects {
		t.Run(project, func(t *testing.T) {
			dir := path.Join("testdata", project)

			disk, diskWarnings := differentialScan(t, os.DirFS(dir))
			memory, memoryWarnings := differentialScan(t, hostFS(t, hostFilesFromDisk(t, dir)))

			want := findingLines(disk)
			compared += len(want)

			assertSameFindingLines(t, want, findingLines(memory), project)
			assertSameTallies(t, disk, memory)
			if diskWarnings != memoryWarnings {
				t.Fatalf("WarnFunc called %d time(s) on disk and %d time(s) in memory", diskWarnings, memoryWarnings)
			}
		})
	}

	if compared == 0 {
		t.Fatalf("compared no finding across %d fixture tree(s); an engine that reported nothing at all would leave every subtree above green", len(projects))
	}
}

// ScanRecursive wraps each project root BELOW the container in subtreeFS,
// which advertises fs.ReadLinkFS, so the plugin guards take a branch the
// per-project leg above does not reach on this FS.
func TestScanRecursiveThroughMemFSMatchesTheSameTreeThroughOSDirFS(t *testing.T) {
	compared := 0

	for _, group := range differentialGroups(t) {
		t.Run(group, func(t *testing.T) {
			dir := path.Join("testdata", group)

			disk, diskWarnings := differentialScanRecursive(t, os.DirFS(dir))
			memory, memoryWarnings := differentialScanRecursive(t, hostFS(t, hostFilesFromDisk(t, dir)))

			if len(disk) != len(memory) {
				t.Fatalf("ScanRecursive enumerated %d project(s) on disk and %d in memory", len(disk), len(memory))
			}
			if diskWarnings != memoryWarnings {
				t.Fatalf("WarnFunc called %d time(s) on disk and %d time(s) in memory", diskWarnings, memoryWarnings)
			}
			for i := range disk {
				if disk[i].Path != memory[i].Path {
					t.Fatalf("project %d = %q on disk and %q in memory", i, disk[i].Path, memory[i].Path)
				}
				project := path.Join(group, disk[i].Path)
				want := findingLines(disk[i].Report)
				compared += len(want)
				assertSameFindingLines(t, want, findingLines(memory[i].Report), project)
				assertSameTallies(t, disk[i].Report, memory[i].Report)
			}
		})
	}

	if compared == 0 {
		t.Fatalf("compared no finding across the recursive scans; an engine that reported nothing at all would leave every group above green")
	}
}

// An extensionless payload carries no mode bit through a path-to-bytes set, so
// the shebang is the only thing that can reach it there.
func TestExtensionlessPayloadReachesBothScansThroughItsShebang(t *testing.T) {
	const payload = ".claude/commands/tool"
	dir := path.Join("testdata", "malicious/claude-bundled-payload")

	disk, _ := differentialScan(t, os.DirFS(dir))
	memory, _ := differentialScan(t, hostFS(t, hostFilesFromDisk(t, dir)))

	if !reportsFile(disk, payload) {
		t.Fatalf("findings = %+v, want the on-disk scan to report %q", disk.Findings(), payload)
	}
	if !reportsFile(memory, payload) {
		t.Fatalf("findings = %+v, want the in-memory scan to report %q", memory.Findings(), payload)
	}
}

// differentialGroups enumerates the fixture groups rather than naming them,
// as differentialProjects does the trees inside one, so a fixture added at
// either level is differentially checked without an edit here.
func differentialGroups(t *testing.T) []string {
	t.Helper()

	groups := subdirectories(t, "testdata")
	if len(groups) == 0 {
		t.Fatalf("no fixture group found under testdata; an empty enumeration must not pass silently")
	}
	return groups
}

func differentialProjects(t *testing.T) []string {
	t.Helper()

	var projects []string
	for _, group := range differentialGroups(t) {
		for _, tree := range subdirectories(t, path.Join("testdata", group)) {
			projects = append(projects, group+"/"+tree)
		}
	}
	if len(projects) == 0 {
		t.Fatalf("no fixture tree found under testdata; an empty enumeration must not pass silently")
	}
	return projects
}

func subdirectories(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) error = %v", dir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return names
}

// hostFilesFromDisk reads dir into the flat path-to-bytes shape a host hands
// memfs.New, discarding the directory entries and the mode bits a host has no
// way to supply.
func hostFilesFromDisk(t *testing.T, dir string) map[string][]byte {
	t.Helper()

	tree := os.DirFS(dir)
	files := map[string][]byte{}
	err := fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(tree, p)
		if err != nil {
			return err
		}
		files[p] = data
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir(%q) error = %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("%q holds no file; an empty host set would make every comparison below vacuous", dir)
	}
	return files
}

func hostFS(t *testing.T, files map[string][]byte) fs.FS {
	t.Helper()

	fsys, err := memfs.New(files)
	if err != nil {
		t.Fatalf("memfs.New() error = %v, want nil", err)
	}
	return fsys
}

func differentialScan(t *testing.T, fsys fs.FS) (agentaudit.Report, int) {
	t.Helper()

	warnings := 0
	scanner := agentaudit.New(agentaudit.WithWarnFunc(func(error) { warnings++ }))
	report, err := scanner.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}
	return report, warnings
}

func differentialScanRecursive(t *testing.T, fsys fs.FS) ([]agentaudit.ProjectReport, int) {
	t.Helper()

	warnings := 0
	scanner := agentaudit.New(agentaudit.WithWarnFunc(func(error) { warnings++ }))
	reports, err := scanner.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v, want nil", err)
	}
	return reports, warnings
}

// findingLines renders a report's findings in emission order, so the
// comparison covers the order an attacker-chosen filename can influence and
// not just the set.
func findingLines(report agentaudit.Report) []string {
	out := make([]string, 0, len(report.Findings()))
	for _, f := range report.Findings() {
		out = append(out, findingLine(f))
	}
	return out
}

// findingLine renders one finding as a comparable string with the entity's
// Executable field cleared, because it reports a +x bit only one of the two
// hosts can carry and leaving it in would compare the two filesystems instead
// of the two scans.
func findingLine(f agentaudit.Finding) string {
	entity := withoutExecutableBit(f.Capability.Entity)
	return fmt.Sprintf("%s\t%s\t%v\t%s\t%v\t%+v\t%T%+v",
		f.RuleID,
		f.Agent,
		f.Categories,
		f.Message,
		f.References,
		f.Capability.Provenance,
		entity,
		entity,
	)
}

func withoutExecutableBit(entity ir.Entity) ir.Entity {
	switch v := entity.(type) {
	case ir.BundledPayload:
		v.Executable = ""
		return v
	case ir.PluginExecutable:
		v.Executable = ""
		return v
	}
	return entity
}

func reportsFile(report agentaudit.Report, file string) bool {
	for _, f := range report.Findings() {
		if f.Capability.Provenance.File == file {
			return true
		}
	}
	return false
}

func assertSameFindingLines(t *testing.T, want, got []string, project string) {
	t.Helper()

	if len(want) != len(got) {
		t.Fatalf("%s: %d finding(s) on disk and %d in memory\non disk:\n%s\nin memory:\n%s", project, len(want), len(got), indentLines(want), indentLines(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("%s: finding %d\non disk:   %s\nin memory: %s", project, i, want[i], got[i])
		}
	}
}

func assertSameTallies(t *testing.T, disk, memory agentaudit.Report) {
	t.Helper()

	if disk.UnreadableSources() != memory.UnreadableSources() {
		t.Fatalf("UnreadableSources() = %d on disk and %d in memory", disk.UnreadableSources(), memory.UnreadableSources())
	}
	if disk.UnparsedSources() != memory.UnparsedSources() {
		t.Fatalf("UnparsedSources() = %d on disk and %d in memory", disk.UnparsedSources(), memory.UnparsedSources())
	}
}

func indentLines(in []string) string {
	out := ""
	for _, s := range in {
		out += "  " + s + "\n"
	}
	return out
}
