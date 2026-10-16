package agentaudit_test

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/treefs"
)

// The contract is parity with os.Root, so real disk is the subject: each
// fixture tree, fetched only as far as Select rounds ask and then sealed,
// yields the findings, in emission order, and the tallies os.Root does.
func TestScanOfASelectedTreeMatchesOSRoot(t *testing.T) {
	compared := 0
	for _, target := range differentialTargets(t) {
		t.Run(target, func(t *testing.T) {
			compared += len(plainParity(t, path.Join("testdata", target)).Findings())
		})
	}
	if compared == 0 {
		t.Fatal("compared no finding; an engine reporting nothing would leave every subtest green")
	}
}

func TestScanRecursiveOfASelectedTreeMatchesOSRoot(t *testing.T) {
	compared := 0
	for _, target := range differentialTargets(t) {
		t.Run(target, func(t *testing.T) {
			for _, project := range recursiveParity(t, path.Join("testdata", target)) {
				compared += len(project.Report.Findings())
			}
		})
	}
	if compared == 0 {
		t.Fatal("compared no finding; an engine reporting nothing would leave every subtest green")
	}
}

func plainParity(t *testing.T, dir string) agentaudit.Report {
	t.Helper()

	diskWarnings := 0
	disk := plainScan(t, agentaudit.New(countWarnings(&diskWarnings)), rootFS(t, dir))

	memoryWarnings := 0
	s := agentaudit.New(countWarnings(&memoryWarnings))
	memory := plainScan(t, s, selectedTree(t, s, treeFromDisk(t, dir)))

	assertSameFindingLines(t, findingLines(disk), findingLines(memory))
	assertSameTallies(t, disk, memory)
	if diskWarnings != memoryWarnings {
		t.Fatalf("WarnFunc called %d time(s) through os.Root and %d through treefs", diskWarnings, memoryWarnings)
	}
	return disk
}

func recursiveParity(t *testing.T, dir string) []agentaudit.ProjectReport {
	t.Helper()

	diskWarnings := 0
	disk := recursiveScan(t, agentaudit.New(countWarnings(&diskWarnings)), rootFS(t, dir))

	memoryWarnings := 0
	s := agentaudit.New(agentaudit.WithRecursive(), countWarnings(&memoryWarnings))
	memory := recursiveScan(t, s, selectedTree(t, s, treeFromDisk(t, dir)))

	if len(disk) != len(memory) {
		t.Fatalf("ScanRecursive enumerated %d project(s) through os.Root and %d through treefs", len(disk), len(memory))
	}
	for i := range disk {
		if disk[i].Path != memory[i].Path {
			t.Fatalf("project %d = %q through os.Root and %q through treefs", i, disk[i].Path, memory[i].Path)
		}
		assertSameFindingLines(t, findingLines(disk[i].Report), findingLines(memory[i].Report))
		assertSameTallies(t, disk[i].Report, memory[i].Report)
	}
	if diskWarnings != memoryWarnings {
		t.Fatalf("WarnFunc called %d time(s) through os.Root and %d through treefs", diskWarnings, memoryWarnings)
	}
	return disk
}

func differentialTargets(t *testing.T) []string {
	t.Helper()

	groups := subdirectories(t, "testdata")
	targets := slices.Clone(groups)
	for _, group := range groups {
		for _, project := range subdirectories(t, path.Join("testdata", group)) {
			targets = append(targets, path.Join(group, project))
		}
	}
	if len(targets) == len(groups) {
		t.Fatal("no fixture project found under testdata; an empty enumeration must not pass silently")
	}
	return targets
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

func rootFS(t *testing.T, dir string) fs.FS {
	t.Helper()

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot(%q) error = %v", dir, err)
	}
	t.Cleanup(func() { root.Close() })
	return root.FS()
}

type diskTree struct {
	entries []treefs.Entry
	blobs   map[string][]byte
}

func treeFromDisk(t *testing.T, dir string) diskTree {
	t.Helper()

	disk := rootFS(t, dir)
	tree := diskTree{blobs: map[string][]byte{}}
	err := fs.WalkDir(disk, ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		info, err := fs.Lstat(disk, p)
		if err != nil {
			return err
		}
		switch mode := info.Mode(); {
		case mode.IsDir():
		case mode.IsRegular():
			data, err := fs.ReadFile(disk, p)
			if err != nil {
				return err
			}
			tree.blobs[p] = data
		case mode&fs.ModeSymlink != 0:
			target, err := fs.ReadLink(disk, p)
			if err != nil {
				return err
			}
			tree.blobs[p] = []byte(target)
		default:
			return nil
		}
		tree.entries = append(tree.entries, treefs.Entry{Path: p, Mode: info.Mode()})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %q: %v", dir, err)
	}
	if len(tree.blobs) == 0 {
		t.Fatalf("%q holds no blob; every comparison over it would be vacuous", dir)
	}
	return tree
}

func selectedTree(t *testing.T, s *agentaudit.Scanner, d diskTree) *treefs.FS {
	t.Helper()

	tree, fetch := fetchingTree(t, d, "")
	for asked := selectRound(t, s, tree); len(asked) > 0; asked = selectRound(t, s, tree) {
		fetch(asked)
	}
	tree.Seal()
	return tree
}

func fetchingTree(t *testing.T, d diskTree, withheld string) (tree *treefs.FS, fetch func(asked []string)) {
	t.Helper()

	fetched := map[string][]byte{}
	tree, err := treefs.New(d.entries, func(p string) ([]byte, bool) {
		data, ok := fetched[p]
		return data, ok
	})
	if err != nil {
		t.Fatalf("treefs.New() error = %v", err)
	}
	return tree, func(asked []string) {
		for _, p := range asked {
			if _, ok := fetched[p]; ok {
				t.Fatalf("Select() asked again for %q, already fetched", p)
			}
			data, ok := d.blobs[p]
			if !ok {
				t.Fatalf("Select() asked for %q, which holds no blob", p)
			}
			if p != withheld {
				fetched[p] = data
			}
		}
	}
}

func selectRound(t *testing.T, s *agentaudit.Scanner, tree *treefs.FS) []string {
	t.Helper()

	asked, err := s.Select(tree)
	if err != nil {
		t.Fatalf("Select() error = %v", err)
	}
	return asked
}

func countWarnings(n *int) agentaudit.Option {
	return agentaudit.WithWarnFunc(func(error) { *n++ })
}

func plainScan(t *testing.T, s *agentaudit.Scanner, fsys fs.FS) agentaudit.Report {
	t.Helper()

	report, err := s.Scan(fsys)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	return report
}

func recursiveScan(t *testing.T, s *agentaudit.Scanner, fsys fs.FS) []agentaudit.ProjectReport {
	t.Helper()

	reports, err := s.ScanRecursive(fsys)
	if err != nil {
		t.Fatalf("ScanRecursive() error = %v", err)
	}
	return reports
}

// findingLines renders the whole entity, since an ir.BundledPayload's
// identity is its path alone and leaves its Executable bit uncompared.
func findingLines(report agentaudit.Report) []string {
	out := make([]string, 0, len(report.Findings()))
	for _, f := range report.Findings() {
		out = append(out, fmt.Sprintf("%s\t%s\t%v\t%s\t%v\t%+v\t%T%+v",
			f.RuleID, f.Agent, f.Categories, f.Message, f.References,
			f.Capability.Provenance, f.Capability.Entity, f.Capability.Entity))
	}
	return out
}

func assertSameFindingLines(t *testing.T, want, got []string) {
	t.Helper()

	if len(want) != len(got) {
		t.Fatalf("%d finding(s) through os.Root and %d through treefs\nos.Root:\n%s\ntreefs:\n%s", len(want), len(got), indentLines(want), indentLines(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("finding %d\nos.Root: %s\ntreefs:  %s", i, want[i], got[i])
		}
	}
}

func assertSameTallies(t *testing.T, disk, memory agentaudit.Report) {
	t.Helper()

	if disk.UnreadableSources() != memory.UnreadableSources() {
		t.Fatalf("UnreadableSources() = %d through os.Root and %d through treefs", disk.UnreadableSources(), memory.UnreadableSources())
	}
	if disk.UnparsedSources() != memory.UnparsedSources() {
		t.Fatalf("UnparsedSources() = %d through os.Root and %d through treefs", disk.UnparsedSources(), memory.UnparsedSources())
	}
	if !slices.Equal(disk.ScannedAgents(), memory.ScannedAgents()) {
		t.Fatalf("ScannedAgents() = %v through os.Root and %v through treefs", disk.ScannedAgents(), memory.ScannedAgents())
	}
}

func indentLines(in []string) string {
	out := ""
	for _, s := range in {
		out += "  " + s + "\n"
	}
	return out
}
