package remote

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/manifold-security/agentaudit"
)

// The reference is the fixture directory scanned in place through os.Root,
// so real disk is the subject: each fixture tree, served by the fake and
// fetched round by round, yields the findings, in emission order, the
// tallies and as many warnings as os.Root does.
func TestFetchedScanMatchesOSRoot(t *testing.T) {
	compared := 0
	for _, target := range differentialTargets(t) {
		t.Run(target, func(t *testing.T) {
			compared += len(plainParity(t, path.Join("../testdata", target)).Findings())
		})
	}
	if compared == 0 {
		t.Fatal("compared no finding; an engine reporting nothing would leave every subtest green")
	}
}

func TestFetchedScanRecursiveMatchesOSRoot(t *testing.T) {
	compared := 0
	for _, target := range differentialTargets(t) {
		t.Run(target, func(t *testing.T) {
			for _, project := range recursiveParity(t, path.Join("../testdata", target)) {
				compared += len(project.Report.Findings())
			}
		})
	}
	if compared == 0 {
		t.Fatal("compared no finding; an engine reporting nothing would leave every subtest green")
	}
}

func fetchFixture(t *testing.T, dir string, s *agentaudit.Scanner) fs.FS {
	t.Helper()
	repo, _ := newFakeRepo(t, rootFS(t, dir))
	useFake(t, &fakeGit{repos: map[string]*fakeRepo{"o/r": repo}})
	_, tree, err := Fetch(context.Background(), "https://github.com/o/r", "", s, DefaultLimits())
	if err != nil {
		t.Fatalf("Fetch(%s) error = %v", dir, err)
	}
	return tree
}

func plainParity(t *testing.T, dir string) agentaudit.Report {
	t.Helper()

	diskWarnings := 0
	disk, err := agentaudit.New(countWarnings(&diskWarnings)).Scan(rootFS(t, dir))
	if err != nil {
		t.Fatalf("Scan(os.Root) error = %v", err)
	}

	fetchedWarnings := 0
	s := agentaudit.New(countWarnings(&fetchedWarnings))
	fetched, err := s.Scan(fetchFixture(t, dir, s))
	if err != nil {
		t.Fatalf("Scan(fetched) error = %v", err)
	}

	assertSameFindingLines(t, findingLines(disk), findingLines(fetched))
	assertSameTallies(t, disk, fetched)
	if diskWarnings != fetchedWarnings {
		t.Fatalf("WarnFunc called %d time(s) through os.Root and %d through the fetch", diskWarnings, fetchedWarnings)
	}
	return disk
}

func recursiveParity(t *testing.T, dir string) []agentaudit.ProjectReport {
	t.Helper()

	diskWarnings := 0
	disk, err := agentaudit.New(countWarnings(&diskWarnings)).ScanRecursive(rootFS(t, dir))
	if err != nil {
		t.Fatalf("ScanRecursive(os.Root) error = %v", err)
	}

	fetchedWarnings := 0
	s := agentaudit.New(agentaudit.WithRecursive(), countWarnings(&fetchedWarnings))
	fetched, err := s.ScanRecursive(fetchFixture(t, dir, s))
	if err != nil {
		t.Fatalf("ScanRecursive(fetched) error = %v", err)
	}

	if len(disk) != len(fetched) {
		t.Fatalf("ScanRecursive enumerated %d project(s) through os.Root and %d through the fetch", len(disk), len(fetched))
	}
	for i := range disk {
		if disk[i].Path != fetched[i].Path {
			t.Fatalf("project %d = %q through os.Root and %q through the fetch", i, disk[i].Path, fetched[i].Path)
		}
		assertSameFindingLines(t, findingLines(disk[i].Report), findingLines(fetched[i].Report))
		assertSameTallies(t, disk[i].Report, fetched[i].Report)
	}
	if diskWarnings != fetchedWarnings {
		t.Fatalf("WarnFunc called %d time(s) through os.Root and %d through the fetch", diskWarnings, fetchedWarnings)
	}
	return disk
}

const linkRowSettings = `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"audit.sh"}]}]}}`

func TestFetchedSymlinkResolutionMatchesOSRoot(t *testing.T) {
	for _, tt := range []linkRow{
		{
			name:  "an in-tree directory link",
			links: map[string]string{".claude": "real/cfg"},
			files: map[string]string{"real/cfg/settings.json": linkRowSettings},
			reads: true,
		},
		{
			name:    "an absolute link",
			links:   map[string]string{".claude": "/nonexistent/cfg"},
			refused: true,
		},
		{
			name:    "an escaping link",
			links:   map[string]string{".claude": "../outside"},
			outside: map[string]string{"outside/settings.json": linkRowSettings},
			refused: true,
		},
		chainOfLinks(8, true),
		chainOfLinks(9, false),
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			writeFiles(t, root, tt.files)
			writeFiles(t, base, tt.outside)
			for link, target := range tt.links {
				if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
					t.Fatalf("os.Symlink(%q, %q) error = %v", target, link, err)
				}
			}

			report := plainParity(t, root)
			if got := len(report.Findings()) > 0; got != tt.reads {
				t.Fatalf("os.Root findings = %d, want reads = %v", len(report.Findings()), tt.reads)
			}
			if got := report.UnreadableSources() > 0; got != tt.refused {
				t.Fatalf("os.Root UnreadableSources() = %d, want refused = %v", report.UnreadableSources(), tt.refused)
			}
			recursiveParity(t, root)
		})
	}
}

type linkRow struct {
	name           string
	links          map[string]string
	files          map[string]string
	outside        map[string]string
	reads, refused bool
}

func chainOfLinks(n int, reads bool) linkRow {
	links := map[string]string{}
	from := ".claude"
	for i := 1; i < n; i++ {
		next := fmt.Sprintf("l%d", i)
		links[from] = next
		from = next
	}
	links[from] = "real/cfg"
	return linkRow{
		name:    fmt.Sprintf("a chain of %d links", n),
		links:   links,
		files:   map[string]string{"real/cfg/settings.json": linkRowSettings},
		reads:   reads,
		refused: !reads,
	}
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

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%q) error = %v", root, err)
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("os.MkdirAll(%q) error = %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("os.WriteFile(%q) error = %v", p, err)
		}
	}
}

func differentialTargets(t *testing.T) []string {
	t.Helper()
	groups := subdirectories(t, "../testdata")
	targets := slices.Clone(groups)
	for _, group := range groups {
		for _, project := range subdirectories(t, path.Join("../testdata", group)) {
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

func countWarnings(n *int) agentaudit.Option {
	return agentaudit.WithWarnFunc(func(error) { *n++ })
}

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
		t.Fatalf("%d finding(s) through os.Root and %d through the fetch\nos.Root:\n%s\nfetch:\n%s", len(want), len(got), indentLines(want), indentLines(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("finding %d\nos.Root: %s\nfetch:   %s", i, want[i], got[i])
		}
	}
}

func assertSameTallies(t *testing.T, disk, fetched agentaudit.Report) {
	t.Helper()
	if disk.UnreadableSources() != fetched.UnreadableSources() {
		t.Fatalf("UnreadableSources() = %d through os.Root and %d through the fetch", disk.UnreadableSources(), fetched.UnreadableSources())
	}
	if disk.UnparsedSources() != fetched.UnparsedSources() {
		t.Fatalf("UnparsedSources() = %d through os.Root and %d through the fetch", disk.UnparsedSources(), fetched.UnparsedSources())
	}
	if !slices.Equal(disk.ScannedAgents(), fetched.ScannedAgents()) {
		t.Fatalf("ScannedAgents() = %v through os.Root and %v through the fetch", disk.ScannedAgents(), fetched.ScannedAgents())
	}
}

func indentLines(in []string) string {
	out := ""
	for _, s := range in {
		out += "  " + s + "\n"
	}
	return out
}
