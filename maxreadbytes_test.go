package agentaudit_test

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/treefs"
)

const (
	settingsFile      = ".claude/settings.json"
	localSettingsFile = ".claude/settings.local.json"
	sniffedPayload    = ".claude/skills/demo/run"
	skillFile         = ".claude/skills/demo/SKILL.md"
	referencedPayload = ".claude/skills/demo/scripts/run.sh"
)

const localStubSettings = `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"l.sh"}]}]}}`

const referencingSkill = "---\nname: demo\n---\nRun scripts/run.sh first.\n"

func findingsByFile(rep finding.Report) []string {
	var out []string
	for _, f := range rep.Findings() {
		out = append(out, f.RuleID+"@"+f.Capability.Provenance.File)
	}
	slices.Sort(out)
	return out
}

func warningsNaming(warnings []string, file string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, file) {
			n++
		}
	}
	return n
}

func TestWithMaxReadBytesRefusesTheReadThatPassesTheBudget(t *testing.T) {
	s, l := int64(len(validStubSettings)), int64(len(localStubSettings))
	k := int64(len(referencingSkill))
	settings := fstest.MapFS{settingsFile: &fstest.MapFile{Data: []byte(validStubSettings)}}
	both := fstest.MapFS{
		settingsFile:      &fstest.MapFile{Data: []byte(validStubSettings)},
		localSettingsFile: &fstest.MapFile{Data: []byte(localStubSettings)},
	}
	emptyLocal := fstest.MapFS{
		settingsFile:      &fstest.MapFile{Data: []byte(validStubSettings)},
		localSettingsFile: &fstest.MapFile{},
	}
	sniffed := fstest.MapFS{sniffedPayload: &fstest.MapFile{Data: []byte("#!/bin/sh\n")}}
	skill := fstest.MapFS{
		skillFile:         &fstest.MapFile{Data: []byte(referencingSkill)},
		referencedPayload: &fstest.MapFile{Data: []byte("echo\n")},
	}
	hook := "claude.hook.command@" + settingsFile
	localHook := "claude.hook.command@" + localSettingsFile

	for _, tc := range []struct {
		name       string
		tree       fstest.MapFS
		budget     int64
		findings   []string
		unreadable int
		unparsed   int
		warned     []string
	}{
		{"one file at the budget", settings, s, []string{hook}, 0, 0, nil},
		{"one file past the budget", settings, s - 1, nil, 1, 0, []string{settingsFile}},
		{"two files at the budget", both, s + l, []string{hook, localHook}, 0, 0, nil},
		{"the second file past the budget", both, s + l - 1, []string{hook}, 1, 0, []string{localSettingsFile}},
		{"an empty file under a filled budget", emptyLocal, s, []string{hook}, 0, 1, []string{localSettingsFile}},
		{"an empty file once the budget is spent", emptyLocal, s - 1, nil, 2, 0, []string{settingsFile, localSettingsFile}},
		{"a sniff at the budget", sniffed, 2, []string{"claude.payload.bundled-script@" + sniffedPayload}, 0, 0, nil},
		{"a sniff past the budget", sniffed, 1, nil, 1, 0, []string{sniffedPayload}},
		{"a repeat read at the budget", skill, 2 * k, []string{"claude.payload.referenced-script@" + referencedPayload}, 0, 0, nil},
		{"a repeat read past the budget", skill, 2*k - 1, []string{"claude.payload.bundled-script@" + referencedPayload}, 1, 0, []string{skillFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			sc := agentaudit.New(
				agentaudit.WithMaxReadBytes(tc.budget),
				agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
			)

			rep, err := sc.Scan(tc.tree)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if got := findingsByFile(rep); !slices.Equal(got, tc.findings) {
				t.Errorf("findings = %q, want %q", got, tc.findings)
			}
			if got := rep.UnreadableSources(); got != tc.unreadable {
				t.Errorf("UnreadableSources() = %d, want %d (warnings: %q)", got, tc.unreadable, warnings)
			}
			if got := rep.UnparsedSources(); got != tc.unparsed {
				t.Errorf("UnparsedSources() = %d, want %d (warnings: %q)", got, tc.unparsed, warnings)
			}
			if len(warnings) != len(tc.warned) {
				t.Errorf("warnings = %q, want one for each of %q", warnings, tc.warned)
			}
			for _, file := range tc.warned {
				if n := warningsNaming(warnings, file); n != 1 {
					t.Errorf("%d warnings name %s, want 1 (warnings: %q)", n, file, warnings)
				}
			}
		})
	}
}

func TestWithMaxReadBytesBudgetsEachScanCall(t *testing.T) {
	s := int64(len(validStubSettings))
	tree := fstest.MapFS{settingsFile: &fstest.MapFile{Data: []byte(validStubSettings)}}
	projects := fstest.MapFS{
		"a/" + settingsFile: &fstest.MapFile{Data: []byte(validStubSettings)},
		"b/" + settingsFile: &fstest.MapFile{Data: []byte(validStubSettings)},
	}
	rootProject := fstest.MapFS{
		settingsFile:        &fstest.MapFile{Data: []byte(validStubSettings)},
		"a/" + settingsFile: &fstest.MapFile{Data: []byte(validStubSettings)},
	}
	scan := func(sc *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) { return sc.Scan(fsys) }
	scanContext := func(sc *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) {
		return sc.ScanContext(context.Background(), fsys)
	}
	scanGlobal := func(sc *agentaudit.Scanner, fsys fs.FS) (finding.Report, error) { return sc.ScanGlobal(fsys) }

	for _, tc := range []struct {
		name string
		scan func(*agentaudit.Scanner, fs.FS) (finding.Report, error)
	}{
		{"Scan", scan},
		{"ScanContext", scanContext},
		{"ScanGlobal", scanGlobal},
	} {
		for _, budget := range []int64{s, s - 1} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, budget), func(t *testing.T) {
				sc := agentaudit.New(agentaudit.WithMaxReadBytes(budget))
				for call := range 2 {
					rep, err := tc.scan(sc, tree)
					if err != nil {
						t.Fatalf("call %d: error = %v, want nil", call, err)
					}
					wantUnreadable := 0
					if budget < s {
						wantUnreadable = 1
					}
					if got := rep.UnreadableSources(); got != wantUnreadable {
						t.Errorf("call %d: UnreadableSources() = %d, want %d", call, got, wantUnreadable)
					}
				}
			})
		}
	}

	for _, tc := range []struct {
		name       string
		tree       fstest.MapFS
		budget     int64
		unreadable map[string]int
	}{
		{"projects", projects, 2 * s, map[string]int{"a": 0, "b": 0}},
		{"projects", projects, 2*s - 1, map[string]int{"a": 0, "b": 1}},
		{"root project", rootProject, 2 * s, map[string]int{".": 0, "a": 0}},
		{"root project", rootProject, s - 1, map[string]int{".": 1, "a": 1}},
	} {
		t.Run(fmt.Sprintf("ScanRecursive/%s/%d", tc.name, tc.budget), func(t *testing.T) {
			sc := agentaudit.New(agentaudit.WithMaxReadBytes(tc.budget))
			for call := range 2 {
				reps, err := sc.ScanRecursive(tc.tree)
				if err != nil {
					t.Fatalf("call %d: error = %v, want nil", call, err)
				}
				got := map[string]int{}
				for _, r := range reps {
					got[r.Path] = r.Report.UnreadableSources()
				}
				if !reflect.DeepEqual(got, tc.unreadable) {
					t.Errorf("call %d: UnreadableSources() by project = %v, want %v", call, got, tc.unreadable)
				}
			}
		})
	}
}

// A refused read counts in the project whose scan made it, even one its
// reader drops.
func TestWithMaxReadBytesCountsASilentRefusalInItsProject(t *testing.T) {
	s, k := int64(len(validStubSettings)), int64(len(referencingSkill))
	projects := fstest.MapFS{
		"a/" + settingsFile:      &fstest.MapFile{Data: []byte(validStubSettings)},
		"b/" + skillFile:         &fstest.MapFile{Data: []byte(referencingSkill)},
		"b/" + referencedPayload: &fstest.MapFile{Data: []byte("echo\n")},
	}
	for _, tc := range []struct {
		budget     int64
		unreadable map[string]int
	}{
		{s + 2*k, map[string]int{"a": 0, "b": 0}},
		{s + 2*k - 1, map[string]int{"a": 0, "b": 1}},
	} {
		t.Run(fmt.Sprint(tc.budget), func(t *testing.T) {
			reps, err := agentaudit.New(agentaudit.WithMaxReadBytes(tc.budget)).ScanRecursive(projects)
			if err != nil {
				t.Fatalf("ScanRecursive() error = %v, want nil", err)
			}
			got := map[string]int{}
			for _, r := range reps {
				got[r.Path] = r.Report.UnreadableSources()
			}
			if !reflect.DeepEqual(got, tc.unreadable) {
				t.Errorf("UnreadableSources() by project = %v, want %v", got, tc.unreadable)
			}
		})
	}
}

func TestWithMaxReadBytesHoldsBesideWithMaxFileSize(t *testing.T) {
	s, l := int64(len(validStubSettings)), int64(len(localStubSettings))
	tree := fstest.MapFS{
		settingsFile:      &fstest.MapFile{Data: []byte(validStubSettings)},
		localSettingsFile: &fstest.MapFile{Data: []byte(localStubSettings)},
	}
	for _, tc := range []struct {
		name          string
		file, budget  int64
		refused, kept string
	}{
		{"the file cap binds", s - 1, s + l, settingsFile, localSettingsFile},
		{"the budget binds", s + l, s + l - 1, localSettingsFile, settingsFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			sc := agentaudit.New(
				agentaudit.WithMaxFileSize(tc.file),
				agentaudit.WithMaxReadBytes(tc.budget),
				agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }),
			)

			rep, err := sc.Scan(tree)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			want := []string{"claude.hook.command@" + tc.kept}
			if got := findingsByFile(rep); !slices.Equal(got, want) {
				t.Errorf("findings = %q, want %q", got, want)
			}
			if rep.UnreadableSources() != 1 || warningsNaming(warnings, tc.refused) != 1 {
				t.Errorf("UnreadableSources() = %d, warnings = %q, want %s refused once", rep.UnreadableSources(), warnings, tc.refused)
			}
		})
	}
}

const defaultMaxReadBytes = 64 << 20

func agentFiles(n, size int) fstest.MapFS {
	data := []byte(strings.Repeat(" ", size))
	fsys := fstest.MapFS{}
	for i := range n {
		fsys[fmt.Sprintf(".claude/agents/a%03d.md", i)] = &fstest.MapFile{Data: data}
	}
	return fsys
}

func TestNewBudgetsEachScanAt64MiB(t *testing.T) {
	const extra = ".claude/agents/z.md"
	full := agentFiles(defaultMaxReadBytes/defaultMaxFileSize, defaultMaxFileSize)
	over := agentFiles(defaultMaxReadBytes/defaultMaxFileSize, defaultMaxFileSize)
	over[extra] = &fstest.MapFile{Data: []byte(" ")}
	refusal := "agentaudit: read budget: " + extra + ": read " + extra + ": past the scan's 64 MiB read budget; not scanned"

	for _, tc := range []struct {
		name     string
		tree     fstest.MapFS
		warnings []string
	}{
		{"at the budget", full, nil},
		{"past the budget", over, []string{refusal}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			s := agentaudit.New(agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))

			rep, err := s.Scan(tc.tree)
			if err != nil {
				t.Fatalf("Scan() error = %v, want nil", err)
			}
			if got := rep.UnreadableSources(); got != len(tc.warnings) {
				t.Errorf("UnreadableSources() = %d, want %d", got, len(tc.warnings))
			}
			if !slices.Equal(warnings, tc.warnings) {
				t.Errorf("warnings = %q, want %q", warnings, tc.warnings)
			}
		})
	}
}

func TestWithMaxReadBytesAtZeroBelowOrTheInt64MaxScansAsUncapped(t *testing.T) {
	fsys := agentFiles(defaultMaxReadBytes/defaultMaxFileSize+1, defaultMaxFileSize)
	fsys[settingsFile] = &fstest.MapFile{Data: []byte(validStubSettings)}
	fsys[sniffedPayload] = &fstest.MapFile{Data: []byte("#!/bin/sh\n")}
	want := []string{"claude.hook.command@" + settingsFile, "claude.payload.bundled-script@" + sniffedPayload}

	live, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, n := range []int64{0, -1, math.MaxInt64} {
		for _, tc := range []struct {
			name string
			ctx  context.Context
		}{
			{"background", context.Background()},
			{"cancellable", live},
		} {
			t.Run(fmt.Sprintf("%d/%s", n, tc.name), func(t *testing.T) {
				got, err := agentaudit.New(agentaudit.WithMaxReadBytes(n)).ScanContext(tc.ctx, fsys)
				if err != nil {
					t.Fatalf("ScanContext() error = %v, want nil", err)
				}
				if findings := findingsByFile(got); !slices.Equal(findings, want) || got.UnreadableSources() != 0 {
					t.Errorf("findings = %q, UnreadableSources() = %d, want %q read whole", findings, got.UnreadableSources(), want)
				}
			})
		}
	}
}

func TestWithMaxReadBytesUnderTheBudgetChangesNoFixtureReport(t *testing.T) {
	const budget = 6 << 20
	compared := 0
	for _, target := range differentialTargets(t) {
		t.Run(target, func(t *testing.T) {
			tree := heldTree(t, treeFromDisk(t, "testdata/"+target))
			scan := func(opts ...agentaudit.Option) (finding.Report, []agentaudit.ProjectReport, []string) {
				var warnings []string
				sc := agentaudit.New(append(opts, agentaudit.WithWarnFunc(func(w error) { warnings = append(warnings, w.Error()) }))...)
				rep := plainScan(t, sc, tree)
				return rep, recursiveScan(t, sc, tree), warnings
			}
			want, wantProjects, wantWarnings := scan()
			got, gotProjects, gotWarnings := scan(agentaudit.WithMaxReadBytes(budget))

			if !reflect.DeepEqual(got, want) {
				t.Errorf("Scan() = %+v, want %+v", got, want)
			}
			if !reflect.DeepEqual(gotProjects, wantProjects) {
				t.Errorf("ScanRecursive() = %+v, want %+v", gotProjects, wantProjects)
			}
			if !slices.Equal(gotWarnings, wantWarnings) {
				t.Errorf("warnings = %q, want %q", gotWarnings, wantWarnings)
			}
			compared += len(want.Findings())
		})
	}
	if compared == 0 {
		t.Fatal("compared no finding; an engine reporting nothing would leave every subtest green")
	}
}

func heldTree(t *testing.T, d diskTree) *treefs.FS {
	t.Helper()

	tree, err := treefs.New(d.entries, func(p string) ([]byte, bool) {
		data, ok := d.blobs[p]
		return data, ok
	})
	if err != nil {
		t.Fatalf("treefs.New() error = %v", err)
	}
	tree.Seal()
	return tree
}
