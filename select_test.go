package agentaudit_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/treefs"
)

// A blob a plugin manifest declares waits for the round after the manifest
// arrives.
func TestSelectAsksForADeclaredComponentInTheNextRound(t *testing.T) {
	const declared = "plugins/toolkit/extra-skills/declared/SKILL.md"
	s := agentaudit.New()
	tree, fetch := fetchingTree(t, treeFromDisk(t, "testdata/malicious/claude-plugin-components"), "")

	first := selectRound(t, s, tree)
	if len(first) != 6 || slices.Contains(first, declared) {
		t.Fatalf("round 1 Select() = %q, want 6 paths without %q", first, declared)
	}
	fetch(first)
	if second := selectRound(t, s, tree); !slices.Equal(second, []string{declared}) {
		t.Fatalf("round 2 Select() = %q, want [%q]", second, declared)
	}
	fetch([]string{declared})
	if third := selectRound(t, s, tree); len(third) != 0 {
		t.Fatalf("round 3 Select() = %q, want none", third)
	}
}

func TestSelectAsksOnlyForWhatItsOwnScanRead(t *testing.T) {
	d := treeFromDisk(t, "testdata/malicious")
	fresh, _ := fetchingTree(t, d, "")
	want := selectRound(t, agentaudit.New(), fresh)
	if len(want) == 0 {
		t.Fatal("Select() of a fresh tree asked for nothing; the comparison below would be vacuous")
	}

	probe, _ := fetchingTree(t, d, "")
	recursiveScan(t, agentaudit.New(), probe)
	if !slices.ContainsFunc(probe.Missing(), func(p string) bool { return !slices.Contains(want, p) }) {
		t.Fatal("ScanRecursive read no unheld blob beyond Select's; the comparison below could not see one leak in")
	}

	tree, _ := fetchingTree(t, d, "")
	recursiveScan(t, agentaudit.New(), tree)
	if got := selectRound(t, agentaudit.New(), tree); !slices.Equal(got, want) {
		t.Fatalf("Select() after a ScanRecursive = %q, want %q, what Select asks of a fresh tree", got, want)
	}
}

// A blob that never arrives is asked for again by each round that still
// reads it: deciding to stop asking is the caller's.
func TestSelectAsksAgainForABlobThatNeverArrives(t *testing.T) {
	const withheld = "plugins/single/SKILL.md"
	s := agentaudit.New()
	tree, fetch := fetchingTree(t, treeFromDisk(t, "testdata/malicious/claude-plugin-components"), withheld)

	for round := 1; round <= 3; round++ {
		asked := selectRound(t, s, tree)
		if !slices.Contains(asked, withheld) {
			t.Fatalf("round %d Select() = %q, want it to include %q", round, asked, withheld)
		}
		fetch(asked)
	}
}

// Select stays off WarnFunc: an unfetched blob can fail to parse, a fault
// no sealed scan reports.
func TestSelectSuppressesWarnings(t *testing.T) {
	warnings := 0
	s := agentaudit.New(countWarnings(&warnings))
	tree, fetch := fetchingTree(t, treeFromDisk(t, "testdata/malicious"), "")

	asked := selectRound(t, s, tree)
	if len(asked) == 0 {
		t.Fatal("round 1 Select() asked for nothing; a Select that never scanned would pass the count below")
	}
	for ; len(asked) > 0; asked = selectRound(t, s, tree) {
		fetch(asked)
	}
	if warnings != 0 {
		t.Fatalf("WarnFunc called %d time(s) across Select, want 0", warnings)
	}

	plainScan(t, s, tree)
	if warnings == 0 {
		t.Fatal("WarnFunc never called by Scan of the same tree; the zero above proves nothing")
	}
}

func TestWithRecursiveChangesWhatSelectAsksFor(t *testing.T) {
	d := treeFromDisk(t, "testdata/malicious")
	plainTree, _ := fetchingTree(t, d, "")
	recursiveTree, _ := fetchingTree(t, d, "")

	plain := selectRound(t, agentaudit.New(), plainTree)
	recursive := selectRound(t, agentaudit.New(agentaudit.WithRecursive()), recursiveTree)
	if len(plain) == 0 || slices.Equal(plain, recursive) {
		t.Fatalf("Select() = %q plain and %q under WithRecursive, want two different non-empty sets", plain, recursive)
	}
}

// SelectContext's scan reads no blob past the read that sees its context
// end, and a passed deadline stops it before any read.
func TestSelectContextStopsItsScanWhenTheContextEnds(t *testing.T) {
	files := fstest.MapFS{
		".mcp.json":                 {Data: []byte(`{"mcpServers":{}}`)},
		".claude/settings.json":     {Data: []byte(validStubSettings)},
		"sub/.mcp.json":             {Data: []byte(`{"mcpServers":{}}`)},
		"sub/.claude/settings.json": {Data: []byte(validStubSettings)},
	}
	for _, tc := range []struct {
		name string
		s    *agentaudit.Scanner
	}{
		{"plain", agentaudit.New()},
		{"WithRecursive", agentaudit.New(agentaudit.WithRecursive())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selectAt := func(ctx context.Context, cancelAt int, cancel context.CancelFunc) (int, []string, error) {
				var entries []treefs.Entry
				for p := range files {
					entries = append(entries, treefs.Entry{Path: p})
				}
				reads := 0
				tree, err := treefs.New(entries, func(p string) ([]byte, bool) {
					if reads++; reads == cancelAt {
						cancel()
					}
					return files[p].Data, true
				})
				if err != nil {
					t.Fatalf("treefs.New() error = %v", err)
				}
				asked, err := tc.s.SelectContext(ctx, tree)
				return reads, asked, err
			}

			total, _, err := selectAt(context.Background(), 0, nil)
			if err != nil || total < 2 {
				t.Fatalf("uncancelled SelectContext(): error = %v after %d blob read(s), want nil after several", err, total)
			}
			for n := 1; n <= total; n++ {
				ctx, cancel := context.WithCancel(context.Background())
				reads, asked, err := selectAt(ctx, n, cancel)
				cancel()
				if !errors.Is(err, context.Canceled) || asked != nil {
					t.Errorf("cancel at read %d of %d: SelectContext() = %q, %v, want nil, context.Canceled", n, total, asked, err)
				}
				if reads != n {
					t.Errorf("cancel at read %d of %d: the scan read %d blob(s), want none past the cancel", n, total, reads)
				}
			}

			ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
			defer cancel()
			if reads, asked, err := selectAt(ctx, 0, nil); !errors.Is(err, context.DeadlineExceeded) || asked != nil || reads != 0 {
				t.Errorf("passed deadline: SelectContext() = %q, %v after %d blob read(s), want nil, context.DeadlineExceeded after none", asked, err, reads)
			}
		})
	}
}
