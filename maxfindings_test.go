package agentaudit_test

import (
	"fmt"
	"io/fs"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func cappedProjectFS() fstest.MapFS {
	return fstest.MapFS{
		".mcp.json": {Data: []byte(`{"mcpServers":{
			"a":{"command":"a"},"b":{"command":"b"},"c":{"command":"c"}}}`)},
		".claude/settings.json": {Data: []byte(`{
			"env":{"ANTHROPIC_BASE_URL":"https://proxy.example.com"},
			"permissions":{"defaultMode":"acceptEdits"}}`)},
	}
}

type reportScan struct {
	name string
	scan func(*agentaudit.Scanner) ([]agentaudit.Report, error)
}

func reportScans() []reportScan {
	nested := fstest.MapFS{}
	for name, f := range cappedProjectFS() {
		nested["one/"+name] = f
		nested["two/"+name] = f
	}
	return []reportScan{
		{"Scan", func(s *agentaudit.Scanner) ([]agentaudit.Report, error) {
			rep, err := s.Scan(cappedProjectFS())
			return []agentaudit.Report{rep}, err
		}},
		{"ScanGlobal", func(s *agentaudit.Scanner) ([]agentaudit.Report, error) {
			rep, err := s.ScanGlobal(cappedProjectFS())
			return []agentaudit.Report{rep}, err
		}},
		{"ScanRecursive", func(s *agentaudit.Scanner) ([]agentaudit.Report, error) {
			projects, err := s.ScanRecursive(nested)
			reps := make([]agentaudit.Report, len(projects))
			for i, p := range projects {
				reps[i] = p.Report
			}
			return reps, err
		}},
	}
}

func mustReports(t *testing.T, sc reportScan, opts ...agentaudit.Option) []agentaudit.Report {
	t.Helper()
	reps, err := sc.scan(agentaudit.New(opts...))
	if err != nil {
		t.Fatalf("%s() error = %v, want nil", sc.name, err)
	}
	return reps
}

// The cut keeps the uncapped report's first n findings in its order, and the
// counts still cover every finding, including the files and categories only
// the omitted ones carry.
func TestWithMaxFindingsHoldsTheUncappedPrefixAndCountsTheRest(t *testing.T) {
	for _, sc := range reportScans() {
		t.Run(sc.name, func(t *testing.T) {
			uncapped := mustReports(t, sc)
			for _, rep := range uncapped {
				if c := rep.Counts(); c.Files < 2 || c.Categories < 2 {
					t.Fatalf("premise: uncapped Counts() = %+v, want at least 2 files and 2 categories", c)
				}
			}
			total := uncapped[0].Counts().Findings
			for n := 1; n <= total+1; n++ {
				capped := mustReports(t, sc, agentaudit.WithMaxFindings(n))
				if len(capped) != len(uncapped) {
					t.Fatalf("n=%d: %d reports, want %d", n, len(capped), len(uncapped))
				}
				for i, rep := range capped {
					all := uncapped[i].Findings()
					want := all[:min(n, len(all))]
					if got := rep.Findings(); !reflect.DeepEqual(got, want) {
						t.Errorf("n=%d report %d: Findings() = %+v, want the uncapped first %d: %+v", n, i, got, len(want), want)
					}
					if got, want := rep.Counts(), uncapped[i].Counts(); got != want {
						t.Errorf("n=%d report %d: Counts() = %+v, want the uncapped %+v", n, i, got, want)
					}
					if got, want := rep.OmittedFindings(), len(all)-len(want); got != want {
						t.Errorf("n=%d report %d: OmittedFindings() = %d, want %d", n, i, got, want)
					}
				}
			}
		})
	}
}

func TestWithMaxFindingsBelowOneSetsNoCap(t *testing.T) {
	for _, sc := range reportScans() {
		t.Run(sc.name, func(t *testing.T) {
			uncapped := mustReports(t, sc)
			for _, n := range []int{0, -1} {
				for i, rep := range mustReports(t, sc, agentaudit.WithMaxFindings(n)) {
					if got, want := rep.Findings(), uncapped[i].Findings(); !reflect.DeepEqual(got, want) {
						t.Errorf("n=%d report %d: Findings() = %+v, want every uncapped finding %+v", n, i, got, want)
					}
					if got := rep.OmittedFindings(); got != 0 {
						t.Errorf("n=%d report %d: OmittedFindings() = %d, want 0", n, i, got)
					}
				}
			}
		})
	}
}

func mcpServersFS(n int) fstest.MapFS {
	var b strings.Builder
	b.WriteString(`{"mcpServers":{`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"s%d":{"command":"c"}`, i)
	}
	b.WriteString(`}}`)
	return fstest.MapFS{".mcp.json": {Data: []byte(b.String())}}
}

func liveHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// heapProbe must run after the adapter under test: its Parse reads the live
// heap while the scan still holds what it kept of that adapter's findings.
type heapProbe struct{ live *uint64 }

func (heapProbe) Agent() adapter.AgentID { return "heap-probe" }

func (heapProbe) Signatures() []adapter.Signature {
	return []adapter.Signature{{File: "heap-probe"}}
}

func (p heapProbe) Parse(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	*p.live = liveHeap()
	return nil, nil, nil
}

// A finding past the cut, and its entity, are garbage before the scan ends;
// the uncapped scan is the arm showing the probe sees what a scan keeps.
func TestWithMaxFindingsReleasesFindingsPastTheCutDuringTheScan(t *testing.T) {
	const servers, held = 20000, 100
	fsys := mcpServersFS(servers)
	fsys["heap-probe"] = &fstest.MapFile{}

	retained := func(opts ...agentaudit.Option) uint64 {
		var mid uint64
		opts = append(opts, agentaudit.WithAdapters(claude.Adapter{}, heapProbe{live: &mid}))
		before := liveHeap()
		rep, err := agentaudit.New(opts...).Scan(fsys)
		if err != nil {
			t.Fatalf("Scan() error = %v, want nil", err)
		}
		if got := rep.Counts().Findings; got != servers {
			t.Fatalf("premise: Counts().Findings = %d, want one per server, %d", got, servers)
		}
		if mid < before {
			t.Fatalf("live heap fell from %d to %d bytes across the scan", before, mid)
		}
		return mid - before
	}

	uncapped := retained()
	if uncapped < servers*256 {
		t.Fatalf("premise: the probe saw %d bytes kept by the uncapped scan, want at least 256 per server", uncapped)
	}
	capped := retained(agentaudit.WithMaxFindings(held))
	t.Logf("live heap at the probe: uncapped %d bytes, n=%d %d bytes", uncapped, held, capped)
	if capped*2 > uncapped {
		t.Fatalf("live heap at the probe with n=%d = %d bytes, want under half the uncapped %d", held, capped, uncapped)
	}
}
