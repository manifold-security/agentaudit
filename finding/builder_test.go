package finding

import (
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// cutFindings gives each finding past the first a file and a category the
// earlier ones lack, so a cut that stops counting there undercounts both.
func cutFindings() []Finding {
	f := func(rule, file string, category Category) Finding {
		return Finding{
			RuleID:     rule,
			Agent:      "a",
			Categories: []Category{category},
			Capability: Capability{Entity: ir.EnvVar{Name: rule}, Provenance: Provenance{File: file}},
		}
	}
	return []Finding{
		f("r1", "one.json", "network"),
		f("r2", "two.json", "secrets"),
		f("r3", "three.json", "sandbox"),
	}
}

func build(n int, findings ...Finding) Report {
	b := NewReportBuilder(n)
	for _, f := range findings {
		b.Add(f)
	}
	return b.Report()
}

func TestReportBuilderHoldsTheFirstNAndCountsEveryFinding(t *testing.T) {
	all := cutFindings()
	for n := 1; n <= len(all)+1; n++ {
		r := build(n, all...)
		want := all[:min(n, len(all))]
		if got := r.Findings(); !reflect.DeepEqual(got, want) {
			t.Errorf("n=%d: Findings() = %+v, want %+v", n, got, want)
		}
		if got, want := r.OmittedFindings(), len(all)-len(want); got != want {
			t.Errorf("n=%d: OmittedFindings() = %d, want %d", n, got, want)
		}
		if got, want := r.Counts(), (Counts{Findings: 3, Files: 3, Categories: 3}); got != want {
			t.Errorf("n=%d: Counts() = %+v, want %+v", n, got, want)
		}
	}
}

func TestReportBuilderCountsADuplicateOnceAcrossTheCut(t *testing.T) {
	all := cutFindings()
	held, omitted := all[0], all[1]
	tests := []struct {
		name     string
		findings []Finding
	}{
		{"of a held finding", []Finding{held, omitted, held}},
		{"of an omitted finding", []Finding{held, omitted, omitted}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := build(1, tt.findings...)
			if got := r.Counts().Findings; got != 2 {
				t.Errorf("Counts().Findings = %d, want 2", got)
			}
			if got := r.OmittedFindings(); got != 1 {
				t.Errorf("OmittedFindings() = %d, want 1", got)
			}
		})
	}
}

func TestReportBuilderBelowOneHoldsEveryFinding(t *testing.T) {
	all := cutFindings()
	builders := map[string]*ReportBuilder{
		"n=0":        NewReportBuilder(0),
		"n=-1":       NewReportBuilder(-1),
		"zero value": {},
	}
	for name, b := range builders {
		for _, f := range all {
			b.Add(f)
		}
		r := b.Report()
		if got := r.Findings(); !reflect.DeepEqual(got, all) {
			t.Errorf("%s: Findings() = %+v, want %+v", name, got, all)
		}
		if got := r.OmittedFindings(); got != 0 {
			t.Errorf("%s: OmittedFindings() = %d, want 0", name, got)
		}
	}
}

func liveHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// Past the cut a finding's Provenance.Key is not kept, however long; the
// uncapped arm shows the heap reading sees the keys a builder holds.
func TestReportBuilderKeepsNoProvenanceKeyPastTheCut(t *testing.T) {
	const findings, keyLen = 64, 64 << 10
	grown := func(n int) uint64 {
		b := NewReportBuilder(n)
		before := liveHeap()
		for i := range findings {
			key := strings.Repeat("k", keyLen) + strconv.Itoa(i)
			b.Add(Finding{RuleID: "r", Capability: Capability{Entity: ir.EnvVar{}, Provenance: Provenance{Key: key}}})
		}
		after := liveHeap()
		runtime.KeepAlive(b)
		if after < before {
			return 0
		}
		return after - before
	}

	if held := grown(0); held < findings*keyLen {
		t.Fatalf("premise: holding every finding grew the heap %d bytes, want at least their %d key bytes", held, findings*keyLen)
	}
	const bound = keyLen + findings*1024
	if capped := grown(1); capped > bound {
		t.Fatalf("n=1: the heap grew %d bytes, want at most the held key plus 1 KiB per omitted finding, %d", capped, bound)
	}
}
