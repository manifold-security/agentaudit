package finding

import "crypto/sha256"

// findingKey is the composite dedupe key: a struct, not a joined string, so
// Go compares it field-wise and no separator choice could let a
// caller-settable Agent forge a collision. It keeps ID()'s SHA-256, not ID(),
// so a seen key costs a fixed size however long its id.
type findingKey struct {
	agent string
	id    [sha256.Size]byte
}

// ReportBuilder builds a Report as NewReport does, one finding at a time.
// Past its cap, which the zero value lacks, it counts but does not hold.
type ReportBuilder struct {
	limit      int
	held       []Finding
	omitted    int
	seen       map[findingKey]struct{}
	files      map[string]struct{}
	categories map[Category]struct{}
}

// NewReportBuilder returns a ReportBuilder that holds at most n findings;
// n <= 0 holds every one.
func NewReportBuilder(n int) *ReportBuilder {
	return &ReportBuilder{limit: n}
}

// Add records f unless a finding with its Agent and ID() came first.
func (b *ReportBuilder) Add(f Finding) {
	if b.seen == nil {
		b.seen = make(map[findingKey]struct{})
		b.files = make(map[string]struct{})
		b.categories = make(map[Category]struct{})
	}
	key := findingKey{agent: f.Agent, id: sha256.Sum256([]byte(f.ID()))}
	if _, ok := b.seen[key]; ok {
		return
	}
	b.seen[key] = struct{}{}
	b.files[f.Capability.Provenance.File] = struct{}{}
	if len(f.Categories) > 0 {
		b.categories[f.Categories[0]] = struct{}{}
	}
	if b.limit > 0 && len(b.held) >= b.limit {
		b.omitted++
		return
	}
	b.held = append(b.held, f)
}

// Report returns a Report of the findings added so far.
func (b *ReportBuilder) Report() Report {
	return Report{
		findings:   b.held,
		omitted:    b.omitted,
		files:      len(b.files),
		categories: len(b.categories),
	}
}
