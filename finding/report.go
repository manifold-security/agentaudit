package finding

// Report is a deduped, ordered collection of Findings. It is a value, not a
// database: construction dedupes and copies input once. Built under a cap it
// holds only the first findings, though Counts covers every one.
type Report struct {
	findings          []Finding
	omitted           int
	files, categories int
	unreadableSources int
	unparsedSources   int
	scannedAgents     []string
}

// NewReport builds a Report from findings, deduplicating by the composite of
// (Agent, ID()): the first occurrence of a given pair wins and the original
// relative order of surviving findings is preserved. Two findings sharing an
// ID() but produced by different agents both survive. A nil or empty
// findings slice produces a well-formed, empty Report.
func NewReport(findings []Finding) Report {
	b := NewReportBuilder(0)
	for _, f := range findings {
		b.Add(f)
	}
	return b.Report()
}

// WithUnreadableSources returns a copy of r recording how many distinct
// sources a scan could not read. A negative n is clamped to 0.
func (r Report) WithUnreadableSources(n int) Report {
	if n < 0 {
		n = 0
	}
	r.unreadableSources = n
	return r
}

// UnreadableSources reports how many distinct sources the scan could not
// read.
func (r Report) UnreadableSources() int {
	return r.unreadableSources
}

// WithUnparsedSources returns a copy of r recording how many distinct sources
// a scan read but could not fully parse. A negative n is clamped to 0.
func (r Report) WithUnparsedSources(n int) Report {
	if n < 0 {
		n = 0
	}
	r.unparsedSources = n
	return r
}

// UnparsedSources reports how many distinct sources the scan read but could
// not fully parse, so a capability they declared is missing from the report.
func (r Report) UnparsedSources() int {
	return r.unparsedSources
}

// WithScannedAgents returns a copy of r recording which agents the scan
// ran, in the order given.
func (r Report) WithScannedAgents(agents []string) Report {
	r.scannedAgents = copyStrings(agents)
	return r
}

// ScannedAgents reports which agents the scan ran, whether or not they
// declared anything.
func (r Report) ScannedAgents() []string {
	return copyStrings(r.scannedAgents)
}

func copyStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// Findings returns a copy of the findings the Report holds, in
// first-occurrence order.
func (r Report) Findings() []Finding {
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	return out
}

// OmittedFindings reports how many deduped findings the Report counts but
// does not hold.
func (r Report) OmittedFindings() int {
	return r.omitted
}

// HasFindings reports whether the Report contains at least one finding.
func (r Report) HasFindings() bool {
	return len(r.findings) > 0
}

// Counts summarizes a Report: the number of deduped findings, the number of
// distinct provenance files they span, and the number of distinct primary
// categories they carry (each contributes only its Categories[0], if any).
// With nothing omitted, Categories equals len(GroupByCategory()), pinned by
// TestCounts_CategoriesMatchesGroupByCategoryLength.
type Counts struct {
	Findings   int
	Files      int
	Categories int

	// UnreadableSources and UnparsedSources are carried from the Report
	// directly, not derived from findings.
	UnreadableSources int
	UnparsedSources   int
}

// Counts computes a Report's Counts over every deduped finding, held or
// omitted.
func (r Report) Counts() Counts {
	return Counts{
		Findings:          len(r.findings) + r.omitted,
		Files:             r.files,
		Categories:        r.categories,
		UnreadableSources: r.unreadableSources,
		UnparsedSources:   r.unparsedSources,
	}
}

// CategoryGroup is the neutral, unfiltered set of findings matching a
// single Category.
type CategoryGroup struct {
	Category Category
	Findings []Finding
}

// GroupByCategory groups the findings the Report holds by their primary
// category (Categories[0]), in first-appearance order; a finding with an
// empty Categories is skipped.
func (r Report) GroupByCategory() []CategoryGroup {
	return groupByCategory(r.findings)
}

func groupByCategory(findings []Finding) []CategoryGroup {
	order := make([]Category, 0)
	byCategory := make(map[Category][]Finding)
	for _, f := range findings {
		if len(f.Categories) == 0 {
			continue
		}
		c := f.Categories[0]
		if _, ok := byCategory[c]; !ok {
			order = append(order, c)
		}
		byCategory[c] = append(byCategory[c], f)
	}

	groups := make([]CategoryGroup, 0, len(order))
	for _, c := range order {
		groups = append(groups, CategoryGroup{Category: c, Findings: byCategory[c]})
	}
	return groups
}

// AgentGroup is one producing agent's findings, already grouped by category.
type AgentGroup struct {
	Agent  string
	Groups []CategoryGroup
}

// GroupByAgent groups the findings the Report holds by Agent then category,
// in first-appearance order, skipping categoryless findings and agents left
// with no group.
func (r Report) GroupByAgent() []AgentGroup {
	order := make([]string, 0)
	byAgent := make(map[string][]Finding)
	for _, f := range r.findings {
		if _, ok := byAgent[f.Agent]; !ok {
			order = append(order, f.Agent)
		}
		byAgent[f.Agent] = append(byAgent[f.Agent], f)
	}

	agentGroups := make([]AgentGroup, 0, len(order))
	for _, agent := range order {
		groups := groupByCategory(byAgent[agent])
		if len(groups) == 0 {
			continue
		}
		agentGroups = append(agentGroups, AgentGroup{Agent: agent, Groups: groups})
	}
	return agentGroups
}
