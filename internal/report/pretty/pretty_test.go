package pretty

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/report/reportfixture"
)

var update = flag.Bool("update", false, "update golden files")

func TestWrite_Golden(t *testing.T) {
	const goldenPath = "testdata/pretty.golden"

	var buf bytes.Buffer
	if err := Write(&buf, reportfixture.Report(), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	if *update {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if buf.String() != string(want) {
		t.Fatalf("Write() output mismatch\n--- got ---\n%s\n--- want ---\n%s", buf.String(), string(want))
	}
}

func TestWrite_FooterSingularCounts(t *testing.T) {
	f := finding.Finding{
		RuleID:     "solo.rule",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "1 capability · 1 file · 1 category\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain footer %q", buf.String(), want)
	}
}

func TestWrite_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport(nil), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if !strings.Contains(got, "no known agent config read\n") {
		t.Fatalf("Write() empty report = %q, want it to contain \"no known agent config read\"", got)
	}
	if strings.Contains(got, "no capabilities found") {
		t.Fatalf("Write() empty report = %q, must not claim a scanned agent declared nothing when none ran", got)
	}
	if !strings.Contains(got, "0 capabilities · 0 files · 0 categories") {
		t.Fatalf("Write() empty report = %q, want zero-count footer", got)
	}
	if agentHeadingRe.MatchString(got) {
		t.Fatalf("Write() empty report = %q, want no agent heading (nothing produced anything to attribute)", got)
	}
}

// An empty report names the agents the scan ran, in the order given, so a
// scanned-but-silent configuration does not read like a tree holding none.
func TestWrite_EmptyReportNamesTheScannedAgents(t *testing.T) {
	tests := []struct {
		name   string
		agents []string
		want   string
	}{
		{"one agent", []string{"claude-code"}, "no capabilities found (scanned: claude-code)\n"},
		{"two agents", []string{"cursor", "claude-code"}, "no capabilities found (scanned: cursor, claude-code)\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, finding.NewReport(nil).WithScannedAgents(tt.agents), Meta{Path: "."}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			if got := buf.String(); !strings.Contains(got, tt.want) {
				t.Fatalf("Write() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// A hostile agent id reaches the clause with its control byte and its
// middle dot both spelled out.
func TestWrite_EmptyReportEscapesAScannedAgentName(t *testing.T) {
	hostile := "ev\x00il · x"

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport(nil).WithScannedAgents([]string{hostile}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if strings.Contains(got, hostile) {
		t.Fatalf("Write() = %q, want the hostile agent name neutralised", got)
	}
	if !strings.Contains(got, `no capabilities found (scanned: ev\\x00il \u00b7 x)`) {
		t.Fatalf("Write() = %q, want the control byte and the separator both spelled out", got)
	}
}

// A degraded empty report carries SCAN INCOMPLETE alone; the scanned-agent
// clause belongs to the branch that claims a clean read.
func TestWrite_DegradedEmptyReportOmitsTheScannedClause(t *testing.T) {
	r := finding.NewReport(nil).
		WithUnreadableSources(1).
		WithScannedAgents([]string{"claude-code"})

	var buf bytes.Buffer
	if err := Write(&buf, r, Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if !strings.Contains(got, "SCAN INCOMPLETE") {
		t.Fatalf("Write() = %q, want the degraded clause", got)
	}
	if strings.Contains(got, "scanned:") {
		t.Fatalf("Write() = %q, want no scanned-agent clause on a degraded report", got)
	}
}

func TestWrite_EmptyReportDegraded(t *testing.T) {
	const goldenPath = "testdata/pretty_degraded_empty.golden"
	const unreadableSources = 3
	const unparsedSources = 2

	r := finding.NewReport(nil).
		WithUnreadableSources(unreadableSources).
		WithUnparsedSources(unparsedSources)

	var buf bytes.Buffer
	if err := Write(&buf, r, Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if strings.Contains(got, "no capabilities found") || strings.Contains(got, "no known agent config read") {
		t.Fatalf("Write() degraded empty report = %q, must carry neither clean claim", got)
	}
	lines := strings.SplitN(got, "\n", 3)
	if len(lines) < 3 || !strings.HasPrefix(lines[2], "SCAN INCOMPLETE") {
		t.Fatalf("Write() degraded empty report = %q, want the first body line to start with \"SCAN INCOMPLETE\"", got)
	}

	if *update {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if got != string(want) {
		t.Fatalf("Write() output mismatch\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
	if agentHeadingRe.MatchString(got) {
		t.Fatalf("Write() degraded empty report = %q, want no agent heading", got)
	}
}

// Each degradation shape appends its own SCAN INCOMPLETE clause and footer
// suffix to the byte-identical clean render, so neither count can be read off
// the other and a zero one contributes nothing.
func TestWrite_DegradedFooterOnFindingsReport(t *testing.T) {
	tests := []struct {
		name             string
		report           finding.Report
		wantIncomplete   string
		wantFooterSuffix string
	}{
		{
			name:             "unreadable only",
			report:           reportfixture.Report().WithUnreadableSources(2),
			wantIncomplete:   "2 sources could not be read",
			wantFooterSuffix: " · 2 unreadable sources",
		},
		{
			name:             "unparsed only",
			report:           reportfixture.Report().WithUnparsedSources(1),
			wantIncomplete:   "1 source could not be parsed",
			wantFooterSuffix: " · 1 unparsed source",
		},
		{
			name:             "both",
			report:           reportfixture.Report().WithUnreadableSources(2).WithUnparsedSources(1),
			wantIncomplete:   "2 sources could not be read and 1 source could not be parsed",
			wantFooterSuffix: " · 2 unreadable sources · 1 unparsed source",
		},
	}

	var clean bytes.Buffer
	if err := Write(&clean, reportfixture.Report(), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() clean error = %v, want nil", err)
	}
	cleanStr := clean.String()
	cleanLines := strings.Split(strings.TrimSuffix(cleanStr, "\n"), "\n")
	footer := cleanLines[len(cleanLines)-1]
	body := strings.TrimSuffix(cleanStr, footer+"\n")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var degraded bytes.Buffer
			if err := Write(&degraded, tt.report, Meta{Path: "."}); err != nil {
				t.Fatalf("Write() degraded error = %v, want nil", err)
			}

			want := body +
				fmt.Sprintf("SCAN INCOMPLETE: %s (see stderr); capabilities may be missing\n", tt.wantIncomplete) +
				footer + tt.wantFooterSuffix + "\n"

			if degraded.String() != want {
				t.Fatalf("Write() degraded findings report mismatch\n--- got ---\n%s\n--- want ---\n%s", degraded.String(), want)
			}
		})
	}
}

// A scan that read every source but discarded what one of them declared is
// degraded too: it must not claim the tree holds no capabilities.
func TestWrite_UnparsedOnlyDegradationSuppressesNoCapabilitiesFound(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport(nil).WithUnparsedSources(1), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if strings.Contains(got, "no capabilities found") || strings.Contains(got, "no known agent config read") {
		t.Fatalf("Write() = %q, must carry neither clean claim when a source went unparsed", got)
	}
	if !strings.Contains(got, "SCAN INCOMPLETE: 1 source could not be parsed") {
		t.Fatalf("Write() = %q, want the unparsed SCAN INCOMPLETE line", got)
	}
	if !strings.Contains(got, "· 1 unparsed source\n") {
		t.Fatalf("Write() = %q, want the unparsed footer suffix", got)
	}
	if strings.Contains(got, "unreadable source") {
		t.Fatalf("Write() = %q, want no unreadable-source text for an unparsed-only degradation", got)
	}
}

// Report.GroupByCategory documents single-group placement: a
// multi-category finding renders once, under its first category only, and
// its secondary category must produce no group and no duplicate line.
func TestWrite_MultiCategoryFindingRendersOnceUnderPrimaryCategory(t *testing.T) {
	f := finding.Finding{
		RuleID:     "combo.rule",
		Categories: []finding.Category{"secrets", "network"},
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "TOKEN_URL", Value: "https://tok.example.com"},
			Provenance: finding.Provenance{File: "config.json", Key: "env.TOKEN_URL"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	occurrences := strings.Count(got, "envVar TOKEN_URL")
	if occurrences != 1 {
		t.Fatalf("Write() rendered the multi-category finding %d times, want 1 (once, under its primary category only)\noutput:\n%s", occurrences, got)
	}
	if !strings.Contains(got, "secrets:\n  envVar TOKEN_URL") {
		t.Fatalf("Write() = %q, want the finding rendered under its primary category \"secrets\"", got)
	}
	if strings.Contains(got, "network:") {
		t.Fatalf("Write() = %q, want no \"network:\" group at all — the finding's secondary category must not produce a group", got)
	}
}

func TestWrite_ProvenanceKeyHandling(t *testing.T) {
	withKey := finding.Finding{
		RuleID:     "with.key",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "with-key-skill"},
			Provenance: finding.Provenance{File: "a.json", Key: "skills[0]"},
		},
	}
	withoutKey := finding.Finding{
		RuleID:     "without.key",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "without-key-skill"},
			Provenance: finding.Provenance{File: "b.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{withKey, withoutKey}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	got := buf.String()
	if !strings.Contains(got, "a.json:skills[0]") {
		t.Fatalf("Write() = %q, want it to contain \"a.json:skills[0]\" for the Key-set provenance", got)
	}
	if !strings.Contains(got, "b.json\n") {
		t.Fatalf("Write() = %q, want a bare \"b.json\" line for the Key-empty provenance", got)
	}
	if strings.Contains(got, "b.json:") {
		t.Fatalf("Write() = %q, want no \":\" suffix on the Key-empty provenance's file", got)
	}
}

// The pretty surface is plain text: no ANSI escape byte appears on either
// view. Explain:true is covered so the follow-on line sits under the guard
// too.
func TestWrite_NoANSIEscapeCodes(t *testing.T) {
	for _, explain := range []bool{false, true} {
		var buf bytes.Buffer
		if err := Write(&buf, reportfixture.Report(), Meta{Path: ".", Explain: explain}); err != nil {
			t.Fatalf("Write() error = %v, want nil", err)
		}
		if strings.ContainsRune(buf.String(), '\x1b') {
			t.Fatalf("Write() output contains an ANSI escape byte, want plain text only (Explain=%v)", explain)
		}
	}
}

// A separate golden keeps the default view's byte-identity usable as a
// regression proof.
func TestWrite_ExplainGolden(t *testing.T) {
	const goldenPath = "testdata/pretty_explain.golden"

	var buf bytes.Buffer
	if err := Write(&buf, reportfixture.Report(), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	if *update {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if buf.String() != string(want) {
		t.Fatalf("Write() explain output mismatch\n--- got ---\n%s\n--- want ---\n%s", buf.String(), string(want))
	}
}

func TestWrite_ExplainOmittedByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, reportfixture.Report(), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if strings.Contains(buf.String(), "—") {
		t.Fatalf("Write() = %q, want no em dash (follow-on line marker) when Explain is false", buf.String())
	}
}

func TestWrite_ExplainLine_EmptyReferencesNoDanglingSeparator(t *testing.T) {
	f := finding.Finding{
		RuleID:     "solo.rule",
		Categories: []finding.Category{"discovery"},
		Message:    "a lone message",
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "    solo.rule — a lone message\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain %q", buf.String(), want)
	}
}

func TestWrite_ExplainLine_EmptyMessageSkipsSegment(t *testing.T) {
	f := finding.Finding{
		RuleID:     "refs.only",
		Categories: []finding.Category{"discovery"},
		References: []string{"https://example.com/docs"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "    refs.only — https://example.com/docs\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain %q", buf.String(), want)
	}
}

func TestWrite_ExplainLine_MultipleReferencesJoined(t *testing.T) {
	f := finding.Finding{
		RuleID:     "multi.ref",
		Categories: []finding.Category{"discovery"},
		Message:    "two references",
		References: []string{"https://a.example.com", "https://b.example.com"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "    multi.ref — two references — https://a.example.com; https://b.example.com\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain %q", buf.String(), want)
	}
}

func renderExplainMessage(t *testing.T, message string) string {
	t.Helper()
	f := finding.Finding{
		RuleID:     "hazard.rule",
		Categories: []finding.Category{"discovery"},
		Message:    message,
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}
	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	return buf.String()
}

// A hazard byte in a rule message must not fabricate what reads as an extra
// finding: each case's line count is compared against an actual hazard-free
// control render of the same shape, not a hardcoded constant that could
// drift silently out of sync with Write's real output.
func TestWrite_ExplainLine_EscapesLineBreakBytes(t *testing.T) {
	wantLines := strings.Count(renderExplainMessage(t, "first second"), "\n")

	tests := []struct {
		name    string
		message string
		want    string // the exact escaped spelling, authored independently of report.Escape
	}{
		{"lone CR", "first\rsecond", `first\rsecond`},
		{"CRLF", "first\r\nsecond", `first\r\nsecond`},
		{"lone LF", "first\nsecond", `first\nsecond`},
		{"line separator", "first\u2028second", `first\u2028second`},
		{"paragraph separator", "first\u2029second", `first\u2029second`},
		{"vertical tab", "first\vsecond", `first\vsecond`},
		{"form feed", "first\fsecond", `first\fsecond`},
		{"next line", "first\u0085second", `first\u0085second`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderExplainMessage(t, tt.message)
			if gotLines := strings.Count(got, "\n"); gotLines != wantLines {
				t.Fatalf("Write() line count = %d, want %d (no extra line introduced by the hazard byte)", gotLines, wantLines)
			}
			if strings.Contains(got, "first second") {
				t.Fatalf("Write() = %q, want the hazard byte escaped rather than folded to a space", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("Write() = %q, want it to contain the escaped spelling %q, not a byte dropped in place", got, tt.want)
			}
		})
	}
}

func TestWrite_ExplainLine_EscapesRuleIDLineBreak(t *testing.T) {
	f := finding.Finding{
		RuleID:     "hazard\nrule",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "    hazard\\nrule\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain %q", buf.String(), want)
	}
}

// Each References element is escaped independently, not just the joined
// result.
func TestWrite_ExplainLine_EscapesReferenceLineBreak(t *testing.T) {
	f := finding.Finding{
		RuleID:     "refs.hazard",
		Categories: []finding.Category{"discovery"},
		References: []string{"https://a.example.com\nhazard", "https://b.example.com"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: ".", Explain: true}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "    refs.hazard — https://a.example.com\\nhazard; https://b.example.com\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain %q", buf.String(), want)
	}
}

// meta.Path can carry a project directory name from the scanned tree under
// -r, so a hazard byte there must not fabricate a second block header.
func TestWrite_Header_EscapesHazardPath(t *testing.T) {
	var buf bytes.Buffer
	meta := Meta{Path: "target\x1b[2Jdir"}
	if err := Write(&buf, finding.NewReport(nil), meta); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("Write() = %q, want the header path escaped", got)
	}
	if got := strings.Count(got, "agentaudit ·"); got != 1 {
		t.Fatalf("Write() has %d block headers, want exactly 1", got)
	}
}

// Finding.Agent is a library-supplied string, not scanned-tree input, but the
// agent heading routes through the same escaping authority as every other
// rendered field.
func TestWrite_AgentHeading_EscapesHazardAgent(t *testing.T) {
	f := finding.Finding{
		RuleID:     "hazard.rule",
		Agent:      "claude\x1b[2Jcode",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("Write() = %q, want the agent heading escaped", got)
	}
	if !strings.Contains(got, `\x1b[2J`) {
		t.Fatalf("Write() = %q, want it to contain the escaped hazard spelling", got)
	}
	if got := len(agentHeadingRe.FindAllString(got, -1)); got != 1 {
		t.Fatalf("Write() has %d agent headings, want exactly 1", got)
	}
}

// report.Escape neutralises the agent heading's control bytes before
// categoryHeadingRe ever sees the line, so an embedded newline cannot forge
// a line matching a category heading's shape; dropping that Escape call is
// exactly the mutation this test is built to catch.
func TestWrite_AgentHeading_HazardCannotFabricateAnExtraHeadingLine(t *testing.T) {
	control := finding.Finding{
		RuleID:     "control.rule",
		Agent:      "a",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}
	hostile := finding.Finding{
		RuleID:     "hostile.rule",
		Agent:      "a\ncode-execution:\nz",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var controlBuf, hostileBuf bytes.Buffer
	if err := Write(&controlBuf, finding.NewReport([]finding.Finding{control}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() control error = %v, want nil", err)
	}
	if err := Write(&hostileBuf, finding.NewReport([]finding.Finding{hostile}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() hostile error = %v, want nil", err)
	}

	wantHeadings := len(categoryHeadingRe.FindAllString(controlBuf.String(), -1))
	if got := len(categoryHeadingRe.FindAllString(hostileBuf.String(), -1)); got != wantHeadings {
		t.Fatalf("Write() hostile agent produced %d category-shaped headings, want %d (no extra heading fabricated)\noutput:\n%s", got, wantHeadings, hostileBuf.String())
	}
}

// group.Category is rule-authored, but the writer escapes it uniformly with
// every other rendered field rather than trusting the wiring that supplies
// it.
func TestWrite_GroupHeading_EscapesHazardCategory(t *testing.T) {
	f := finding.Finding{
		RuleID:     "hazard.heading",
		Categories: []finding.Category{"probe\x1b[2Jforged"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if strings.ContainsRune(got, '\x1b') {
		t.Fatalf("Write() = %q, want the group heading escaped", got)
	}
	if got := strings.Count(got, ":\n"); got != 1 {
		t.Fatalf("Write() has %d group headings, want exactly 1", got)
	}
}

// findingWithHazard builds a finding whose Describe what (via the entity
// name), Describe value, Provenance.File and Provenance.Key all carry the
// embedded hazard string, so a single row exercises every argument
// writeFindingLine passes to Fprintf.
func findingWithHazard(embedded string) finding.Finding {
	return finding.Finding{
		RuleID:     "hazard.rule",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "PROBE" + embedded, Value: embedded},
			Provenance: finding.Provenance{File: "probe" + embedded + ".json", Key: "k" + embedded},
		},
	}
}

func renderFinding(t *testing.T, f finding.Finding) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	return buf.String()
}

// A hazard byte reaching writeFindingLine's what, value, Provenance.File or
// Provenance.Key must not fabricate an extra line, and must render as a
// visible escape rather than a raw byte or a silently folded space.
func TestWrite_FindingLine_EscapesHazardBytes(t *testing.T) {
	wantLines := strings.Count(renderFinding(t, findingWithHazard("x SAFE y")), "\n")

	// checkNoRawRune is false only for a hazard the output legitimately
	// contains elsewhere as ordinary formatting (a line feed separates every
	// rendered line), so its absence is proven by the line-count invariant
	// instead of a direct search. wantEscaped is authored independently of
	// report.Escape, so this table cannot pass by construction.
	tests := []struct {
		name           string
		hazardRune     rune
		hazard         string
		checkNoRawRune bool
		wantEscaped    string
	}{
		{"line feed", '\n', "x\ny", false, `\n`},
		{"ANSI erase-display", '\x1b', "x\x1b[2Jy", true, `\x1b`},
		{"tab", '\t', "x\ty", true, `\t`},
		{"vertical tab", '\v', "x\vy", true, `\v`},
		{"right-to-left override", '\u202e', "x\u202ey", true, `\u202e`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderFinding(t, findingWithHazard(tt.hazard))

			if gotLines := strings.Count(got, "\n"); gotLines != wantLines {
				t.Fatalf("Write() line count = %d, want %d (no extra line from the hazard byte)\noutput:\n%s", gotLines, wantLines, got)
			}
			if tt.checkNoRawRune && strings.ContainsRune(got, tt.hazardRune) {
				t.Fatalf("Write() output contains the raw hazard rune %U, want it escaped\noutput:\n%s", tt.hazardRune, got)
			}
			if !strings.Contains(got, tt.wantEscaped) {
				t.Fatalf("Write() = %q, want it to contain the escaped spelling %q", got, tt.wantEscaped)
			}
		})
	}
}

// A lone invalid byte cannot be expressed as a Go rune, so it gets its own
// test rather than a table row shared with the rune-keyed cases above.
func TestWrite_FindingLine_EscapesInvalidUTF8Byte(t *testing.T) {
	wantLines := strings.Count(renderFinding(t, findingWithHazard("x SAFE y")), "\n")

	hazard := "x" + string([]byte{0x80}) + "y"
	got := renderFinding(t, findingWithHazard(hazard))

	if gotLines := strings.Count(got, "\n"); gotLines != wantLines {
		t.Fatalf("Write() line count = %d, want %d (no extra line from the hazard byte)\noutput:\n%s", gotLines, wantLines, got)
	}
	if strings.Contains(got, string([]byte{0x80})) {
		t.Fatalf("Write() output contains the raw invalid byte, want it escaped\noutput:\n%s", got)
	}
	if !strings.Contains(got, `\x80`) {
		t.Fatalf("Write() = %q, want it to contain the escaped spelling %q", got, `\x80`)
	}
}

// A hazard shaped like a genuine finding line (leading two spaces, a
// middot-separated triple) must still render as part of the ONE finding it
// belongs to: no extra line may match the finding-line shape.
var findingLineShape = regexp.MustCompile(`(?m)^  [^\n]+ \x{00B7} [^\n]+ \x{00B7} [^\n]+$`)

// findingWithHazard embeds the same forgery text into what, value, file and
// key at once, so this does not isolate a what-only regression: escaping
// what alone already keeps the still-escaped value and file segments from
// completing the shape below on their own line. A what-only regression is
// still caught, independently, by
// TestWrite_HazardousReport_NoRawEscapeByteOnEitherView, whose what call site
// carries the hazard across most of HazardousReport's findings.
func TestWrite_FindingLine_ForgeryShapeCannotFabricateASecondFindingLine(t *testing.T) {
	forgery := "real\n  forgedWhat · forgedValue · forged/file.json"
	got := renderFinding(t, findingWithHazard(forgery))

	if matches := findingLineShape.FindAllString(got, -1); len(matches) != 1 {
		t.Fatalf("Write() produced %d lines matching the finding-line shape, want exactly 1\noutput:\n%s", len(matches), got)
	}
}

// Write never branches on provenance shape, so a hook declared in
// settings.json and one declared in frontmatter must render identically.
func TestWrite_HookRenderingIdenticalAcrossProvenance(t *testing.T) {
	entity := ir.Hook{Event: "PreToolUse", Matcher: "Bash", Command: "audit.sh"}
	const key = "hooks.PreToolUse[0].hooks[0]"

	settingsFinding := finding.Finding{
		RuleID:     "claude.hook.command",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{
			Entity:     entity,
			Provenance: finding.Provenance{File: ".claude/settings.json", Key: key},
		},
	}
	frontmatterFinding := finding.Finding{
		RuleID:     "claude.hook.command",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{
			Entity:     entity,
			Provenance: finding.Provenance{File: ".claude/skills/foo/SKILL.md", Key: key},
		},
	}

	var settingsBuf, frontmatterBuf bytes.Buffer
	if err := Write(&settingsBuf, finding.NewReport([]finding.Finding{settingsFinding}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() settings-sourced error = %v, want nil", err)
	}
	if err := Write(&frontmatterBuf, finding.NewReport([]finding.Finding{frontmatterFinding}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() frontmatter-sourced error = %v, want nil", err)
	}

	got := frontmatterBuf.String()
	want := strings.ReplaceAll(settingsBuf.String(), ".claude/settings.json", ".claude/skills/foo/SKILL.md")
	if got != want {
		t.Fatalf("rendering differs by more than provenance\n--- settings-sourced (file-substituted, want) ---\n%s\n--- frontmatter-sourced (got) ---\n%s", want, got)
	}
}

var findingIndentRe = regexp.MustCompile(`(?m)^  \S`)

var agentHeadingRe = regexp.MustCompile(`(?m)^\(`)
var categoryHeadingRe = regexp.MustCompile(`(?m)^[^ (\n]+:$`)

func TestWrite_GroupsFindingsByProducingAgent(t *testing.T) {
	claude := finding.Finding{
		RuleID:     "claude.rule",
		Agent:      "claude-code",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "claude-skill"}, Provenance: finding.Provenance{File: "a.json"}},
	}
	cursor := finding.Finding{
		RuleID:     "cursor.rule",
		Agent:      "cursor",
		Categories: []finding.Category{"network"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "cursor-skill"}, Provenance: finding.Provenance{File: "b.json"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{claude, cursor}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	claudeHeadingRe := regexp.MustCompile(`(?m)^\(claude-code\)$`)
	cursorHeadingRe := regexp.MustCompile(`(?m)^\(cursor\)$`)
	if n := len(claudeHeadingRe.FindAllString(got, -1)); n != 1 {
		t.Fatalf("Write() = %q, want exactly one \"(claude-code)\" heading", got)
	}
	if n := len(cursorHeadingRe.FindAllString(got, -1)); n != 1 {
		t.Fatalf("Write() = %q, want exactly one \"(cursor)\" heading", got)
	}
	if !strings.Contains(got, "(claude-code)\ncode-execution:") {
		t.Fatalf("Write() = %q, want \"(claude-code)\" immediately followed by its category heading", got)
	}
	if !strings.Contains(got, "(cursor)\nnetwork:") {
		t.Fatalf("Write() = %q, want \"(cursor)\" immediately followed by its category heading", got)
	}
}

func TestWrite_AgentHeadingPrecedesItsCategoryHeadingAtTheSameIndent(t *testing.T) {
	f := finding.Finding{
		RuleID:     "solo.rule",
		Agent:      "claude-code",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	agentLines := agentHeadingRe.FindAllString(got, -1)
	categoryLines := categoryHeadingRe.FindAllString(got, -1)
	if len(agentLines) != 1 || len(categoryLines) != 1 {
		t.Fatalf("Write() = %q, want exactly one agent heading and one category heading, got %d and %d", got, len(agentLines), len(categoryLines))
	}
	if strings.Index(got, agentLines[0]) > strings.Index(got, categoryLines[0]) {
		t.Fatalf("Write() = %q, want the agent heading before the category heading", got)
	}
	if gotFindingLines := len(findingIndentRe.FindAllString(got, -1)); gotFindingLines != 1 {
		t.Fatalf("Write() has %d finding-indent lines, want 1 (no finding line was re-indented)", gotFindingLines)
	}
}

func TestWrite_SingleAgentStillRendersTheGroupedForm(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, reportfixture.Report(), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if got := len(agentHeadingRe.FindAllString(got, -1)); got != 1 {
		t.Fatalf("Write() has %d agent headings, want exactly 1", got)
	}
}

func TestWrite_EmptyAgentRendersEmptyParentheses(t *testing.T) {
	f := finding.Finding{
		RuleID:     "noagent.rule",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if !strings.Contains(got, "()\n") {
		t.Fatalf("Write() = %q, want an empty-parentheses heading for an empty Agent", got)
	}
}

func TestWrite_FooterCategoryCountStaysWholeReport(t *testing.T) {
	claude := finding.Finding{
		RuleID:     "claude.rule",
		Agent:      "claude-code",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "claude-skill"}, Provenance: finding.Provenance{File: "shared.json"}},
	}
	cursor := finding.Finding{
		RuleID:     "cursor.rule",
		Agent:      "cursor",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "cursor-skill"}, Provenance: finding.Provenance{File: "shared.json"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{claude, cursor}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if got := strings.Count(got, "code-execution:"); got != 2 {
		t.Fatalf("Write() has %d \"code-execution:\" headings, want 2 (one per agent sharing the category)", got)
	}
	if !strings.Contains(got, "2 capabilities · 1 file · 1 category") {
		t.Fatalf("Write() = %q, want footer \"2 capabilities · 1 file · 1 category\"", got)
	}
}

func TestWrite_AllCategorylessFindingsRenderNoAgentHeading(t *testing.T) {
	f := finding.Finding{
		RuleID: "nocategory.rule",
		Agent:  "claude-code",
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport([]finding.Finding{f}), Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	got := buf.String()

	if agentHeadingRe.MatchString(got) {
		t.Fatalf("Write() = %q, want no agent heading when every finding is categoryless", got)
	}
	if !strings.Contains(got, "1 capability · 1 file · 0 categories") {
		t.Fatalf("Write() = %q, want footer \"1 capability · 1 file · 0 categories\"", got)
	}
}

// The header (meta.Path) and group heading (group.Category) call sites are
// pinned separately by TestWrite_Header_EscapesHazardPath and
// TestWrite_GroupHeading_EscapesHazardCategory.
func TestWrite_HazardousReport_NoRawEscapeByteOnEitherView(t *testing.T) {
	wantLines := reportfixture.HazardousReport().Counts().Findings

	for _, explain := range []bool{false, true} {
		var buf bytes.Buffer
		if err := Write(&buf, reportfixture.HazardousReport(), Meta{Path: ".", Explain: explain}); err != nil {
			t.Fatalf("Write() error = %v, want nil (Explain=%v)", err, explain)
		}
		got := buf.String()

		if gotLines := len(findingIndentRe.FindAllString(got, -1)); gotLines != wantLines {
			t.Fatalf("Write() rendered %d finding lines, want %d (Explain=%v)\noutput:\n%s", gotLines, wantLines, explain, got)
		}
		if !strings.Contains(got, `\x1b[2J`) {
			t.Fatalf("Write() = %q, want it to contain the escaped hazard spelling (Explain=%v)", got, explain)
		}
		if strings.ContainsRune(got, '\x1b') {
			t.Fatalf("Write() output contains a raw ESC byte, want it escaped everywhere (Explain=%v)\noutput:\n%s", explain, got)
		}
	}
}

var hostileMCPArgs = []string{
	"ARGPAYLOAD · forged · column",
	"ARGPAYLOAD\nsecond line",
	`ARGPAYLOAD" quoted`,
}

// The vector follows the command inside the value column, and the hazards
// its elements carry render escaped, so the line keeps its two column
// separators.
func TestWrite_FindingLine_MCPServerArgsFollowTheCommandWithoutForgingAColumn(t *testing.T) {
	got := renderFinding(t, finding.Finding{
		RuleID:     "mcp.stdio",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{
			Entity:     ir.MCPServer{Name: "srv", Transport: ir.TransportStdio, Command: "npx", Args: hostileMCPArgs},
			Provenance: finding.Provenance{File: ".mcp.json", Key: "mcpServers.srv"},
		},
	})

	matches := findingLineShape.FindAllString(got, -1)
	if len(matches) != 1 {
		t.Fatalf("Write() produced %d lines matching the finding-line shape, want exactly 1\noutput:\n%s", len(matches), got)
	}
	if n := strings.Count(matches[0], " · "); n != 2 {
		t.Fatalf("finding line %q holds %d column separators, want 2", matches[0], n)
	}
	want := `  mcpServer srv (stdio) · npx "ARGPAYLOAD \u00b7 forged \u00b7 column" "ARGPAYLOAD\\nsecond line" "ARGPAYLOAD\\" quoted" · .mcp.json:mcpServers.srv`
	if matches[0] != want {
		t.Fatalf("finding line =\n%q\nwant\n%q", matches[0], want)
	}
}

func TestWrite_FindingLine_LSPServerArgsFollowTheCommand(t *testing.T) {
	got := renderFinding(t, finding.Finding{
		RuleID:     "lsp.server",
		Categories: []finding.Category{"code-execution"},
		Capability: finding.Capability{
			Entity:     ir.LSPServer{Name: "go", Command: "gopls", Args: []string{"serve", "--listen addr · x"}},
			Provenance: finding.Provenance{File: ".lsp.json", Key: "go"},
		},
	})

	want := `  lspServer go · gopls serve "--listen addr \u00b7 x" · .lsp.json:go`
	if line := soleFindingLine(t, got); line != want {
		t.Fatalf("finding line =\n%q\nwant\n%q", line, want)
	}
}

// Distinct command lines must render distinct lines, including pairs that
// differ only in where an element boundary falls or in how a byte is spelled.
func TestWrite_FindingLine_DistinctCommandLinesRenderDistinctLines(t *testing.T) {
	mcp := func(command string, args ...string) ir.Entity {
		return ir.MCPServer{Name: "srv", Transport: ir.TransportStdio, Command: command, Args: args}
	}
	lsp := func(command string, args ...string) ir.Entity {
		return ir.LSPServer{Name: "srv", Command: command, Args: args}
	}
	entities := map[string]ir.Entity{
		"none":                            mcp("npx"),
		"one empty":                       mcp("npx", ""),
		"two empty":                       mcp("npx", "", ""),
		"joined":                          mcp("npx", "-y pkg"),
		"split":                           mcp("npx", "-y", "pkg"),
		"literal quotes":                  mcp("npx", `"-y pkg"`),
		"trailing backslash":              mcp("npx", `a\`, "b"),
		"escaped space":                   mcp("npx", `a\ b`),
		"raw control byte":                mcp("npx", "\x1b"),
		"literal control spelling":        mcp("npx", `\x1b`),
		"raw separator":                   mcp("npx", "·"),
		"literal separator spelling":      mcp("npx", `\u00b7`),
		"raw line feed":                   mcp("npx", "a\nb"),
		"literal line feed":               mcp("npx", `a\nb`),
		"quote then bare":                 mcp("npx", `a"`, "b"),
		"quote and space":                 mcp("npx", `a" b`),
		"command holds the arg":           mcp("npx -y"),
		"arg after the command":           mcp("npx", "-y"),
		"command holds the first arg":     mcp("npx mcp-fs", "-y"),
		"both args after the command":     mcp("npx", "mcp-fs", "-y"),
		"command with a quote":            mcp(`npx"`, "b"),
		"quoted arg with a quote":         mcp("npx", `" b`),
		"command with a backslash":        mcp(`C:\srv`, "x"),
		"command with a raw control byte": mcp("npx\x1b"),
		"command with a literal spelling": mcp(`npx\x1b`),
		"lsp command holds the arg":       lsp("gopls serve"),
		"lsp arg after the command":       lsp("gopls", "serve"),
		"lsp command holds the first arg": lsp("go pls", "serve"),
		"lsp both args after the command": lsp("go", "pls", "serve"),
		"literal empty quotes":            mcp("npx", `""`),
		"hangul filler between":           mcp("npx", "-y\u3164pkg"),
		"zero-width space between":        mcp("npx", "-y\u200bpkg"),
	}
	seen := map[string]string{}
	for name, entity := range entities {
		got := renderFinding(t, finding.Finding{
			RuleID:     "mcp.stdio",
			Categories: []finding.Category{"code-execution"},
			Capability: finding.Capability{
				Entity:     entity,
				Provenance: finding.Provenance{File: ".mcp.json", Key: "mcpServers.srv"},
			},
		})
		line := soleFindingLine(t, got)
		if other, ok := seen[line]; ok {
			t.Errorf("entities %q and %q both render %q", other, name, line)
		}
		seen[line] = name
	}
}

func TestWrite_FindingLine_InvisibleOrBlankRunesForceQuoting(t *testing.T) {
	for _, r := range []rune{
		'\u200b', '\u200d', '\ufeff', '\u3164', '\u2800', '\u115f', '\u1160', '\uffa0',
		'\u034f', '\u17b4', '\u180b', '\ufe0f', '\U000e0100', '\ufffc',
	} {
		t.Run(fmt.Sprintf("%U", r), func(t *testing.T) {
			got := renderFinding(t, finding.Finding{
				RuleID:     "mcp.stdio",
				Categories: []finding.Category{"code-execution"},
				Capability: finding.Capability{
					Entity:     ir.MCPServer{Name: "srv", Transport: ir.TransportStdio, Command: "npx", Args: []string{"-y" + string(r) + "pkg"}},
					Provenance: finding.Provenance{File: ".mcp.json", Key: "mcpServers.srv"},
				},
			})
			want := `  mcpServer srv (stdio) · npx "-y` + string(r) + `pkg" · .mcp.json:mcpServers.srv`
			if line := soleFindingLine(t, got); line != want {
				t.Fatalf("finding line =\n%q\nwant\n%q", line, want)
			}
		})
	}
}

func findingLines(out string) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if findingIndentRe.MatchString(line) {
			lines = append(lines, line)
		}
	}
	return lines
}

// soleFindingLine fails unless exactly one finding line was rendered, so a
// column assertion below cannot read a forged row as the genuine one.
func soleFindingLine(t *testing.T, out string) string {
	t.Helper()
	lines := findingLines(out)
	if len(lines) != 1 {
		t.Fatalf("Write() produced %d finding lines, want exactly 1\noutput:\n%s", len(lines), out)
	}
	return lines[0]
}

// The finding line's own " · " separator is reachable from every scanned
// field it renders, so a name spelling one would close the row early and
// leave the real value reading as text past what looks like a complete,
// benign record.
func TestWrite_FindingLine_MiddleDotCannotForgeAColumn(t *testing.T) {
	got := renderFinding(t, findingWithHazard("x · y·z"))
	line := soleFindingLine(t, got)

	if n := strings.Count(line, "·"); n != 2 {
		t.Fatalf("finding line %q holds %d middle dots, want 2 (the writer's own separators)", line, n)
	}
	if !strings.Contains(line, "\\u00b7") {
		t.Fatalf("finding line %q, want the hazard middle dot kept visible as an escape", line)
	}
}

// meta.Path can name a scanned directory, so a middle dot there must not
// fabricate a second header column.
func TestWrite_Header_MiddleDotInPathCannotForgeAColumn(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, finding.NewReport(nil), Meta{Path: "proj · evil"}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	header := strings.SplitN(buf.String(), "\n", 2)[0]
	if n := strings.Count(header, "·"); n != 1 {
		t.Fatalf("header %q holds %d middle dots, want 1 (the writer's own separator)", header, n)
	}
	if !strings.Contains(header, "\\u00b7") {
		t.Fatalf("header %q, want the hazard middle dot kept visible as an escape", header)
	}
}

// The column layer doubles a backslash before it escapes the middle dot, so
// a value already spelling that escape literally stays distinguishable from
// one carrying a real middle dot; the reverse order renders both alike.
func TestWrite_FindingLine_LiteralBackslashStaysDistinctFromAnEscapedMiddleDot(t *testing.T) {
	dot := renderFinding(t, findingWithHazard("a·b"))
	spelled := renderFinding(t, findingWithHazard("a\\u00b7b"))

	if dot == spelled {
		t.Fatalf("a middle dot and its literal escape spelling render alike, want them distinguishable\noutput:\n%s", dot)
	}
	if !strings.Contains(spelled, `a\\u00b7b`) {
		t.Fatalf("Write() = %q, want the literal backslash doubled", spelled)
	}
}

// report.Escape runs first and the column layer second, so a value carrying
// both a control byte and a middle dot is neutralised on both axes and the
// backslash Escape introduced does not read as escaping what follows it.
func TestWrite_FindingLine_EscapesControlByteAndMiddleDotTogether(t *testing.T) {
	got := renderFinding(t, findingWithHazard("x\x1b·y"))
	line := soleFindingLine(t, got)

	if strings.ContainsRune(line, '\x1b') {
		t.Fatalf("finding line %q contains a raw ESC byte, want it escaped", line)
	}
	if n := strings.Count(line, "·"); n != 2 {
		t.Fatalf("finding line %q holds %d middle dots, want 2 (the writer's own separators)", line, n)
	}
	if !strings.Contains(line, "\\\\x1b\\u00b7") {
		t.Fatalf("finding line %q, want the control byte and the middle dot both escaped, in that order", line)
	}
}
