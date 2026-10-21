// Package pretty renders a finding.Report as deterministic, plain-text
// human-readable output on any io.Writer. Its non-test code performs no I/O
// of its own (never touches os — enforced by
// TestOSIsolation_EngineAndReporterPackages).
package pretty

import (
	"fmt"
	"io"
	"strings"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/report"
)

// Meta carries CLI-supplied context a Report itself does not have.
type Meta struct {
	Path    string
	Explain bool
}

// Write renders no severity. Every scanned-tree string it prints passes
// through report.Escape first — including meta.Path, which is scanned-tree
// input under -r — so a control byte, a bidirectional-formatting character or
// an invalid UTF-8 byte renders as a visible escape instead of fabricating an
// extra header or finding line. Write's own literal text carries no
// scanned-tree content and needs no escaping.
func Write(w io.Writer, r finding.Report, meta Meta) error {
	if _, err := fmt.Fprintf(w, "agentaudit · %s\n\n", escapeColumn(report.Escape(meta.Path))); err != nil {
		return err
	}

	counts := r.Counts()

	if !r.HasFindings() {
		if report.Degraded(counts) {
			if err := writeIncomplete(w, counts); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, "no source the scan could read and parse declared a capability"); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintln(w, emptyLine(r.ScannedAgents())); err != nil {
			return err
		}
		return writeFooter(w, counts)
	}

	for _, ag := range r.GroupByAgent() {
		if _, err := fmt.Fprintf(w, "(%s)\n", report.Escape(ag.Agent)); err != nil {
			return err
		}
		for _, group := range ag.Groups {
			if err := writeGroup(w, group, meta.Explain); err != nil {
				return err
			}
		}
	}

	if report.Degraded(counts) {
		if err := writeIncomplete(w, counts); err != nil {
			return err
		}
	}
	return writeFooter(w, counts)
}

// emptyLine separates a scan that read an agent's configuration and found
// nothing declared in it from one that read no such configuration.
func emptyLine(agents []string) string {
	if len(agents) == 0 {
		return "no known agent config read"
	}
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = escapeColumn(report.Escape(a))
	}
	return fmt.Sprintf("no capabilities found (scanned: %s)", strings.Join(names, ", "))
}

// writeGroup preserves Report first-occurrence order; no sort is applied here.
func writeGroup(w io.Writer, group finding.CategoryGroup, explain bool) error {
	if _, err := fmt.Fprintf(w, "%s:\n", report.Escape(string(group.Category))); err != nil {
		return err
	}
	for _, f := range group.Findings {
		if err := writeFindingLine(w, f); err != nil {
			return err
		}
		if explain {
			if err := writeExplainLine(w, f); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

func writeFindingLine(w io.Writer, f finding.Finding) error {
	what, value := report.Describe(f.Capability.Entity)
	if line, ok := report.CommandLine(f.Capability.Entity); ok {
		value = line
	}

	file := f.Capability.Provenance.File
	if key := f.Capability.Provenance.Key; key != "" {
		file = file + ":" + key
	}

	_, err := fmt.Fprintf(w, "  %s · %s · %s\n", escapeColumn(report.Escape(what)), escapeColumn(report.Escape(value)), escapeColumn(report.Escape(file)))
	return err
}

// escapeColumn runs after report.Escape and keeps its result from breaking a
// columned line. The backslash goes first, so a spelling Escape produced is
// not read as escaping what follows it; the separator's middle dot goes
// second.
func escapeColumn(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "·", "\\u00b7")
	return s
}

func writeExplainLine(w io.Writer, f finding.Finding) error {
	parts := []string{report.Escape(f.RuleID)}
	if f.Message != "" {
		parts = append(parts, report.Escape(f.Message))
	}
	if len(f.References) > 0 {
		refs := make([]string, len(f.References))
		for i, ref := range f.References {
			refs[i] = report.Escape(ref)
		}
		parts = append(parts, strings.Join(refs, "; "))
	}
	_, err := fmt.Fprintf(w, "    %s\n", strings.Join(parts, " — "))
	return err
}

func writeIncomplete(w io.Writer, c finding.Counts) error {
	_, err := fmt.Fprintf(w, "SCAN INCOMPLETE: %s (see stderr); capabilities may be missing\n", report.DegradedClause(c))
	return err
}

func writeFooter(w io.Writer, c finding.Counts) error {
	line := fmt.Sprintf("%d %s · %d %s · %d %s",
		c.Findings, report.PluralNoun(c.Findings, "capability", "capabilities"),
		c.Files, report.PluralNoun(c.Files, "file", "files"),
		c.Categories, report.PluralNoun(c.Categories, "category", "categories"))
	if c.UnreadableSources > 0 {
		line += fmt.Sprintf(" · %d unreadable source%s", c.UnreadableSources, report.Plural(c.UnreadableSources))
	}
	if c.UnparsedSources > 0 {
		line += fmt.Sprintf(" · %d unparsed source%s", c.UnparsedSources, report.Plural(c.UnparsedSources))
	}
	_, err := fmt.Fprintln(w, line)
	return err
}
