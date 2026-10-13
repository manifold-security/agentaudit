// Package md renders a finding.Report as a grouped Markdown document on any
// io.Writer. Its non-test code performs no I/O of its own (never touches os —
// enforced by TestOSIsolation_EngineAndReporterPackages).
package md

import (
	"fmt"
	"io"
	"strings"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/report"
)

// Meta carries CLI-supplied context a Report itself does not have.
type Meta struct {
	Path string
}

// Write renders r to w as one Markdown document: a hazard byte in a scanned
// name cannot forge an extra heading, row or table column, and a Report
// carrying a blind spot of either kind signals incompleteness rather than
// none found.
func Write(w io.Writer, r finding.Report, meta Meta) error {
	if _, err := fmt.Fprintf(w, "# agentaudit · %s\n\n", escapeCell(report.Escape(meta.Path))); err != nil {
		return err
	}

	counts := r.Counts()

	if !r.HasFindings() {
		if report.Degraded(counts) {
			if err := writeIncomplete(w, counts); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, "_no source the scan could read and parse declared a capability_\n\n"); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(w, "_%s_\n\n", emptyLine(r.ScannedAgents())); err != nil {
			return err
		}
		return writeFooter(w, counts)
	}

	for _, ag := range r.GroupByAgent() {
		if _, err := fmt.Fprintf(w, "## (%s)\n\n", escapeCell(report.Escape(ag.Agent))); err != nil {
			return err
		}
		for _, group := range ag.Groups {
			if err := writeGroup(w, group); err != nil {
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

// emptyLine distinguishes a scan that read an agent's configuration and
// found nothing declared in it from one that read no such configuration.
// An id arrives from the registry, not from the scanned tree, and passes
// report.Escape and escapeCell regardless, so what neutralises a name is
// where it renders rather than where it came from.
func emptyLine(agents []string) string {
	if len(agents) == 0 {
		return "no known agent config read"
	}
	names := make([]string, len(agents))
	for i, a := range agents {
		names[i] = escapeCell(report.Escape(a))
	}
	return fmt.Sprintf("no capabilities found (scanned: %s)", strings.Join(names, ", "))
}

func writeGroup(w io.Writer, group finding.CategoryGroup) error {
	if _, err := fmt.Fprintf(w, "## %s\n\n", escapeCell(report.Escape(string(group.Category)))); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Rule | Capability | Value | Location | Message | References | ID |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- |"); err != nil {
		return err
	}
	for _, f := range group.Findings {
		if err := writeRow(w, f); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

func writeRow(w io.Writer, f finding.Finding) error {
	what, value := report.Describe(f.Capability.Entity)

	location := f.Capability.Provenance.File
	if key := f.Capability.Provenance.Key; key != "" {
		location += ":" + key
	}

	_, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | `%s` |\n",
		escapeCell(report.Escape(f.RuleID)), escapeCell(report.Escape(what)), escapeCell(report.Escape(value)), escapeCell(report.Escape(location)),
		escapeCell(report.Escape(f.Message)), escapeCell(report.Escape(strings.Join(f.References, "; "))),
		report.Digest(f.ID()))
	return err
}

// escapeCell runs on text report.Escape has already neutralised and keeps
// that text from breaking the structure around it. The backslash is doubled
// first, so a spelling Escape produced is not read as escaping what follows
// it; then the pipe, which would split an extra table column, and the middle
// dot, which would spell the H1's own " · " separator.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "·", "\\u00b7")
	return s
}

func writeIncomplete(w io.Writer, c finding.Counts) error {
	_, err := fmt.Fprintf(w, "**SCAN INCOMPLETE**: %s (see stderr); capabilities may be missing.\n\n", report.DegradedClause(c))
	return err
}

func writeFooter(w io.Writer, c finding.Counts) error {
	line := fmt.Sprintf("**%d** %s · **%d** %s · **%d** %s",
		c.Findings, report.PluralNoun(c.Findings, "capability", "capabilities"),
		c.Files, report.PluralNoun(c.Files, "file", "files"),
		c.Categories, report.PluralNoun(c.Categories, "category", "categories"))
	if c.UnreadableSources > 0 {
		line += fmt.Sprintf(" · **%d** unreadable source%s", c.UnreadableSources, report.Plural(c.UnreadableSources))
	}
	if c.UnparsedSources > 0 {
		line += fmt.Sprintf(" · **%d** unparsed source%s", c.UnparsedSources, report.Plural(c.UnparsedSources))
	}
	_, err := fmt.Fprintln(w, line)
	return err
}
