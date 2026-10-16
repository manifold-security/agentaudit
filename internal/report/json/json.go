// Package json renders one or more finding.Report values as a single JSON
// array on any io.Writer, one document per report. Its non-test code
// performs no I/O of its own (never touches os — enforced by
// TestOSIsolation_EngineAndReporterPackages).
package json

import (
	stdjson "encoding/json"
	"io"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/report"
)

// Meta carries CLI-supplied context a Report itself does not have: the
// scanned path. The agent label lives per finding, never here.
type Meta struct {
	Path string
}

// Entry pairs one report with its own Meta; Write renders one array element
// per Entry, in the order given.
type Entry struct {
	Report finding.Report
	Meta   Meta
}

type document struct {
	Path string `json:"path"`
	// ScannedAgents is rendered whatever its length, so a consumer gates on
	// an empty list rather than on the absence of a key.
	ScannedAgents []string      `json:"scannedAgents"`
	Findings      []findingJSON `json:"findings"`
	Counts        countsJSON    `json:"counts"`
}

type findingJSON struct {
	ID         string             `json:"id"`
	Agent      string             `json:"agent"`
	RuleID     string             `json:"ruleId"`
	Categories []finding.Category `json:"categories"`
	Message    string             `json:"message"`
	References []string           `json:"references"`
	Capability capabilityJSON     `json:"capability"`
}

type capabilityJSON struct {
	Kind  string `json:"kind"`
	What  string `json:"what"`
	Value string `json:"value"`
	// Args is omitted rather than normalized to an empty array the way
	// categories and references are: most entity kinds carry no argument
	// vector at all, so an "args": [] on one would assert a declaration the
	// scanned config never made.
	Args []string `json:"args,omitempty"`
	File string   `json:"file"`
	Key  string   `json:"key,omitempty"`
}

type countsJSON struct {
	Findings          int `json:"findings"`
	Files             int `json:"files"`
	Categories        int `json:"categories"`
	UnreadableSources int `json:"unreadableSources"`
	UnparsedSources   int `json:"unparsedSources"`
}

// Write renders entries as one indented JSON array to w, one element per
// entry in the order given — for every length, including one, so the shape
// never varies with the number of scanned targets. capability.what/value come
// from report.Describe, never the entity's raw Identity(), which embeds a
// non-display-safe control byte.
func Write(w io.Writer, entries []Entry) error {
	docs := make([]document, len(entries))
	for i, e := range entries {
		docs[i] = buildDocument(e.Report, e.Meta)
	}

	enc := stdjson.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(docs)
}

func buildDocument(r finding.Report, meta Meta) document {
	src := r.Findings()
	out := make([]findingJSON, len(src))
	for i, f := range src {
		what, value := report.Describe(f.Capability.Entity)

		categories := f.Categories
		if categories == nil {
			categories = []finding.Category{}
		}
		references := f.References
		if references == nil {
			references = []string{}
		}

		out[i] = findingJSON{
			ID:         f.Digest(),
			Agent:      f.Agent,
			RuleID:     f.RuleID,
			Categories: categories,
			Message:    f.Message,
			References: references,
			Capability: capabilityJSON{
				Kind:  f.Capability.Entity.Kind(),
				What:  what,
				Value: value,
				Args:  report.Args(f.Capability.Entity),
				File:  f.Capability.Provenance.File,
				Key:   f.Capability.Provenance.Key,
			},
		}
	}

	c := r.Counts()
	return document{
		Path:          meta.Path,
		ScannedAgents: r.ScannedAgents(),
		Findings:      out,
		Counts: countsJSON{
			Findings:          c.Findings,
			Files:             c.Files,
			Categories:        c.Categories,
			UnreadableSources: c.UnreadableSources,
			UnparsedSources:   c.UnparsedSources,
		},
	}
}
