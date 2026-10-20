// Package agentaudit composes discovery, adapters, and the rule engine behind
// the Scanner's scan methods, re-exporting the domain types callers need.
//
// To scan a directory on disk, pass the FS of os.OpenRoot(dir): os.DirFS(dir)
// follows a symlink that leads out of dir, and an os.Root refuses one.
package agentaudit

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/discovery"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/registry"
	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

// embeddedRules is the bundled default ruleset. The "all:" prefix is
// load-bearing: a bare "//go:embed rules" pattern skips dotfiles.
//
//go:embed all:rules
var embeddedRules embed.FS

const defaultRulesDir = "rules"

type (
	Finding    = finding.Finding
	Report     = finding.Report
	Capability = finding.Capability
	Entity     = finding.Entity
	Provenance = finding.Provenance
	Category   = finding.Category
	AgentID    = adapter.AgentID
)

const (
	AgentClaudeCode = adapter.AgentClaudeCode
	AgentCursor     = adapter.AgentCursor
	AgentCodex      = adapter.AgentCodex
)

// WarnFunc receives each non-fatal warning as Scan runs; it does not receive
// the fatal errors Scan returns directly, which
// TestScanRootDiscoveryFailureStaysFatal pins. A nil WarnFunc is a no-op.
type WarnFunc func(error)

// ErrLimit is the sentinel errors.Is finds in a warning about a file a scan
// limit refused.
var ErrLimit = limits.ErrLimit

// Scanner holds the resolved configuration built by New and its Options.
// One Scanner may run Scan and ScanRecursive concurrently, and its WarnFunc
// may then be called concurrently.
type Scanner struct {
	agents       []adapter.AgentID
	warn         WarnFunc
	rulesFS      fs.FS
	rulesDir     string
	adapters     []adapter.Adapter
	recursive    bool
	maxFileSize  int64
	maxFindings  int
	maxReadBytes int64
	maxEntities  int
}

// Option configures a Scanner built by New.
type Option func(*Scanner)

// New builds a Scanner from opts. With no options every registered adapter
// runs, warnings are dropped, rules load from the embedded default set, and
// each limit whose option names a default holds it.
func New(opts ...Option) *Scanner {
	s := &Scanner{
		maxFileSize:  512 << 10,
		maxReadBytes: 64 << 20,
		maxEntities:  10000,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithAgents restricts which registered adapters Scan runs. No arguments
// means every registered adapter runs.
func WithAgents(ids ...adapter.AgentID) Option {
	return func(s *Scanner) { s.agents = ids }
}

// WithRecursive makes Select ask for what ScanRecursive reads rather than
// what Scan reads.
func WithRecursive() Option {
	return func(s *Scanner) { s.recursive = true }
}

// WithWarnFunc sets the callback invoked for each non-fatal warning.
func WithWarnFunc(fn WarnFunc) Option {
	return func(s *Scanner) { s.warn = fn }
}

// WithMaxFindings makes each Report a scan returns hold at most its first n
// findings, counting the rest; n <= 0 sets no cap.
func WithMaxFindings(n int) Option {
	return func(s *Scanner) { s.maxFindings = n }
}

// withRulesFS is a test-only seam replacing the embedded default ruleset,
// reaching black-box tests through export_test.go's WithRulesFS bridge.
func withRulesFS(fsys fs.FS, dir string) Option {
	return func(s *Scanner) {
		s.rulesFS = fsys
		s.rulesDir = dir
	}
}

// withAdapters is the same seam for registry.Adapters(). WithAgents still
// filters whichever set is active.
func withAdapters(adapters ...adapter.Adapter) Option {
	return func(s *Scanner) { s.adapters = adapters }
}

// warnSink collapses one faulty source seen by more than one walker:
// discovery and an adapter's own Parse-time walk can reach one directory.
// Emission and counting dedupe on separate keys because they answer separate
// questions — stderr explains which layer was defeated and how, so it keys on
// the reported error, while the tallies answer how many sources were missed,
// so they key on the path, the identity that survives two layers reporting
// one fault through different syscalls. Neither keys on the formatted
// message, whose per-call-site prefix would fail to merge those duplicates.
type warnSink struct {
	emit       func(error)
	emitted    map[string]struct{}
	counted    map[string]struct{}
	unreadable int
	unparsed   int
}

func newWarnSink(emit func(error)) *warnSink {
	return &warnSink{
		emit:    emit,
		emitted: make(map[string]struct{}),
		counted: make(map[string]struct{}),
	}
}

// isGenuineReadFailure reports whether err is a source the scanner could not
// read at all, never inflated by a parse fault on a file it did read. A
// declared-but-missing source hides nothing, so it does not count; an
// adapter.ErrUnreadable refusal does, being an attacker-chosen blind spot the
// agent may still follow even though the scanner deliberately does not.
func isGenuineReadFailure(err error) bool {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return errors.Is(err, adapter.ErrUnreadable)
}

// isParseDiscard reports whether err is a source the scanner did read but
// could not fully parse, so a declaration it carried was dropped instead of
// reported: a fault on bytes the scanner held.
func isParseDiscard(err error) bool {
	return !isGenuineReadFailure(err) && !errors.Is(err, fs.ErrNotExist)
}

func (s *warnSink) source(w adapter.Warning, msg error) {
	switch {
	case isGenuineReadFailure(w.Err):
		if s.firstInBucket("unreadable", w.File) {
			s.unreadable++
		}
	case isParseDiscard(w.Err):
		if s.firstInBucket("unparsed", w.File) {
			s.unparsed++
		}
	}
	s.emitOnce("source\x00"+w.File+"\x00"+w.Err.Error(), msg)
}

// adapterFailure routes an adapter's trailing Parse error, which carries no
// File, so it is namespaced apart from source keys and tallies on that error
// rather than a path. It lands in the unreadable bucket whatever the reason
// for the abort: an adapter that stopped mid-parse leaves its sources unread.
func (s *warnSink) adapterFailure(agent adapter.AgentID, err, msg error) {
	key := "adapter\x00" + string(agent) + "\x00" + err.Error()
	if s.firstInBucket("unreadable", key) {
		s.unreadable++
	}
	s.emitOnce(key, msg)
}

func (s *warnSink) firstInBucket(bucket, id string) bool {
	key := bucket + "\x00" + id
	if _, ok := s.counted[key]; ok {
		return false
	}
	s.counted[key] = struct{}{}
	return true
}

func (s *warnSink) emitOnce(key string, msg error) {
	if _, ok := s.emitted[key]; ok {
		return
	}
	s.emitted[key] = struct{}{}
	s.emit(msg)
}

func (s *warnSink) unreadableSources() int {
	return s.unreadable
}

func (s *warnSink) unparsedSources() int {
	return s.unparsed
}

// Scan returns a deduplicated Report whose UnreadableSources and
// UnparsedSources counts reflect the sources it could not read and those it
// read but could not fully parse; both are also routed through WarnFunc.
func (s *Scanner) Scan(fsys fs.FS) (finding.Report, error) {
	return s.ScanContext(context.Background(), fsys)
}

func (s *Scanner) emitFunc() func(error) {
	if s.warn == nil {
		return func(error) {}
	}
	return s.warn
}

// pass decides whether an adapter runs in one scanFS call and which of its
// sources it is asked for — where a global scan differs from a project one.
type pass interface {
	activates(a adapter.Adapter, fsys fs.FS, matched bool) bool
	entities(a adapter.Adapter, fsys fs.FS) ([]ir.Entity, []adapter.Warning, error)
}

type projectPass struct{}

func (projectPass) activates(_ adapter.Adapter, _ fs.FS, matched bool) bool {
	return matched
}

func (projectPass) entities(a adapter.Adapter, fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return a.Parse(fsys)
}

// scanFS takes its sink from the caller so ScanRecursive can share one
// between enumeration and the container's own scan.
func (s *Scanner) scanFS(fsys fs.FS, sink *warnSink, p pass) (finding.Report, error) {
	warn := sink.emit
	adapters := s.selectedAdapters()

	disc, discWarnings, err := discovery.Discover(fsys, adapters)
	for _, w := range discWarnings {
		sink.source(w, fmt.Errorf("agentaudit: discover: %s: %w", w.File, w.Err))
	}
	if err != nil {
		return finding.Report{}, fmt.Errorf("agentaudit: discover: %w", err)
	}

	matched := make(map[adapter.AgentID]bool, len(disc.Sources))
	for _, src := range disc.Sources {
		matched[src.Agent] = true
	}

	rules, err := s.loadRules()
	if err != nil {
		return finding.Report{}, fmt.Errorf("agentaudit: load rules: %w", err)
	}
	rulesByID := make(map[string]ruleeng.Rule, len(rules))
	for _, r := range rules {
		rulesByID[r.ID] = r
	}

	findings := finding.NewReportBuilder(s.maxFindings)
	var scanned []string
	for _, a := range adapters {
		if !p.activates(a, fsys, matched[a.Agent()]) {
			continue
		}
		// Recorded before the parse, so an adapter defeated by an I/O fault
		// still counts as scanned: a list that shrank under one would read
		// as a tree holding no known agent config, and the fault already
		// reaches the reader through the degradation tally.
		scanned = append(scanned, string(a.Agent()))

		budget := limits.NewEntities(s.maxEntities)
		entities, warnings, err := p.entities(a, bound(context.Background(), fsys, 0, nil, budget, nil))
		warnings = budget.KeepWarnings(warnings)
		for _, w := range warnings {
			w.Err = limits.JSONDepthRefusal(w.Err)
			sink.source(w, fmt.Errorf("agentaudit: parse %s: %s: %w", a.Agent(), w.File, w.Err))
		}
		if err != nil {
			sink.adapterFailure(a.Agent(), err, fmt.Errorf("agentaudit: parse %s: %w", a.Agent(), err))
			continue
		}

		hits := ruleeng.Evaluate(rules, budget.Keep(entities), string(a.Agent()))
		for _, h := range hits {
			f, ok := toFinding(rulesByID[h.RuleID], h, a.Agent())
			if !ok {
				warn(fmt.Errorf("agentaudit: rule %s produced unconvertible finding (empty message)", h.RuleID))
				continue
			}
			findings.Add(f)
		}
	}

	return findings.Report().
		WithUnreadableSources(sink.unreadableSources()).
		WithUnparsedSources(sink.unparsedSources()).
		WithScannedAgents(scanned), nil
}

func (s *Scanner) selectedAdapters() []adapter.Adapter {
	all := s.adapters
	if all == nil {
		all = registry.Adapters()
	}
	if len(s.agents) == 0 {
		return all
	}

	want := make(map[adapter.AgentID]bool, len(s.agents))
	for _, id := range s.agents {
		want[id] = true
	}

	var out []adapter.Adapter
	for _, a := range all {
		if want[a.Agent()] {
			out = append(out, a)
		}
	}
	return out
}

func (s *Scanner) loadRules() ([]ruleeng.Rule, error) {
	if s.rulesFS != nil {
		return ruleeng.Load(s.rulesFS, s.rulesDir)
	}
	return ruleeng.LoadAll(embeddedRules, defaultRulesDir)
}

// toFinding converts a Hit into a Finding attributed to agent, the adapter
// whose Parse produced h.Entity. An empty Message is skipped here because
// ValidateRule does not require one, leaving this the enforcement point.
func toFinding(r ruleeng.Rule, h ruleeng.Hit, agent adapter.AgentID) (finding.Finding, bool) {
	if r.Message == "" {
		return finding.Finding{}, false
	}

	cats := make([]finding.Category, len(r.Category))
	for i, c := range r.Category {
		cats[i] = finding.Category(c)
	}

	return finding.Finding{
		RuleID:     h.RuleID,
		Agent:      string(agent),
		Categories: cats,
		Message:    r.Message,
		References: r.References,
		Capability: finding.Capability{
			Entity:     h.Entity,
			Provenance: finding.ProvenanceFromLocation(ir.LocationOf(h.Entity)),
		},
	}, true
}
