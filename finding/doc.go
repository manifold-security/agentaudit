// Package finding defines agentaudit's public, scan-result domain types.
//
// The package is stdlib-only and performs zero I/O. It MAY import
// internal/ir, and only internal/ir, for ir.Entity and
// ProvenanceFromLocation(ir.Location) — a same-layer, I/O-free domain
// reference. It MUST NOT import any other agentaudit package.
//
// There is no severity, score, or risk-level concept in this package:
// agentaudit surfaces capabilities, it never assigns a severity.
//
// Finding.ID() is a frozen contract (see finding.go); extending the type set
// is additive, but renaming/removing existing names or changing ID()'s
// composition is a breaking change.
package finding
