// Package ruleeng loads and evaluates declarative JSON detection rules.
//
// Rules are authored as JSON arrays and read over an fs.FS, so the package
// stays embeddable: the shipped ruleset is an embedded FS and tests supply
// their own. Its production sources depend only on the Go standard library
// and agentaudit/internal/ir — TestPackagePurity pins that — keeping the
// detection layer decoupled from finding.Finding construction and
// adapter/CLI wiring.
//
// Field matching against a concrete ir.Entity uses reflection over flat IR
// fields rather than per-kind Go code, so adding a rule over an existing
// operator is a data change, not a Go one.
package ruleeng
