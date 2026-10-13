// Package ir defines agentaudit's normalized, I/O-free intermediate
// representation: the frozen contract every adapter emits and every rule
// matches against.
//
// The package is pure data. It has zero I/O — no os, net, filesystem, or
// serialization imports — and imports no other agentaudit package. This
// package's TestPackagePurity and cmd/agentaudit's
// TestOSIsolation_EngineAndReporterPackages together pin that.
//
// Entities satisfy the Entity interface on value receivers, so a flat
// []ir.Entity slice holds copies rather than pointers into adapter state. The
// authoritative list of entity types is kind.go's Kind* constants and
// ruleeng's targets registry.
//
// This is a frozen contract: downstream packages (adapters, the rule
// engine, findings) bind directly to these names and tokens. Extending the
// entity set is additive; renaming or removing existing names, tokens, or
// identity semantics is a breaking change.
package ir
