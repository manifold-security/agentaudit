package ruleeng

import "github.com/manifold-security/agentaudit/internal/ir"

// Hit is a single rule match against a normalized IR entity. ruleeng never
// constructs finding.Finding — that translation belongs to the caller.
type Hit struct {
	RuleID string
	Entity ir.Entity
}
