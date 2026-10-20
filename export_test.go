package agentaudit

import (
	"context"
	"io/fs"

	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

var WithRulesFS = withRulesFS

var WithAdapters = withAdapters

func Bound(ctx context.Context, fsys fs.FS, limit int64) fs.FS {
	return bound(ctx, fsys, limit, nil, nil, nil)
}

// EmbeddedRuleIDs reads ids from the shipped ruleset itself, so a coverage
// guard built on it picks up a rule added later.
func EmbeddedRuleIDs() ([]string, error) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids, nil
}
