package report

import (
	"fmt"
	"strings"

	"github.com/manifold-security/agentaudit/finding"
)

// Degraded reports whether a scan left a blind spot of either kind, which is
// what stops a reporter from claiming the tree simply holds no capabilities.
func Degraded(c finding.Counts) bool {
	return c.UnreadableSources > 0 || c.UnparsedSources > 0
}

// DegradedClause names each blind spot a scan left, dropping a kind with no
// sources so a report does not assert a degradation it did not suffer. The
// kinds stay apart because an unread source may hide anything, while an
// unparsed one was seen and only its declarations dropped.
func DegradedClause(c finding.Counts) string {
	var parts []string
	if c.UnreadableSources > 0 {
		parts = append(parts, fmt.Sprintf("%d source%s could not be read", c.UnreadableSources, Plural(c.UnreadableSources)))
	}
	if c.UnparsedSources > 0 {
		parts = append(parts, fmt.Sprintf("%d source%s could not be parsed", c.UnparsedSources, Plural(c.UnparsedSources)))
	}
	return strings.Join(parts, " and ")
}
