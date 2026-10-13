package report_test

import (
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/report"
)

func TestDegradedAndDegradedClause(t *testing.T) {
	tests := []struct {
		name       string
		counts     finding.Counts
		wantFlag   bool
		wantClause string
	}{
		{name: "clean", counts: finding.Counts{}, wantFlag: false, wantClause: ""},
		{
			name:       "one unreadable",
			counts:     finding.Counts{UnreadableSources: 1},
			wantFlag:   true,
			wantClause: "1 source could not be read",
		},
		{
			name:       "many unparsed",
			counts:     finding.Counts{UnparsedSources: 3},
			wantFlag:   true,
			wantClause: "3 sources could not be parsed",
		},
		{
			name:       "both",
			counts:     finding.Counts{UnreadableSources: 2, UnparsedSources: 1},
			wantFlag:   true,
			wantClause: "2 sources could not be read and 1 source could not be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := report.Degraded(tt.counts); got != tt.wantFlag {
				t.Errorf("Degraded(%+v) = %v, want %v", tt.counts, got, tt.wantFlag)
			}
			if got := report.DegradedClause(tt.counts); got != tt.wantClause {
				t.Errorf("DegradedClause(%+v) = %q, want %q", tt.counts, got, tt.wantClause)
			}
		})
	}
}
