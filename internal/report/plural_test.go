package report_test

import (
	"testing"

	"github.com/manifold-security/agentaudit/internal/report"
)

func TestPlural(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "s"},
		{1, ""},
		{2, "s"},
		{6, "s"},
	}
	for _, tt := range tests {
		if got := report.Plural(tt.n); got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// Covers the irregular nouns Plural's suffix-only rule cannot handle.
func TestPluralNoun(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "categories"},
		{1, "category"},
		{2, "categories"},
	}
	for _, tt := range tests {
		if got := report.PluralNoun(tt.n, "category", "categories"); got != tt.want {
			t.Errorf("PluralNoun(%d, ...) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
