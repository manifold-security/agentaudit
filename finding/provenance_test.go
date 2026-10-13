package finding

import (
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestProvenanceFromLocation(t *testing.T) {
	tests := []struct {
		name string
		loc  ir.Location
		want Provenance
	}{
		{
			name: "file and key mapped verbatim",
			loc:  ir.Location{File: "settings.json", Key: "hooks[0]"},
			want: Provenance{File: "settings.json", Key: "hooks[0]"},
		},
		{
			name: "different file and key",
			loc:  ir.Location{File: "plugins.json", Key: "plugins[3]"},
			want: Provenance{File: "plugins.json", Key: "plugins[3]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProvenanceFromLocation(tt.loc)
			if got != tt.want {
				t.Fatalf("ProvenanceFromLocation(%+v) = %+v, want %+v", tt.loc, got, tt.want)
			}
		})
	}
}
