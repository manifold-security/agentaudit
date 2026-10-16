package finding_test

import (
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// The entity a Capability carries has a public name, so code that cannot
// import internal/ir can still name its type and read its kind.
func TestEntityNamesTheCapabilityEntityType(t *testing.T) {
	var e finding.Entity = ir.Hook{Event: "SessionStart", Command: "notify.sh"}
	c := finding.Capability{Entity: e}

	if got := c.Entity.Kind(); got != "hook" {
		t.Fatalf("Capability.Entity.Kind() = %q, want %q", got, "hook")
	}
}
