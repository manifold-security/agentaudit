package agentaudit_test

import (
	"testing"

	"github.com/manifold-security/agentaudit"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// The facade re-exports the entity type, so a caller that imports agentaudit
// without finding can still name a Capability's entity type.
func TestFacadeNamesTheCapabilityEntityType(t *testing.T) {
	var e agentaudit.Entity = ir.Hook{Event: "SessionStart", Command: "notify.sh"}
	c := agentaudit.Capability{Entity: e}

	if got := c.Entity.Kind(); got != "hook" {
		t.Fatalf("Capability.Entity.Kind() = %q, want %q", got, "hook")
	}
}
