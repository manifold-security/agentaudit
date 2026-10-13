package finding

import (
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func TestCapability_FieldsReadBack(t *testing.T) {
	entity := ir.Hook{Event: "PreToolUse", Matcher: "Bash", Command: "echo hi"}
	prov := Provenance{File: "settings.json", Key: "hooks[0]"}

	capability := Capability{Entity: entity, Provenance: prov}

	if capability.Entity != entity {
		t.Fatalf("Capability.Entity = %+v, want %+v", capability.Entity, entity)
	}
	if capability.Provenance != prov {
		t.Fatalf("Capability.Provenance = %+v, want %+v", capability.Provenance, prov)
	}
}
