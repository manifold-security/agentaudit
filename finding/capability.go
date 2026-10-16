package finding

import "github.com/manifold-security/agentaudit/internal/ir"

// Entity is what a Capability describes; its Kind() names the entity type.
type Entity = ir.Entity

// Capability is a neutral entity+provenance descriptor: what an entity can
// do (via the concrete Entity value) and where it was declared.
type Capability struct {
	Entity     Entity
	Provenance Provenance
}
