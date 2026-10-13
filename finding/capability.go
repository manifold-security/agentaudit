package finding

import "github.com/manifold-security/agentaudit/internal/ir"

// Capability is a neutral entity+provenance descriptor: what an entity can
// do (via the concrete ir.Entity value) and where it was declared.
type Capability struct {
	Entity     ir.Entity
	Provenance Provenance
}
