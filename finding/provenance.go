package finding

import "github.com/manifold-security/agentaudit/internal/ir"

// Provenance records where a capability was declared: the file it came from
// and the key path within that file. It is decoupled from ir.Location so the
// public surface never leans on the internal IR representation directly.
type Provenance struct {
	File string
	Key  string
}

// ProvenanceFromLocation maps an ir.Location to a Provenance, copying File
// and Key verbatim.
func ProvenanceFromLocation(loc ir.Location) Provenance {
	return Provenance{File: loc.File, Key: loc.Key}
}
