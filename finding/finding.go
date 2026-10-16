package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Finding is a single detected capability, described by a rule, tagged with
// zero or more categories, and located via its Capability's Provenance.
type Finding struct {
	RuleID string
	// Agent is the producing adapter's identifier. A hand-built Finding with
	// an empty Agent is legal and carries no validation.
	Agent      string
	Categories []Category
	Message    string
	References []string
	Capability Capability
}

// ID returns a stable, deterministic identity string for the Finding, built
// from the rule id, the underlying entity's Identity(), and the Provenance.
// Frozen contract: downstream tooling may bind to it directly, so the
// separator, part order, and part set must not change.
func (f Finding) ID() string {
	return stableID(f.RuleID, f.Capability.Entity.Identity(), f.Capability.Provenance.File, f.Capability.Provenance.Key)
}

// Digest returns the id the JSON report prints for the Finding, ID() reduced
// to 32 lowercase hex digits. It is frozen on the same terms as ID().
func (f Finding) Digest() string {
	sum := sha256.Sum256([]byte(f.ID()))
	return hex.EncodeToString(sum[:16])
}

// stableID joins parts with the ASCII Unit Separator (0x1f), mirroring
// ir.identity's separator choice.
func stableID(parts ...string) string {
	return strings.Join(parts, "\x1f")
}
