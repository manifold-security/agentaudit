package codex

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// ParseGlobal reads nothing: Parse already surfaces every key codex declares
// under its home Base.
func (Adapter) ParseGlobal(fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	return nil, nil, nil
}
