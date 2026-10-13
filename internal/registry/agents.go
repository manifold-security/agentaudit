package registry

import (
	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/adapters/codex"
	"github.com/manifold-security/agentaudit/internal/adapters/cursor"
)

// Adapters returns every wired agent adapter, explicitly. Adding an agent
// means adding one entry here.
func Adapters() []adapter.Adapter {
	return []adapter.Adapter{claude.New(), cursor.New(), codex.New()}
}
