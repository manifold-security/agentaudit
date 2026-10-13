package adapter

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// Base names an adapter's global config root symbolically: cmd/agentaudit's
// TestOSIsolation_EngineAndReporterPackages bars "os" from this package's
// non-test files.
type Base string

// BaseHome is the current user's home directory.
const BaseHome Base = "home"

// GlobalConfig declares an adapter's global (not per-project) config: each
// Entries prefix admits its own subtree under the resolved Base, nothing else.
type GlobalConfig struct {
	Base    Base
	Entries []string
}

// GlobalScoped is the optional port for an adapter with a global config.
type GlobalScoped interface {
	Adapter
	GlobalConfig() GlobalConfig

	// ParseGlobal reads keys under a resolved Base that Parse does not
	// surface on its own. An adapter with none returns nothing and
	// implements this only so the port admits its Base to the global scan.
	ParseGlobal(fsys fs.FS) ([]ir.Entity, []Warning, error)
}
