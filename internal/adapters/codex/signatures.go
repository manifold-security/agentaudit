package codex

import (
	"github.com/manifold-security/agentaudit/adapter"
)

const (
	configFileName = ".codex/config.toml"
	hooksFileName  = ".codex/hooks.json"
)

// Adapter implements adapter.Adapter for Codex.
type Adapter struct{}

func New() Adapter { return Adapter{} }

func (Adapter) Agent() adapter.AgentID { return adapter.AgentCodex }

// Signatures declares which paths this adapter owns.
// TestParseReachesEveryDeclaredSignature checks the set against Parse in
// both directions.
func (Adapter) Signatures() []adapter.Signature {
	return []adapter.Signature{
		{Dir: ".codex", File: "config.toml"},
		{Dir: ".codex", File: "hooks.json"},
		{Dir: skillsRoot, Recursive: true},
	}
}

// PluginMarkers declares the marker folder a Codex plugin keeps its manifest
// in. It stays out of Signatures because Parse reads nothing there.
func (Adapter) PluginMarkers() []adapter.Signature {
	return []adapter.Signature{{Dir: ".codex-plugin", File: "plugin.json", AnyDepth: true}}
}

// GlobalConfig declares the home-relative locations this adapter scans.
func (Adapter) GlobalConfig() adapter.GlobalConfig {
	return adapter.GlobalConfig{
		Base: adapter.BaseHome,
		Entries: []string{
			configFileName,
			hooksFileName,
			skillsRoot,
		},
	}
}
