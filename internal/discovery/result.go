package discovery

import "github.com/manifold-security/agentaudit/adapter"

// Source is a single adapter-owned config location found during a walk.
type Source struct {
	Path  string
	Agent adapter.AgentID
}

// Result is the sorted, deduplicated output of one Discover pass.
type Result struct {
	Sources     []Source
	PluginRoots []string
}
