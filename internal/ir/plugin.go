package ir

// Plugin is a declared plugin installation.
type Plugin struct {
	Name    string
	Version string
	// Source names the kind of declaration that installs the plugin, "" when
	// the producer does not classify it. A string rather than an enum, for
	// the reason BundledPayload.Executable gives.
	Source   string
	Location Location
}

func (Plugin) Kind() string { return KindPlugin }

// Identity returns a stable identity built from Name only. Version is
// excluded so re-declarations at different versions dedupe to one identity.
func (p Plugin) Identity() string {
	return identity(KindPlugin, p.Name)
}
