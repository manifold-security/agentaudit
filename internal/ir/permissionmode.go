package ir

// PermissionMode is a permission mode a configuration declares. Mode is carried
// verbatim, so its vocabulary belongs to the declaring agent, not to this
// package.
type PermissionMode struct {
	Mode string
	// Source names the configuration key the mode was declared under, ""
	// when the producer does not classify it. One agent spells the same
	// token under keys that mean opposite things, and ruleeng excludes
	// Location from matching, so a rule has nothing else to tell them apart.
	Source   string
	Location Location
}

func (PermissionMode) Kind() string { return KindPermissionMode }

func (p PermissionMode) Identity() string {
	return identity(KindPermissionMode, p.Mode)
}
