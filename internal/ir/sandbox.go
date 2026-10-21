package ir

// Sandbox is one grant a sandbox configuration makes. Adapters fan out one
// Sandbox entity per grant.
type Sandbox struct {
	// SocketPath is a Unix socket admitted into the sandbox.
	SocketPath string
	// Mode is the sandbox type a configuration selects, verbatim.
	Mode string
	// Path is a filesystem location opened beyond the workspace.
	Path string
	// Access is the level Path is opened under.
	Access   string
	Location Location
}

func (Sandbox) Kind() string { return KindSandbox }

// Identity is distinct for distinct grants, whichever form declared them.
func (s Sandbox) Identity() string {
	if s.SocketPath != "" {
		return identity(KindSandbox, s.SocketPath)
	}
	return identity(KindSandbox, s.Mode, s.Path, s.Access)
}
