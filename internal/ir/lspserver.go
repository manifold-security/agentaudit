package ir

// LSPServer is a plugin-declared language server configuration.
type LSPServer struct {
	Name     string
	Command  string
	Args     []string
	Location Location
}

func (LSPServer) Kind() string { return KindLSPServer }

// Identity returns a stable identity built from Name and Command; Args is
// payload the report surfaces, not something that separates two servers.
func (l LSPServer) Identity() string {
	return identity(KindLSPServer, l.Name, l.Command)
}
