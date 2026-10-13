package ir

// MCPServer is a configured Model Context Protocol server.
type MCPServer struct {
	Name      string
	Transport Transport
	Command   string
	URL       string
	Args      []string
	Env       map[string]string
	Location  Location
	// UnrecognizedTransport carries a declared type/transport token verbatim
	// when Transport was resolved by presence-based fallback rather than
	// decoded from a known alias — a guess must not be reported as if the
	// config had made the claim itself.
	UnrecognizedTransport string
	// HeadersHelper and ForwardedEnv name a command the server's connection
	// runs and a local environment variable the server receives. They sit
	// outside Identity.
	HeadersHelper string
	ForwardedEnv  string
}

func (MCPServer) Kind() string { return KindMCPServer }

// endpoint returns the transport-relevant address: Command for stdio
// (which spawns a process), URL for http/sse (which reach a host).
func (m MCPServer) endpoint() string {
	if m.Transport == TransportStdio {
		return m.Command
	}
	return m.URL
}

// Identity returns a stable identity built from Name, Transport, and the
// transport-appropriate endpoint.
func (m MCPServer) Identity() string {
	return identity(KindMCPServer, m.Name, string(m.Transport), m.endpoint())
}
