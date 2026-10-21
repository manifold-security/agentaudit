package ir

// Transport identifies how an MCPServer is reached.
type Transport string

// Frozen Transport values.
const (
	TransportStdio Transport = "stdio"
	TransportHTTP  Transport = "http"
	TransportSSE   Transport = "sse"
	// TransportWS is the WebSocket transport used by some plugin MCP
	// servers. Without explicit handling, a "ws" entry falls through
	// transportOf's default and, with a URL set, gets mislabeled as http.
	TransportWS Transport = "ws"
)
