package cursor

import (
	"io/fs"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const mcpFileName = ".cursor/mcp.json"

const mcpServersKey = "mcpServers"

func mcpEntities(fsys fs.FS, file string) ([]ir.Entity, []adapter.Warning, error) {
	return mcpjson.EntitiesFromFile(fsys, file, mcpServersKey, transportOf)
}

// transportOf normalizes an entry's declared type into ir.Transport.
//
// Cursor's field table marks type required while its own examples omit it and
// its plugins reference infers transport from command or url, so an absent
// type resolves by presence and is no unrecognized token.
func transportOf(e mcpjson.Entry) (ir.Transport, string) {
	switch e.Type {
	case "":
		transport, _ := byPresence(e)
		return transport, ""
	case "stdio":
		return ir.TransportStdio, ""
	case "http":
		return ir.TransportHTTP, ""
	case "sse":
		return ir.TransportSSE, ""
	default:
		return byPresence(e)
	}
}

func byPresence(e mcpjson.Entry) (ir.Transport, string) {
	if e.URL != "" {
		return ir.TransportHTTP, e.Type
	}
	return ir.TransportStdio, e.Type
}
