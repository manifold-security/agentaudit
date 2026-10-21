package claude

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/mcpjson"
)

const mcpFileName = ".mcp.json"

func entryType(e mcpjson.Entry) string {
	if e.Type != "" {
		return e.Type
	}
	return e.Transport
}

func mcpEntities(fsys fs.FS) ([]ir.Entity, []adapter.Warning, error) {
	servers, warnings, err := mcpjson.ServersFromFile(fsys, mcpFileName, "mcpServers")
	if err != nil || servers == nil {
		return nil, warnings, err
	}
	entities, entityWarnings := entitiesFromMCPMap(servers, mcpFileName, "mcpServers")
	entities, warnings = limits.Of(fsys).Admit(mcpFileName, entities, append(warnings, entityWarnings...))
	return entities, warnings, nil
}

// entitiesFromMCPMap binds Claude's own transportOf, so a Claude surface
// carrying an mcpServers map resolves transport the way Claude documents it.
// A non-empty headersHelper entry also appends a copy at its own Location.
func entitiesFromMCPMap(servers map[string]mcpjson.Entry, file, keyPrefix string) ([]ir.Entity, []adapter.Warning) {
	entities := mcpjson.Entities(servers, file, keyPrefix, transportOf)

	var warnings []adapter.Warning
	for _, e := range entities {
		server := e.(ir.MCPServer)
		helper, wrongType, form := headersHelperOf(servers[server.Name].HeadersHelper)
		helperKey := keyPrefix + "." + server.Name + ".headersHelper"
		if wrongType {
			warnings = append(warnings, adapter.Warning{File: file, Err: fmt.Errorf("%s: expected a string, found %s", helperKey, form)})
			continue
		}
		if helper == "" {
			continue
		}
		entities = append(entities, ir.MCPServer{
			Name:                  server.Name,
			Transport:             server.Transport,
			Command:               server.Command,
			URL:                   server.URL,
			UnrecognizedTransport: server.UnrecognizedTransport,
			HeadersHelper:         helper,
			Location:              ir.Location{File: file, Key: helperKey},
		})
	}
	return entities, warnings
}

func headersHelperOf(v any) (helper string, wrongType bool, form string) {
	switch t := v.(type) {
	case nil:
		return "", false, ""
	case string:
		return t, false, ""
	case map[string]any:
		return "", true, "an object"
	case []any:
		return "", true, "an array"
	default:
		return "", true, "a non-string value"
	}
}

// transportOf normalizes an entry's effective type into ir.Transport, falling
// back by field presence when the type is unrecognized. The ws:// check must
// precede the generic URL case, or an unrecognized type carrying a WebSocket
// URL is mis-labeled http. An alias Claude documents is decoded knowledge
// rather than a guess, so those arms report no token.
func transportOf(e mcpjson.Entry) (ir.Transport, string) {
	switch entryType(e) {
	case "", "stdio":
		return ir.TransportStdio, ""
	case "http", "streamable-http":
		return ir.TransportHTTP, ""
	case "sse":
		return ir.TransportSSE, ""
	case "ws":
		return ir.TransportWS, ""
	default:
		switch {
		case strings.HasPrefix(e.URL, "ws://"), strings.HasPrefix(e.URL, "wss://"):
			return ir.TransportWS, entryType(e)
		case e.URL != "":
			return ir.TransportHTTP, entryType(e)
		default:
			return ir.TransportStdio, entryType(e)
		}
	}
}
