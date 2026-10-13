package cursor

import (
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func mcpMapFS(data string) fstest.MapFS {
	return fstest.MapFS{mcpFileName: &fstest.MapFile{Data: []byte(data)}}
}

func onlyServers(t *testing.T, fsys fs.FS) []ir.MCPServer {
	t.Helper()
	entities, warnings, err := mcpEntities(fsys, mcpFileName)
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("mcpEntities() warnings = %+v, want none", warnings)
	}
	servers := make([]ir.MCPServer, 0, len(entities))
	for _, e := range entities {
		s, ok := e.(ir.MCPServer)
		if !ok {
			t.Fatalf("entity %+v is %T, want ir.MCPServer", e, e)
		}
		servers = append(servers, s)
	}
	return servers
}

func TestMCPEntitiesMissingFileIsSilent(t *testing.T) {
	entities, warnings, err := mcpEntities(fstest.MapFS{}, mcpFileName)
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 || len(warnings) != 0 {
		t.Fatalf("mcpEntities() = (%+v, %+v), want neither", entities, warnings)
	}
}

// The location must name Cursor's own file, or a finding sends a reader to
// the Claude project file that does not carry this server.
func TestMCPEntitiesLocateServersInTheCursorFile(t *testing.T) {
	got := onlyServers(t, mcpMapFS(`{"mcpServers":{"build":{"command":"npx","args":["-y","srv"],"env":{"TOKEN":"t"}}}}`))
	want := []ir.MCPServer{{
		Name:      "build",
		Transport: ir.TransportStdio,
		Command:   "npx",
		Args:      []string{"-y", "srv"},
		Env:       map[string]string{"TOKEN": "t"},
		Location:  ir.Location{File: ".cursor/mcp.json", Key: "mcpServers.build"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mcpEntities() = %+v, want %+v", got, want)
	}
}

func TestMCPEntitiesResolveTransportFromDeclaredTypeAndFromPresence(t *testing.T) {
	tests := []struct {
		name             string
		entry            string
		wantTransport    ir.Transport
		wantUnrecognized string
	}{
		{"absent type with a command", `{"command":"npx"}`, ir.TransportStdio, ""},
		{"absent type with a url", `{"url":"https://example.test/mcp"}`, ir.TransportHTTP, ""},
		{"declared stdio", `{"type":"stdio","command":"npx"}`, ir.TransportStdio, ""},
		{"declared http", `{"type":"http","url":"https://example.test/mcp"}`, ir.TransportHTTP, ""},
		{"declared sse", `{"type":"sse","url":"https://example.test/sse"}`, ir.TransportSSE, ""},
		{"unknown token with a url", `{"type":"banana","url":"https://example.test/mcp"}`, ir.TransportHTTP, "banana"},
		{"unknown token without a url", `{"type":"banana","command":"npx"}`, ir.TransportStdio, "banana"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onlyServers(t, mcpMapFS(`{"mcpServers":{"s":`+tt.entry+`}}`))
			if len(got) != 1 {
				t.Fatalf("mcpEntities() = %+v, want one server", got)
			}
			if got[0].Transport != tt.wantTransport {
				t.Errorf("Transport = %q, want %q", got[0].Transport, tt.wantTransport)
			}
			if got[0].UnrecognizedTransport != tt.wantUnrecognized {
				t.Errorf("UnrecognizedTransport = %q, want %q", got[0].UnrecognizedTransport, tt.wantUnrecognized)
			}
		})
	}
}

// The rows part ways after the refusal: an unread type token still surfaces
// as unrecognized, while an unread key leaves nothing behind at all.
func TestMCPEntitiesRefuseToBorrowUndocumentedTransportSpellings(t *testing.T) {
	tests := []struct {
		name             string
		entry            string
		wantUnrecognized string
	}{
		{"streamable-http is not a cursor type token", `{"type":"streamable-http","url":"https://example.test/mcp"}`, "streamable-http"},
		{"the transport key is not read at all", `{"transport":"sse","url":"https://example.test/mcp"}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := onlyServers(t, mcpMapFS(`{"mcpServers":{"s":`+tt.entry+`}}`))
			if len(got) != 1 {
				t.Fatalf("mcpEntities() = %+v, want one server", got)
			}
			if got[0].Transport != ir.TransportHTTP {
				t.Errorf("Transport = %q, want %q", got[0].Transport, ir.TransportHTTP)
			}
			if got[0].UnrecognizedTransport != tt.wantUnrecognized {
				t.Errorf("UnrecognizedTransport = %q, want %q", got[0].UnrecognizedTransport, tt.wantUnrecognized)
			}
		})
	}
}

// Cursor resolves ${env:NAME} and friends at launch. A read-only scanner that
// expanded them would report a command line the file does not contain, and
// one it resolved from this machine's environment rather than the agent's.
func TestMCPEntitiesStoreInterpolationVerbatim(t *testing.T) {
	got := onlyServers(t, mcpMapFS(`{"mcpServers":{"s":{"command":"${userHome}/bin/srv","args":["${workspaceFolder}/x"],"env":{"K":"${env:SECRET}"}}}}`))
	if len(got) != 1 {
		t.Fatalf("mcpEntities() = %+v, want one server", got)
	}
	if got[0].Command != "${userHome}/bin/srv" {
		t.Errorf("Command = %q, want it stored verbatim", got[0].Command)
	}
	if !reflect.DeepEqual(got[0].Args, []string{"${workspaceFolder}/x"}) {
		t.Errorf("Args = %q, want them stored verbatim", got[0].Args)
	}
	if got[0].Env["K"] != "${env:SECRET}" {
		t.Errorf("Env[K] = %q, want it stored verbatim", got[0].Env["K"])
	}
}

func TestMCPEntitiesSortServersByName(t *testing.T) {
	got := onlyServers(t, mcpMapFS(`{"mcpServers":{"z":{"command":"z"},"a":{"command":"a"},"m":{"command":"m"}}}`))
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"a", "m", "z"}) {
		t.Fatalf("names = %v, want them sorted", names)
	}
}

func TestMCPEntitiesDegradeMalformedSourcesToWarnings(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantMsg  string
		wantNoGo string
	}{
		{"invalid json", `{not json`, "", "map[string]"},
		{"array document", `[1,2,3]`, "expected an object, found an array", "map[string]"},
		{"string mcpServers", `{"mcpServers":"nope"}`, "mcpServers: expected an object of server entries, found a string", "map[string]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(tt.data), mcpFileName)
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil: a malformed source degrades", err)
			}
			if len(entities) != 0 {
				t.Fatalf("mcpEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 || warnings[0].File != mcpFileName {
				t.Fatalf("warnings = %+v, want exactly one naming %q", warnings, mcpFileName)
			}
			if tt.wantMsg != "" && warnings[0].Err.Error() != tt.wantMsg {
				t.Errorf("warning = %q, want %q", warnings[0].Err, tt.wantMsg)
			}
			if strings.Contains(warnings[0].Err.Error(), tt.wantNoGo) {
				t.Errorf("warning = %q, must not leak a Go type name", warnings[0].Err)
			}
		})
	}
}

// One wrong-typed entry must not blank its siblings, or a hostile file hides
// every server it declares by breaking one of them.
func TestMCPEntitiesKeepSiblingsOfAMalformedEntry(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`{"mcpServers":{"bad":[],"good":{"command":"npx"}}}`), mcpFileName)
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(entities) != 1 {
		t.Fatalf("mcpEntities() = %+v, want the well-formed sibling alone", entities)
	}
	if got := entities[0].(ir.MCPServer).Name; got != "good" {
		t.Errorf("surviving server = %q, want %q", got, "good")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Err.Error(), "mcpServers.bad") {
		t.Fatalf("warnings = %+v, want one naming the faulty entry key", warnings)
	}
}

// Parse is the port the scanner drives, so the surface must be reachable
// through it and not only through the package-private entry point.
func TestParseSurfacesTheCursorMCPServers(t *testing.T) {
	entities, warnings, err := New().Parse(mcpMapFS(`{"mcpServers":{"s":{"command":"npx"}}}`))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() = %+v, want one entity", entities)
	}
	if got := entities[0].(ir.MCPServer).Location.File; got != mcpFileName {
		t.Errorf("Location.File = %q, want %q", got, mcpFileName)
	}
}
