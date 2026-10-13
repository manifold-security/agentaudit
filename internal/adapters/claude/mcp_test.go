package claude

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func mcpMapFS(data string) fstest.MapFS {
	return fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte(data)},
	}
}

func TestMCPEntities_MissingFile(t *testing.T) {
	entities, warnings, err := mcpEntities(fstest.MapFS{})
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if entities != nil {
		t.Fatalf("mcpEntities() = %+v, want nil", entities)
	}
	if warnings != nil {
		t.Fatalf("mcpEntities() warnings = %+v, want nil", warnings)
	}
}

func TestMCPEntities_MalformedJSON(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`{not valid json`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil (malformed source recovers via Warning)", err)
	}
	if entities != nil {
		t.Fatalf("mcpEntities() entities = %+v, want nil", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("mcpEntities() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	if warnings[0].File != mcpFileName {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, mcpFileName)
	}
	if warnings[0].Err == nil {
		t.Errorf("warnings[0].Err = nil, want non-nil")
	}
}

func TestMCPEntities_NonObjectTopLevelNamesTheShape(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`[1,2,3]`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(entities) != 0 {
		t.Fatalf("mcpEntities() entities = %+v, want none", entities)
	}
	if len(warnings) != 1 {
		t.Fatalf("mcpEntities() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	wantMsg := "expected an object, found an array"
	if warnings[0].Err == nil || warnings[0].Err.Error() != wantMsg {
		t.Errorf("warnings[0].Err = %v, want %q", warnings[0].Err, wantMsg)
	}
	if strings.Contains(warnings[0].Err.Error(), "map[string]") {
		t.Errorf("warnings[0].Err = %v, must not leak a Go type name", warnings[0].Err)
	}
}

// A literal JSON null decodes with no error and declares no server, so
// classifying it as a wrong shape would warn on a config declaring nothing.
func TestMCPEntities_NonObjectTopLevelNullIsSilent(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`null`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Errorf("mcpEntities() warnings = %+v, want none", warnings)
	}
	if len(entities) != 0 {
		t.Errorf("mcpEntities() entities = %+v, want none", entities)
	}
}

func TestMCPEntities_TransportCases(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ir.MCPServer
	}{
		{
			name: "type absent decodes as stdio",
			data: `{"mcpServers":{"fs":{"command":"/usr/local/bin/mcp-fs","args":["--root","/"],"env":{"DEBUG":"1"}}}}`,
			want: ir.MCPServer{
				Name:      "fs",
				Transport: ir.TransportStdio,
				Command:   "/usr/local/bin/mcp-fs",
				Args:      []string{"--root", "/"},
				Env:       map[string]string{"DEBUG": "1"},
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.fs"},
			},
		},
		{
			name: "explicit stdio type",
			data: `{"mcpServers":{"fs":{"type":"stdio","command":"/usr/local/bin/mcp-fs"}}}`,
			want: ir.MCPServer{
				Name:      "fs",
				Transport: ir.TransportStdio,
				Command:   "/usr/local/bin/mcp-fs",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.fs"},
			},
		},
		{
			name: "http decodes URL",
			data: `{"mcpServers":{"api":{"type":"http","url":"https://api.example.com"}}}`,
			want: ir.MCPServer{
				Name:      "api",
				Transport: ir.TransportHTTP,
				URL:       "https://api.example.com",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.api"},
			},
		},
		{
			name: "streamable-http normalizes to http",
			data: `{"mcpServers":{"stream":{"type":"streamable-http","url":"https://stream.example.com"}}}`,
			want: ir.MCPServer{
				Name:      "stream",
				Transport: ir.TransportHTTP,
				URL:       "https://stream.example.com",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.stream"},
			},
		},
		{
			name: "sse decodes URL",
			data: `{"mcpServers":{"events":{"type":"sse","url":"https://events.example.com"}}}`,
			want: ir.MCPServer{
				Name:      "events",
				Transport: ir.TransportSSE,
				URL:       "https://events.example.com",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.events"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParse_AppendsMCPEntitiesAfterSettings(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{"apiKeyHelper": "get-key.sh"}`)},
		".mcp.json":             &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"/usr/local/bin/mcp-fs"}}}`)},
	}

	entities, _, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(entities) != 2 {
		t.Fatalf("Parse() entities len = %d, want 2: %+v", len(entities), entities)
	}
	if _, ok := entities[0].(ir.CredentialHelper); !ok {
		t.Fatalf("entities[0] type = %T, want ir.CredentialHelper (settings entity first)", entities[0])
	}
	mcp, ok := entities[1].(ir.MCPServer)
	if !ok {
		t.Fatalf("entities[1] type = %T, want ir.MCPServer (mcp entity after settings)", entities[1])
	}
	if mcp.Name != "fs" || mcp.Command != "/usr/local/bin/mcp-fs" {
		t.Errorf("entities[1] = %+v, want Name=fs Command=/usr/local/bin/mcp-fs", mcp)
	}
}

// Recovery is per file, not per adapter: one malformed source must not take a
// healthy sibling's entities down with it.
func TestParse_MalformedMCPWarnsSettingsSurvives(t *testing.T) {
	fsys := fstest.MapFS{
		".claude/settings.json": &fstest.MapFile{Data: []byte(`{"apiKeyHelper": "get-key.sh"}`)},
		".mcp.json":             &fstest.MapFile{Data: []byte(`{not valid json`)},
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("Parse() warnings len = %d, want 1: %+v", len(warnings), warnings)
	}
	if warnings[0].File != mcpFileName {
		t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, mcpFileName)
	}
	if len(entities) != 1 {
		t.Fatalf("Parse() entities len = %d, want 1 (settings.json survives): %+v", len(entities), entities)
	}
	if _, ok := entities[0].(ir.CredentialHelper); !ok {
		t.Fatalf("entities[0] type = %T, want ir.CredentialHelper", entities[0])
	}
}

// A read failure is a different path from malformed content.
func TestMCPEntities_UnreadableFileWarnsOtherCapabilitySurvives(t *testing.T) {
	fsys := failingReadFileFS{
		m: fstest.MapFS{
			".mcp.json":             &fstest.MapFile{Data: []byte(`{"mcpServers":{"fs":{"command":"mcp-fs"}}}`)},
			".claude/settings.json": &fstest.MapFile{Data: []byte(`{"apiKeyHelper": "get-key.sh"}`)},
		},
		failPath: ".mcp.json",
	}

	entities, warnings, err := New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil (an unreadable .mcp.json must warn, never abort)", err)
	}

	var foundWarning bool
	for _, w := range warnings {
		if w.File == mcpFileName {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("Parse() warnings = %+v, want one naming %q", warnings, mcpFileName)
	}

	var found bool
	for _, e := range entities {
		if ch, ok := e.(ir.CredentialHelper); ok && ch.Command == "get-key.sh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Parse() entities = %+v, want the settings.json credential helper to survive", entities)
	}
}

func TestMCPEntities_WSTransport(t *testing.T) {
	entities, _, err := mcpEntities(mcpMapFS(`{"mcpServers":{"chat":{"type":"ws","url":"wss://x.tld/mcp"}}}`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(entities) != 1 {
		t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
	}
	got, ok := entities[0].(ir.MCPServer)
	if !ok {
		t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
	}
	want := ir.MCPServer{
		Name:      "chat",
		Transport: ir.TransportWS,
		URL:       "wss://x.tld/mcp",
		Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.chat"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mcpEntities() = %+v, want %+v", got, want)
	}
}

// An unrecognized type is a token the config author wrote and the scanner
// never decoded; dropping it reports the fallback guess as the config's claim.
func TestMCPEntities_UnrecognizedTransportIsRecorded(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ir.MCPServer
	}{
		{
			name: "unrecognized type with command falls back to stdio",
			data: `{"mcpServers":{"legacy":{"type":"banana","command":"/bin/x"}}}`,
			want: ir.MCPServer{
				Name:                  "legacy",
				Transport:             ir.TransportStdio,
				Command:               "/bin/x",
				UnrecognizedTransport: "banana",
				Location:              ir.Location{File: ".mcp.json", Key: "mcpServers.legacy"},
			},
		},
		{
			name: "unrecognized type with ws:// URL keeps ws precedence",
			data: `{"mcpServers":{"legacy":{"type":"banana","url":"ws://x.tld"}}}`,
			want: ir.MCPServer{
				Name:                  "legacy",
				Transport:             ir.TransportWS,
				URL:                   "ws://x.tld",
				UnrecognizedTransport: "banana",
				Location:              ir.Location{File: ".mcp.json", Key: "mcpServers.legacy"},
			},
		},
		{
			name: "unrecognized transport alias with no endpoint falls back to stdio",
			data: `{"mcpServers":{"legacy":{"transport":"banana"}}}`,
			want: ir.MCPServer{
				Name:                  "legacy",
				Transport:             ir.TransportStdio,
				UnrecognizedTransport: "banana",
				Location:              ir.Location{File: ".mcp.json", Key: "mcpServers.legacy"},
			},
		},
		{
			name: "case variant is not a recognized alias",
			data: `{"mcpServers":{"x":{"type":"STDIO","command":"c"}}}`,
			want: ir.MCPServer{
				Name:                  "x",
				Transport:             ir.TransportStdio,
				Command:               "c",
				UnrecognizedTransport: "STDIO",
				Location:              ir.Location{File: ".mcp.json", Key: "mcpServers.x"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestTransportOfLabelsWSFromURLScheme(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ir.MCPServer
	}{
		{
			name: "unrecognized type with ws:// URL",
			data: `{"mcpServers":{"legacy":{"type":"unknown-thing","url":"ws://x.tld/mcp"}}}`,
			want: ir.MCPServer{Name: "legacy", Transport: ir.TransportWS, URL: "ws://x.tld/mcp", UnrecognizedTransport: "unknown-thing", Location: ir.Location{File: ".mcp.json", Key: "mcpServers.legacy"}},
		},
		{
			name: "unrecognized type with wss:// URL",
			data: `{"mcpServers":{"secure":{"type":"unknown-thing","url":"wss://x.tld/mcp"}}}`,
			want: ir.MCPServer{Name: "secure", Transport: ir.TransportWS, URL: "wss://x.tld/mcp", UnrecognizedTransport: "unknown-thing", Location: ir.Location{File: ".mcp.json", Key: "mcpServers.secure"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A resolved-transport-only projection would hide an http server's own
// code-execution path from the rule engine and every reporter.
func TestMCPEntities_DeclaredEndpointsSurviveAnyTransport(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ir.MCPServer
	}{
		{
			name: "http with both url and command",
			data: `{"mcpServers":{"api":{"type":"http","url":"https://a","command":"/bin/sh -c evil"}}}`,
			want: ir.MCPServer{
				Name:      "api",
				Transport: ir.TransportHTTP,
				URL:       "https://a",
				Command:   "/bin/sh -c evil",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.api"},
			},
		},
		{
			name: "stdio with both command and url",
			data: `{"mcpServers":{"fs":{"command":"c","url":"https://a"}}}`,
			want: ir.MCPServer{
				Name:      "fs",
				Transport: ir.TransportStdio,
				Command:   "c",
				URL:       "https://a",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.fs"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMCPEntities_RecognizedTransportLeavesUnrecognizedFieldEmpty(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"type absent", `{"mcpServers":{"x":{"command":"c"}}}`},
		{"type stdio", `{"mcpServers":{"x":{"type":"stdio","command":"c"}}}`},
		{"type http", `{"mcpServers":{"x":{"type":"http","url":"https://a"}}}`},
		{"type streamable-http", `{"mcpServers":{"x":{"type":"streamable-http","url":"https://a"}}}`},
		{"type sse", `{"mcpServers":{"x":{"type":"sse","url":"https://a"}}}`},
		{"type ws", `{"mcpServers":{"x":{"type":"ws","url":"wss://a"}}}`},
		{"transport key present but empty", `{"mcpServers":{"x":{"transport":"","command":"c"}}}`},
		{"transport stdio", `{"mcpServers":{"x":{"transport":"stdio","command":"c"}}}`},
		{"transport http", `{"mcpServers":{"x":{"transport":"http","url":"https://a"}}}`},
		{"transport streamable-http", `{"mcpServers":{"x":{"transport":"streamable-http","url":"https://a"}}}`},
		{"transport sse", `{"mcpServers":{"x":{"transport":"sse","url":"https://a"}}}`},
		{"transport ws", `{"mcpServers":{"x":{"transport":"ws","url":"wss://a"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if got.UnrecognizedTransport != "" {
				t.Errorf("UnrecognizedTransport = %q, want empty for a recognized token", got.UnrecognizedTransport)
			}
		})
	}
}

// "type" wins where a config sets it and the transport alias to different
// values.
func TestMCPEntryTransportAlias(t *testing.T) {
	tests := []struct {
		name string
		data string
		want ir.MCPServer
	}{
		{
			name: "transport alias used when type absent",
			data: `{"mcpServers":{"chat":{"transport":"ws","url":"wss://x.tld/mcp"}}}`,
			want: ir.MCPServer{Name: "chat", Transport: ir.TransportWS, URL: "wss://x.tld/mcp", Location: ir.Location{File: ".mcp.json", Key: "mcpServers.chat"}},
		},
		{
			name: "type wins over transport alias when both present",
			data: `{"mcpServers":{"api":{"type":"http","transport":"ws","url":"https://api.example.com"}}}`,
			want: ir.MCPServer{Name: "api", Transport: ir.TransportHTTP, URL: "https://api.example.com", Location: ir.Location{File: ".mcp.json", Key: "mcpServers.api"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, _, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1: %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// A wrong-typed field inside ONE server must not fail an unmarshal spanning
// every sibling: that makes the scanner stricter than the thing it audits, and
// servers the agent runs happily would drop out of the report.
func TestMCPEntities_MalformedEntryKeepsSiblings(t *testing.T) {
	tests := []struct {
		name string
		bad  string
	}{
		{name: "args is a string, not an array", bad: `"bad":{"command":"node","args":"server.js"}`},
		{name: "env value is a number, not a string", bad: `"bad":{"command":"node","env":{"PORT":8080}}`},
		{name: "command is a number, not a string", bad: `"bad":{"command":42}`},
		{name: "entry is an array, not an object", bad: `"bad":["node","server.js"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(`{"mcpServers":{` + tt.bad + `,"good":{"command":"/usr/local/bin/mcp-fs"}}}`))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}

			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1 (the sibling survives): %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok {
				t.Fatalf("entities[0] type = %T, want ir.MCPServer", entities[0])
			}
			want := ir.MCPServer{
				Name:      "good",
				Transport: ir.TransportStdio,
				Command:   "/usr/local/bin/mcp-fs",
				Location:  ir.Location{File: ".mcp.json", Key: "mcpServers.good"},
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("mcpEntities() = %+v, want %+v", got, want)
			}

			if len(warnings) != 1 {
				t.Fatalf("mcpEntities() warnings len = %d, want 1: %+v", len(warnings), warnings)
			}
			if warnings[0].File != mcpFileName {
				t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, mcpFileName)
			}
			// Without the key in the text a reader cannot tell which server was
			// dropped.
			if warnings[0].Err == nil || !strings.Contains(warnings[0].Err.Error(), "mcpServers.bad") {
				t.Errorf("warnings[0].Err = %v, want it to name mcpServers.bad", warnings[0].Err)
			}
		})
	}
}

// An unguarded json.Unmarshal into map[string]json.RawMessage would hand the
// reader that Go type name on a non-object mcpServers value.
func TestMCPEntities_NonObjectServersKeyNamesTheShape(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantShape string
	}{
		{"array", `{"mcpServers":[{"name":"x"}]}`, "an array"},
		{"string", `{"mcpServers":"./servers.json"}`, "a string"},
		{"number", `{"mcpServers":5}`, "a non-object value"},
		{"bool", `{"mcpServers":true}`, "a non-object value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 0 {
				t.Fatalf("mcpEntities() entities = %+v, want none", entities)
			}
			if len(warnings) != 1 {
				t.Fatalf("mcpEntities() warnings len = %d, want 1: %+v", len(warnings), warnings)
			}
			if warnings[0].File != mcpFileName {
				t.Errorf("warnings[0].File = %q, want %q", warnings[0].File, mcpFileName)
			}
			wantMsg := "mcpServers: expected an object of server entries, found " + tt.wantShape
			if warnings[0].Err == nil || warnings[0].Err.Error() != wantMsg {
				t.Errorf("warnings[0].Err = %v, want %q", warnings[0].Err, wantMsg)
			}
			for _, leak := range []string{"json.RawMessage", "map[string]", "unmarshal"} {
				if warnings[0].Err != nil && strings.Contains(warnings[0].Err.Error(), leak) {
					t.Errorf("warnings[0].Err = %v, must not contain %q", warnings[0].Err, leak)
				}
			}
		})
	}
}

// A naive "not an object, so warn" gate would warn at a config that merely
// declares no servers.
func TestMCPEntities_ExplicitNullServersKeyIsSilent(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`{"mcpServers":null}`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Errorf("mcpEntities() warnings = %+v, want none", warnings)
	}
	if len(entities) != 0 {
		t.Errorf("mcpEntities() entities = %+v, want none", entities)
	}
}

func TestMCPEntities_AbsentServersKeyIsSilent(t *testing.T) {
	for _, data := range []string{`{}`, `{"otherKey":1}`} {
		t.Run(data, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Errorf("mcpEntities() warnings = %+v, want none", warnings)
			}
			if len(entities) != 0 {
				t.Errorf("mcpEntities() entities = %+v, want none", entities)
			}
		})
	}
}

// The copy surfaces the transport the server resolved to, including stdio.
func TestMCPEntities_HeadersHelperYieldsABaseAndACopy(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantBase   ir.MCPServer
		wantHelper ir.MCPServer
	}{
		{
			name: "http server",
			data: `{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.test/mcp","headersHelper":"./scripts/headers.sh"}}}`,
			wantBase: ir.MCPServer{
				Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp",
				Location: ir.Location{File: ".mcp.json", Key: "mcpServers.docs"},
			},
			wantHelper: ir.MCPServer{
				Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp",
				HeadersHelper: "./scripts/headers.sh",
				Location:      ir.Location{File: ".mcp.json", Key: "mcpServers.docs.headersHelper"},
			},
		},
		{
			name: "stdio server",
			data: `{"mcpServers":{"fs":{"command":"npx","args":["--flag"],"env":{"DEBUG":"1"},"headersHelper":"./scripts/headers.sh"}}}`,
			wantBase: ir.MCPServer{
				Name: "fs", Transport: ir.TransportStdio, Command: "npx", Args: []string{"--flag"},
				Env:      map[string]string{"DEBUG": "1"},
				Location: ir.Location{File: ".mcp.json", Key: "mcpServers.fs"},
			},
			wantHelper: ir.MCPServer{
				Name: "fs", Transport: ir.TransportStdio, Command: "npx",
				HeadersHelper: "./scripts/headers.sh",
				Location:      ir.Location{File: ".mcp.json", Key: "mcpServers.fs.headersHelper"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("mcpEntities() warnings = %+v, want none", warnings)
			}
			if len(entities) != 2 {
				t.Fatalf("mcpEntities() len = %d, want 2: %+v", len(entities), entities)
			}
			if !reflect.DeepEqual(entities[0], tt.wantBase) {
				t.Errorf("entities[0] = %+v, want %+v", entities[0], tt.wantBase)
			}
			if !reflect.DeepEqual(entities[1], tt.wantHelper) {
				t.Errorf("entities[1] = %+v, want %+v", entities[1], tt.wantHelper)
			}
		})
	}
}

func TestMCPEntities_EmptyHeadersHelperYieldsNothing(t *testing.T) {
	entities, warnings, err := mcpEntities(mcpMapFS(`{"mcpServers":{"docs":{"command":"npx","headersHelper":""}}}`))
	if err != nil {
		t.Fatalf("mcpEntities() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("mcpEntities() warnings = %+v, want none", warnings)
	}
	if len(entities) != 1 {
		t.Fatalf("mcpEntities() len = %d, want 1 (no copy): %+v", len(entities), entities)
	}
}

// A wrong-typed headersHelper must not drop the server it decorates: only
// the helper value is skipped, with a warning naming its own key.
func TestMCPEntities_WrongTypedHeadersHelperWarnsAndKeepsServer(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantForm string
	}{
		{"object", `{"mcpServers":{"docs":{"command":"npx","headersHelper":{"nested":"x"}}}}`, "an object"},
		{"array", `{"mcpServers":{"docs":{"command":"npx","headersHelper":["a"]}}}`, "an array"},
		{"number", `{"mcpServers":{"docs":{"command":"npx","headersHelper":5}}}`, "a non-string value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := mcpEntities(mcpMapFS(tt.data))
			if err != nil {
				t.Fatalf("mcpEntities() error = %v, want nil", err)
			}
			if len(entities) != 1 {
				t.Fatalf("mcpEntities() len = %d, want 1 (server survives): %+v", len(entities), entities)
			}
			got, ok := entities[0].(ir.MCPServer)
			if !ok || got.HeadersHelper != "" {
				t.Fatalf("entities[0] = %+v, want the base server with HeadersHelper empty", entities[0])
			}
			if len(warnings) != 1 {
				t.Fatalf("mcpEntities() warnings len = %d, want 1: %+v", len(warnings), warnings)
			}
			wantMsg := "mcpServers.docs.headersHelper: expected a string, found " + tt.wantForm
			if warnings[0].Err == nil || warnings[0].Err.Error() != wantMsg {
				t.Errorf("warnings[0].Err = %v, want %q", warnings[0].Err, wantMsg)
			}
		})
	}
}

// Repeated runs are what distinguish an explicit sort from incidental order.
func TestMCPEntities_SortedByName(t *testing.T) {
	fsys := mcpMapFS(`{"mcpServers":{
		"z":{"command":"z-bin"},
		"a":{"command":"a-bin"},
		"m":{"command":"m-bin"}
	}}`)

	wantOrder := []string{"a", "m", "z"}
	for run := 0; run < 2; run++ {
		entities, _, err := mcpEntities(fsys)
		if err != nil {
			t.Fatalf("run %d: mcpEntities() error = %v, want nil", run, err)
		}
		if len(entities) != 3 {
			t.Fatalf("run %d: mcpEntities() len = %d, want 3: %+v", run, len(entities), entities)
		}
		for i, e := range entities {
			mcp, ok := e.(ir.MCPServer)
			if !ok {
				t.Fatalf("run %d: entities[%d] type = %T, want ir.MCPServer", run, i, e)
			}
			if mcp.Name != wantOrder[i] {
				t.Errorf("run %d: entities[%d].Name = %q, want %q", run, i, mcp.Name, wantOrder[i])
			}
		}
	}
}
