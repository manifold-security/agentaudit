package ir

import "testing"

// Each Transport constant reads back verbatim as its own string value.
func TestTransportRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		want      string
	}{
		{"stdio", TransportStdio, "stdio"},
		{"http", TransportHTTP, "http"},
		{"sse", TransportSSE, "sse"},
		{"ws", TransportWS, "ws"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MCPServer{Name: "srv", Transport: tt.transport}
			if string(m.Transport) != tt.want {
				t.Fatalf("Transport field = %q, want %q", string(m.Transport), tt.want)
			}
			if m.Transport != tt.transport {
				t.Fatalf("Transport field = %v, want original constant %v", m.Transport, tt.transport)
			}
		})
	}
}

// ${CLAUDE_PLUGIN_ROOT} and ${CLAUDE_PROJECT_DIR} are never expanded in IR.
func TestPlaceholderVerbatim(t *testing.T) {
	t.Run("string field", func(t *testing.T) {
		const want = "${CLAUDE_PROJECT_DIR}/scripts/audit.sh"
		h := Hook{Event: "PreToolUse", Matcher: "Bash", Command: want}
		if h.Command != want {
			t.Fatalf("Hook.Command = %q, want byte-identical %q", h.Command, want)
		}
	})

	t.Run("slice element", func(t *testing.T) {
		const want = "${CLAUDE_PLUGIN_ROOT}/bin/tool"
		s := Subagent{Name: "reviewer", Tools: []string{"Read", want}}
		if s.Tools[1] != want {
			t.Fatalf("Subagent.Tools[1] = %q, want byte-identical %q", s.Tools[1], want)
		}
	})

	t.Run("map value", func(t *testing.T) {
		const want = "${CLAUDE_PLUGIN_ROOT}/config"
		m := MCPServer{Name: "srv", Transport: TransportStdio, Command: "srv-bin", Env: map[string]string{"CONFIG_DIR": want}}
		if m.Env["CONFIG_DIR"] != want {
			t.Fatalf("MCPServer.Env[CONFIG_DIR] = %q, want byte-identical %q", m.Env["CONFIG_DIR"], want)
		}
	})
}
