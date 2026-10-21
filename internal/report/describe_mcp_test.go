package report

import (
	"reflect"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// An undecoded transport token must be disclosed as an inference next to the
// resolved transport, so a reader cannot mistake the scanner's fallback guess
// for a claim the config itself made.
func TestDescribe_MCPServerUnrecognizedTransport(t *testing.T) {
	what, _ := Describe(ir.MCPServer{
		Name:                  "legacy",
		Transport:             ir.TransportWS,
		URL:                   "ws://x",
		UnrecognizedTransport: "banana",
	})
	want := `mcpServer legacy (ws inferred; declared "banana")`
	if what != want {
		t.Fatalf("Describe() what = %q, want %q", what, want)
	}
}

// A recognized transport must carry no inference annotation, because nothing
// was guessed — only the presence-based fallback branch is a claim the
// config never made.
func TestDescribe_MCPServerRecognizedTransportUnannotated(t *testing.T) {
	what, value := Describe(ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx mcp-fs"})
	if what != "mcpServer fs (stdio)" {
		t.Fatalf("Describe() what = %q, want %q", what, "mcpServer fs (stdio)")
	}
	if value != "npx mcp-fs" {
		t.Fatalf("Describe() value = %q, want %q", value, "npx mcp-fs")
	}
}

// A second value channel with no delimiting structure would let one
// attacker-controlled field read as two declared fields.
func TestDescribe_MCPServerValueCarriesOnlyPrimaryEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		entity    ir.MCPServer
		wantValue string
	}{
		{
			name:      "http primary, command also declared",
			entity:    ir.MCPServer{Name: "api", Transport: ir.TransportHTTP, URL: "https://a", Command: "/bin/sh -c evil"},
			wantValue: "https://a",
		},
		{
			name:      "stdio primary, url also declared",
			entity:    ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "c", URL: "https://a"},
			wantValue: "c",
		},
		{
			name:      "http with command only, no url",
			entity:    ir.MCPServer{Name: "api", Transport: ir.TransportHTTP, Command: "/bin/sh -c evil"},
			wantValue: "command=/bin/sh -c evil",
		},
		{
			name:      "stdio only, unlabelled",
			entity:    ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "c"},
			wantValue: "c",
		},
		{
			name:      "neither endpoint declared",
			entity:    ir.MCPServer{Name: "empty", Transport: ir.TransportStdio},
			wantValue: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, value := Describe(tt.entity)
			if value != tt.wantValue {
				t.Errorf("Describe() value = %q, want %q", value, tt.wantValue)
			}
		})
	}
}

// The absent endpoint is quoted inside the existing "what" parenthetical the
// same way an inferred transport token already is.
func TestDescribe_MCPServerWhatDisclosesTheEndpointAbsentFromValue(t *testing.T) {
	tests := []struct {
		name     string
		entity   ir.MCPServer
		wantWhat string
	}{
		{
			name:     "http primary, command disclosed",
			entity:   ir.MCPServer{Name: "api", Transport: ir.TransportHTTP, URL: "https://a", Command: "/bin/sh -c evil"},
			wantWhat: `mcpServer api (http; command="/bin/sh -c evil")`,
		},
		{
			name:     "stdio primary, url disclosed",
			entity:   ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "c", URL: "https://a"},
			wantWhat: `mcpServer fs (stdio; url="https://a")`,
		},
		{
			name:     "only one endpoint declared, nothing to disclose",
			entity:   ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "c"},
			wantWhat: "mcpServer fs (stdio)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			what, _ := Describe(tt.entity)
			if what != tt.wantWhat {
				t.Errorf("Describe() what = %q, want %q", what, tt.wantWhat)
			}
		})
	}
}

// A lone endpoint that lands in the transport's PRIMARY slot must render
// bare, with no "command="/"url=" prefix. See the sole-secondary case just
// below for the complementary slot.
func TestDescribe_MCPServerSingleEndpointStaysUnlabelled(t *testing.T) {
	_, value := Describe(ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx mcp-fs"})
	if value != "npx mcp-fs" {
		t.Fatalf("Describe() value = %q, want the bare endpoint with no label", value)
	}
}

// A lone endpoint that lands in the transport's SECONDARY slot — a stdio
// server naming only a url, with no command — must still render labelled:
// an unlabelled bare url under a stdio transport would read as a shell
// command, so labelling is a property of the slot, not of "exactly one
// endpoint declared".
func TestDescribe_MCPServerSoleSecondaryEndpointStaysLabelled(t *testing.T) {
	_, value := Describe(ir.MCPServer{Name: "x", Transport: ir.TransportStdio, URL: "https://a"})
	if value != "url=https://a" {
		t.Fatalf("Describe() value = %q, want %q", value, "url=https://a")
	}
}

// A single field whose own declared text imitates the two-endpoint
// disclosure shape must never render byte-identically, on either channel, to
// a server that genuinely declared both endpoints: only the second field
// makes "command=..." a fact the config actually stated.
func TestDescribe_MCPServerForgedURLCannotMimicGenuineCommandDisclosure(t *testing.T) {
	forged := ir.MCPServer{Name: "forged", Transport: ir.TransportHTTP, URL: `"https://harmless.tld"; command="/bin/forged"`}
	honest := ir.MCPServer{Name: "honest", Transport: ir.TransportHTTP, URL: "https://harmless.tld", Command: "/bin/forged"}

	forgedWhat, forgedValue := Describe(forged)
	honestWhat, honestValue := Describe(honest)

	if forgedValue == honestValue {
		t.Fatalf("forged and honest servers rendered the same value: %q", forgedValue)
	}
	wantHonestWhat := `mcpServer honest (http; command="/bin/forged")`
	if honestWhat != wantHonestWhat {
		t.Fatalf("Describe() what = %q, want %q", honestWhat, wantHonestWhat)
	}
	if strings.Contains(forgedWhat, "command=") {
		t.Fatalf("Describe() what = %q, a single declared field must not manufacture a command disclosure", forgedWhat)
	}
}

// A server name is attacker-authored (a scanned config chooses its own
// mcpServers key) and sits OUTSIDE the parenthetical this disclosure lives
// in, so a name crafted to look like a genuine two-endpoint disclosure must
// still be followed by the real transport clause computed from the actual
// struct fields, not swallowed by the forged text.
func TestDescribe_MCPServerNameCannotForgeTheDisclosureClause(t *testing.T) {
	forgedName := ir.MCPServer{
		Name:      `evil (http; command="/bin/planted")`,
		Transport: ir.TransportStdio,
		Command:   "npx real",
	}
	what, _ := Describe(forgedName)
	if !strings.HasSuffix(what, "(stdio)") {
		t.Fatalf("Describe() what = %q, want it to end with the real transport clause regardless of a forged name", what)
	}

	genuineComposite := ir.MCPServer{Name: "b", Transport: ir.TransportHTTP, URL: "https://a", Command: "/bin/planted"}
	genuineWhat, _ := Describe(genuineComposite)
	if what == genuineWhat {
		t.Fatalf("a forged server name produced the same what as a genuine composite disclosure: %q", what)
	}
}

// Declaring a vector on a server must leave both of Describe's returned
// strings untouched — Args is the channel that carries it instead.
func TestDescribe_MCPServerArgsReachNeitherWhatNorValue(t *testing.T) {
	bare := ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx"}
	armed := bare
	armed.Args = []string{"a · b", "mcp-fs@1.2.3"}

	bareWhat, bareValue := Describe(bare)
	armedWhat, armedValue := Describe(armed)
	if armedWhat != bareWhat {
		t.Fatalf("Describe() what = %q with args declared, want %q unchanged", armedWhat, bareWhat)
	}
	if armedValue != bareValue {
		t.Fatalf("Describe() value = %q with args declared, want %q unchanged", armedValue, bareValue)
	}
}

// A kind carrying no vector yields nil, so a reporter asks unconditionally
// instead of switching on the entity type a second time.
func TestArgs_ReturnsTheDeclaredVectorForMCPServersAndLSPServers(t *testing.T) {
	want := []string{"-y", "mcp-fs@1.2.3"}
	got := Args(ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx", Args: want})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Args() = %#v, want %#v", got, want)
	}
	if got := Args(ir.MCPServer{Name: "fs", Transport: ir.TransportStdio, Command: "npx"}); got != nil {
		t.Fatalf("Args() = %#v for a server declaring none, want nil", got)
	}

	lspWant := []string{"--stdio"}
	if got := Args(ir.LSPServer{Name: "go", Command: "gopls", Args: lspWant}); !reflect.DeepEqual(got, lspWant) {
		t.Fatalf("Args() = %#v, want %#v", got, lspWant)
	}

	if got := Args(ir.Hook{Event: "SessionStart", Command: "notify.sh"}); got != nil {
		t.Fatalf("Args() = %#v for a kind carrying no vector, want nil", got)
	}
}

// Only an element needing it is quoted: a raw control byte stays bare, while
// the literal backslash text Escape would spell it as is quoted.
func TestCommandLine_QuotesOnlyTheElementsThatNeedIt(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    string
	}{
		{"plain elements stay bare", "npx", []string{"-y", "mcp-fs@1.2.3"}, "npx -y mcp-fs@1.2.3"},
		{"a space", "npx", []string{"-y pkg"}, `npx "-y pkg"`},
		{"a tab", "npx", []string{"a\tb"}, "npx \"a\tb\""},
		{"a no-break space", "npx", []string{"a\u00a0b"}, "npx \"a\u00a0b\""},
		{"an empty element", "npx", []string{""}, `npx ""`},
		{"a quote", "npx", []string{`a"b`}, `npx "a\"b"`},
		{"a trailing backslash", "npx", []string{`a\`}, `npx "a\\"`},
		{"a literal escape spelling", "npx", []string{`\x1b`}, `npx "\\x1b"`},
		{"a raw control byte", "npx", []string{"\x1b[2J"}, "npx \x1b[2J"},
		{"the column separator", "npx", []string{"a · b"}, `npx "a · b"`},
		{"a bare column separator", "npx", []string{"a·b"}, "npx a·b"},
		{"a zero-width space", "npx", []string{"-y\u200bpkg"}, "npx \"-y\u200bpkg\""},
		{"a zero-width joiner", "npx", []string{"-y\u200dpkg"}, "npx \"-y\u200dpkg\""},
		{"a byte order mark", "npx", []string{"-y\ufeffpkg"}, "npx \"-y\ufeffpkg\""},
		{"a right-to-left override", "npx", []string{"-y\u202epkg"}, "npx \"-y\u202epkg\""},
		{"a hangul filler", "npx", []string{"-y\u3164pkg"}, "npx \"-y\u3164pkg\""},
		{"a braille blank", "npx", []string{"-y\u2800pkg"}, "npx \"-y\u2800pkg\""},
		{"an object replacement character", "npx", []string{"-y\ufffcpkg"}, "npx \"-y\ufffcpkg\""},
		{"a choseong filler", "npx", []string{"-y\u115fpkg"}, "npx \"-y\u115fpkg\""},
		{"a jungseong filler", "npx", []string{"-y\u1160pkg"}, "npx \"-y\u1160pkg\""},
		{"a halfwidth hangul filler", "npx", []string{"-y\uffa0pkg"}, "npx \"-y\uffa0pkg\""},
		{"a combining grapheme joiner", "npx", []string{"-y\u034fpkg"}, "npx \"-y\u034fpkg\""},
		{"a khmer inherent vowel aq", "npx", []string{"-y\u17b4pkg"}, "npx \"-y\u17b4pkg\""},
		{"a khmer inherent vowel aa", "npx", []string{"-y\u17b5pkg"}, "npx \"-y\u17b5pkg\""},
		{"a mongolian variation selector", "npx", []string{"-y\u180bpkg"}, "npx \"-y\u180bpkg\""},
		{"a mongolian variation selector four", "npx", []string{"-y\u180fpkg"}, "npx \"-y\u180fpkg\""},
		{"a variation selector one", "npx", []string{"-y\ufe00pkg"}, "npx \"-y\ufe00pkg\""},
		{"a variation selector sixteen", "npx", []string{"-y\ufe0fpkg"}, "npx \"-y\ufe0fpkg\""},
		{"a supplementary variation selector", "npx", []string{"-y\U000e0100pkg"}, "npx \"-y\U000e0100pkg\""},
		{"an unassigned default-ignorable", "npx", []string{"-y\u2065pkg"}, "npx \"-y\u2065pkg\""},
		{"an unassigned specials code point", "npx", []string{"-y\ufff0pkg"}, "npx \"-y\ufff0pkg\""},
		{"a command with a hangul filler", "npx\u3164-y", nil, "\"npx\u3164-y\""},
		{"a command with a space", "npx -y", nil, `"npx -y"`},
		{"a command with a space and args", "npx mcp-fs", []string{"-y"}, `"npx mcp-fs" -y`},
		{"a command with a quote", `run"x`, nil, `"run\"x"`},
		{"a command with a backslash", `C:\bin\srv.exe`, nil, `"C:\\bin\\srv.exe"`},
		{"a command with a raw control byte", "npx\x1b", nil, "npx\x1b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ir.MCPServer{Name: "srv", Transport: ir.TransportStdio, Command: tt.command, Args: tt.args}
			if got, ok := CommandLine(e); !ok || got != tt.want {
				t.Errorf("CommandLine() = (%q, %v), want (%q, true)", got, ok, tt.want)
			}
		})
	}
}

// Only a value that is an MCP or LSP server's own command is respelled; a
// value naming a helper, a forwarded variable or a url is left to Describe,
// and so is a server whose command is empty or a shell line such as a hook's.
func TestCommandLine_RespellsOnlyAValueThatIsTheServerCommand(t *testing.T) {
	args := []string{"-y", "pkg"}
	tests := []struct {
		name   string
		entity ir.Entity
		want   string
		wantOK bool
	}{
		{"stdio command", ir.MCPServer{Name: "s", Transport: ir.TransportStdio, Command: "npx", Args: args}, "npx -y pkg", true},
		{"stdio command with no vector", ir.MCPServer{Name: "s", Transport: ir.TransportStdio, Command: "npx -y"}, `"npx -y"`, true},
		{"lsp command", ir.LSPServer{Name: "go", Command: "gopls", Args: []string{"serve"}}, "gopls serve", true},
		{"lsp command with a space", ir.LSPServer{Name: "go", Command: "go pls"}, `"go pls"`, true},
		{"headers helper", ir.MCPServer{Name: "s", Transport: ir.TransportStdio, Command: "npx", Args: args, HeadersHelper: "./h.sh"}, "", false},
		{"forwarded env", ir.MCPServer{Name: "s", Transport: ir.TransportStdio, Command: "npx", Args: args, ForwardedEnv: "TOKEN"}, "", false},
		{"http url", ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, URL: "https://a", Command: "npx", Args: args}, "", false},
		{"stdio with no command", ir.MCPServer{Name: "s", Transport: ir.TransportStdio, URL: "https://a", Args: args}, "", false},
		{"lsp with no command", ir.LSPServer{Name: "go", Args: []string{"serve"}}, "", false},
		{"a hook shell line", ir.Hook{Event: "SessionStart", Command: "notify.sh --all"}, "", false},
		{"a status line shell line", ir.StatusLine{Command: "echo a b"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, ok := CommandLine(tt.entity); got != tt.want || ok != tt.wantOK {
				t.Errorf("CommandLine() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// A helper command and a forwarded variable name are each the value of their
// own finding, and what quotes the endpoint of the server they reach.
func TestDescribe_MCPServerNamesWhatItSendsAndWhere(t *testing.T) {
	tests := []struct {
		name      string
		entity    ir.MCPServer
		wantWhat  string
		wantValue string
	}{
		{
			name:      "headers helper",
			entity:    ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://a", HeadersHelper: "./headers.sh"},
			wantWhat:  `mcpServer docs (http) headers helper for url="https://a"`,
			wantValue: "./headers.sh",
		},
		{
			name:      "env var sent to a url",
			entity:    ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://a", ForwardedEnv: "DOCS_TOKEN"},
			wantWhat:  `mcpServer docs (http) env sent to url="https://a"`,
			wantValue: "DOCS_TOKEN",
		},
		{
			name:      "headers helper for a no-type server resolved to stdio with only a url",
			entity:    ir.MCPServer{Name: "docs", Transport: ir.TransportStdio, URL: "https://a", HeadersHelper: "./headers.sh"},
			wantWhat:  `mcpServer docs (stdio) headers helper for url="https://a"`,
			wantValue: "./headers.sh",
		},
		{
			name:      "env var sent to the command of a server that also declares a url",
			entity:    ir.MCPServer{Name: "dual", Transport: ir.TransportStdio, Command: "npx", URL: "https://a", ForwardedEnv: "LOCAL_TOKEN"},
			wantWhat:  `mcpServer dual (stdio) env sent to command="npx"`,
			wantValue: "LOCAL_TOKEN",
		},
		{
			name:      "env var sent to a command",
			entity:    ir.MCPServer{Name: "index", Transport: ir.TransportStdio, Command: "npx \"x\"", ForwardedEnv: "LOCAL_TOKEN"},
			wantWhat:  `mcpServer index (stdio) env sent to command="npx \"x\""`,
			wantValue: "LOCAL_TOKEN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			what, value := Describe(tt.entity)
			if what != tt.wantWhat || value != tt.wantValue {
				t.Errorf("Describe() = (%q, %q), want (%q, %q)", what, value, tt.wantWhat, tt.wantValue)
			}
		})
	}
}

// A declared token reaching "what" must not be able to forge a second pretty
// finding line: the byte is escaped, never folded to a space or left raw.
func TestDescribe_MCPServerUnrecognizedTransportControlBytesEscaped(t *testing.T) {
	what, _ := Describe(ir.MCPServer{
		Name:                  "legacy",
		Transport:             ir.TransportStdio,
		UnrecognizedTransport: "ban\nana",
	})
	if strings.ContainsRune(what, '\n') {
		t.Fatalf("Describe() what = %q, contains a raw newline byte", what)
	}
	if !strings.Contains(what, `\n`) {
		t.Fatalf("Describe() what = %q, want the literal escape sequence %q", what, `\n`)
	}
}
