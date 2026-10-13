package codex

import (
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
)

func at(key string) ir.Location {
	return ir.Location{File: configFileName, Key: key}
}

func warningTexts(warnings []adapter.Warning) []string {
	var got []string
	for _, w := range warnings {
		got = append(got, w.Err.Error())
	}
	return got
}

// Transport follows from which endpoint a server declares, and servers are
// walked in name order whatever order the file spells them in.
func TestParseEmitsEachMCPServerWithItsTransport(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[mcp_servers.index]\ncommand = \"npx\"\nargs = [\"-y\", \"@acme/index\"]\n\n" +
			"[mcp_servers.index.env]\nINDEX_MODE = \"fast\"\n\n" +
			"[mcp_servers.docs]\nurl = \"https://mcp.example.test/mcp\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	want := []ir.Entity{
		ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", Location: at("mcp_servers.docs")},
		ir.MCPServer{
			Name:      "index",
			Transport: ir.TransportStdio,
			Command:   "npx",
			Args:      []string{"-y", "@acme/index"},
			Env:       map[string]string{"INDEX_MODE": "fast"},
			Location:  at("mcp_servers.index"),
		},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A server declaring both endpoints is reported as the stdio server its
// command starts, with its url kept beside the command, and the values each
// side of it declares still reach the report without a warning.
func TestParseReportsAnMCPServerDeclaringBothEndpointsAsStdio(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[mcp_servers.dual]\ncommand = \"npx\"\nargs = [\"serve\"]\nurl = \"https://mcp.example.test/mcp\"\n" +
			"env_vars = [\"LOCAL_TOKEN\"]\nbearer_token_env_var = \"DUAL_TOKEN\"\nhttp_headers_helper = \"./h.sh\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	dual := ir.MCPServer{Name: "dual", Transport: ir.TransportStdio, Command: "npx", URL: "https://mcp.example.test/mcp", Location: at("mcp_servers.dual")}
	local := dual
	local.ForwardedEnv, local.Location = "LOCAL_TOKEN", at("mcp_servers.dual.env_vars[0]")
	bearer := dual
	bearer.Transport, bearer.ForwardedEnv, bearer.Location = ir.TransportHTTP, "DUAL_TOKEN", at("mcp_servers.dual.bearer_token_env_var")
	helper := dual
	helper.Transport, helper.HeadersHelper, helper.Location = ir.TransportHTTP, "./h.sh", at("mcp_servers.dual.http_headers_helper")

	server := dual
	server.Args = []string{"serve"}

	want := []ir.Entity{server, local, bearer, helper}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// A server declaring no usable endpoint reaches no finding of its own, while
// the helper and the variables it declares are still reported with an empty
// destination. The warning names the endpoint that is missing or empty, and
// the well-formed server beside it is still reported.
func TestParseNamesAnMCPServerDeclaringNoEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{"neither", "", "mcp_servers.bad: expected a command or a url, found neither"},
		{"empty command", "command = \"\"\n", "mcp_servers.bad.command: expected a non-empty string, found an empty string"},
		{"empty url", "url = \"\"\n", "mcp_servers.bad.url: expected a non-empty string, found an empty string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS(
				"[mcp_servers.bad]\n" + tt.endpoint + "args = [\"serve\"]\nenv_vars = [\"LOCAL_TOKEN\"]\n" +
					"bearer_token_env_var = \"TOKEN\"\nhttp_headers_helper = \"./h.sh\"\n\n" +
					"[mcp_servers.ok]\ncommand = \"./ok.sh\"\n",
			))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}
			if got := warningTexts(warnings); !reflect.DeepEqual(got, []string{tt.want}) {
				t.Fatalf("warnings = %q, want %q", got, tt.want)
			}
			want := []ir.Entity{
				ir.MCPServer{Name: "bad", Transport: ir.TransportStdio, ForwardedEnv: "LOCAL_TOKEN", Location: at("mcp_servers.bad.env_vars[0]")},
				ir.MCPServer{Name: "bad", Transport: ir.TransportHTTP, ForwardedEnv: "TOKEN", Location: at("mcp_servers.bad.bearer_token_env_var")},
				ir.MCPServer{Name: "bad", Transport: ir.TransportHTTP, HeadersHelper: "./h.sh", Location: at("mcp_servers.bad.http_headers_helper")},
				ir.MCPServer{Name: "ok", Transport: ir.TransportStdio, Command: "./ok.sh", Location: at("mcp_servers.ok")},
			}
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
			}
		})
	}
}

// A value is read whichever transport its server resolves to, so a helper or
// variable declared on the other transport's side is still reported, with no
// warning.
func TestParseReadsBothSidesOfAnMCPServerWhateverItsTransport(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   []ir.Entity
	}{
		{
			name:   "http fields on a stdio server",
			server: "command = \"npx\"\nbearer_token_env_var = \"TOKEN\"\nenv_http_headers = { X-Team = \"TEAM_ID\" }\nhttp_headers_helper = \"./h.sh\"\n",
			want: []ir.Entity{
				ir.MCPServer{Name: "s", Transport: ir.TransportStdio, Command: "npx", Location: at("mcp_servers.s")},
				ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, Command: "npx", ForwardedEnv: "TOKEN", Location: at("mcp_servers.s.bearer_token_env_var")},
				ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, Command: "npx", ForwardedEnv: "TEAM_ID", Location: at("mcp_servers.s.env_http_headers.X-Team")},
				ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, Command: "npx", HeadersHelper: "./h.sh", Location: at("mcp_servers.s.http_headers_helper")},
			},
		},
		{
			name:   "env_vars on an http server",
			server: "url = \"https://mcp.example.test/mcp\"\nenv_vars = [\"LOCAL_TOKEN\"]\n",
			want: []ir.Entity{
				ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", Location: at("mcp_servers.s")},
				ir.MCPServer{Name: "s", Transport: ir.TransportStdio, URL: "https://mcp.example.test/mcp", ForwardedEnv: "LOCAL_TOKEN", Location: at("mcp_servers.s.env_vars[0]")},
			},
		},
		{
			name:   "env_vars beside an empty command and a url",
			server: "command = \"\"\nurl = \"https://mcp.example.test/mcp\"\nenv_vars = [\"LOCAL_TOKEN\"]\n",
			want: []ir.Entity{
				ir.MCPServer{Name: "s", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", Location: at("mcp_servers.s")},
				ir.MCPServer{Name: "s", Transport: ir.TransportStdio, URL: "https://mcp.example.test/mcp", ForwardedEnv: "LOCAL_TOKEN", Location: at("mcp_servers.s.env_vars[0]")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS("[mcp_servers.s]\n" + tt.server))
			if err != nil || len(warnings) != 0 {
				t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
			}
			if !reflect.DeepEqual(entities, tt.want) {
				t.Fatalf("Parse() entities = %+v, want %+v", entities, tt.want)
			}
		})
	}
}

// enabled = false switches a server off, together with everything it would
// send, while an enabled sibling and one that leaves the key unset are still
// reported.
func TestParseEmitsNothingForADisabledMCPServer(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[mcp_servers.off]\nenabled = false\nurl = \"https://mcp.example.test/off\"\nbearer_token_env_var = \"OFF_TOKEN\"\nhttp_headers_helper = \"./off.sh\"\n\n" +
			"[mcp_servers.on]\nenabled = true\ncommand = \"./on.sh\"\n\n" +
			"[mcp_servers.unset]\ncommand = \"./unset.sh\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{
		ir.MCPServer{Name: "on", Transport: ir.TransportStdio, Command: "./on.sh", Location: at("mcp_servers.on")},
		ir.MCPServer{Name: "unset", Transport: ir.TransportStdio, Command: "./unset.sh", Location: at("mcp_servers.unset")},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// An enabled value that is not a boolean is named in a warning, and the
// server is still reported rather than read as off.
func TestParseReportsAnMCPServerWhoseEnabledIsNotABoolean(t *testing.T) {
	entities, warnings, err := New().Parse(configFS("[mcp_servers.maybe]\nenabled = \"no\"\ncommand = \"./maybe.sh\"\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got, want := warningTexts(warnings), []string{"mcp_servers.maybe.enabled: expected a boolean, found a string"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %q, want %q", got, want)
	}
	want := []ir.Entity{ir.MCPServer{Name: "maybe", Transport: ir.TransportStdio, Command: "./maybe.sh", Location: at("mcp_servers.maybe")}}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// Each variable a server reads from the local environment reaches its own
// entity under the key that named it. An env_vars entry sourced from a
// remote executor is left out, while the string and local entries beside it
// are kept.
func TestParseEmitsEachLocalVariableAnMCPServerReceives(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[mcp_servers.docs]\nurl = \"https://mcp.example.test/mcp\"\n" +
			"bearer_token_env_var = \"DOCS_TOKEN\"\n" +
			"http_headers = { \"X-Region\" = \"us\" }\n" +
			"env_http_headers = { \"X-Team\" = \"TEAM_ID\", \"X-Api-Key\" = \"DOCS_API_KEY\" }\n\n" +
			"[mcp_servers.index]\ncommand = \"npx\"\n" +
			"env_vars = [\"LOCAL_TOKEN\", { name = \"SHELL_TOKEN\", source = \"local\" }, { name = \"REMOTE_TOKEN\", source = \"remote\" }, { name = \"PLAIN_TOKEN\" }]\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}

	docs := func(env, key string) ir.Entity {
		return ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", ForwardedEnv: env, Location: at(key)}
	}
	index := func(env, key string) ir.Entity {
		return ir.MCPServer{Name: "index", Transport: ir.TransportStdio, Command: "npx", ForwardedEnv: env, Location: at(key)}
	}
	want := []ir.Entity{
		docs("", "mcp_servers.docs"),
		docs("DOCS_TOKEN", "mcp_servers.docs.bearer_token_env_var"),
		docs("DOCS_API_KEY", "mcp_servers.docs.env_http_headers.X-Api-Key"),
		docs("TEAM_ID", "mcp_servers.docs.env_http_headers.X-Team"),
		index("", "mcp_servers.index"),
		index("LOCAL_TOKEN", "mcp_servers.index.env_vars[0]"),
		index("SHELL_TOKEN", "mcp_servers.index.env_vars[1]"),
		index("PLAIN_TOKEN", "mcp_servers.index.env_vars[3]"),
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The helper command reaches its own entity, which carries the url of the
// server it supplies headers for.
func TestParseEmitsTheHeadersHelperAnMCPServerRuns(t *testing.T) {
	entities, warnings, err := New().Parse(configFS(
		"[mcp_servers.docs]\nurl = \"https://mcp.example.test/mcp\"\nhttp_headers_helper = \"./scripts/headers.sh\"\n",
	))
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Parse() = (%v, %+v), want no failure", err, warnings)
	}
	want := []ir.Entity{
		ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", Location: at("mcp_servers.docs")},
		ir.MCPServer{Name: "docs", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", HeadersHelper: "./scripts/headers.sh", Location: at("mcp_servers.docs.http_headers_helper")},
	}
	if !reflect.DeepEqual(entities, want) {
		t.Fatalf("Parse() entities = %+v, want %+v", entities, want)
	}
}

// The well-formed values beside a malformed one, in its own table or array
// or another server, still reach the report.
func TestParseSkipsAMalformedMCPValueAlone(t *testing.T) {
	ok := ir.MCPServer{Name: "zz", Transport: ir.TransportStdio, Command: "./ok.sh", Location: at("mcp_servers.zz")}
	stdio := func(env, key string) ir.MCPServer {
		return ir.MCPServer{Name: "bad", Transport: ir.TransportStdio, Command: "npx", ForwardedEnv: env, Location: at(key)}
	}
	http := func(env, key string) ir.MCPServer {
		return ir.MCPServer{Name: "bad", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/mcp", ForwardedEnv: env, Location: at(key)}
	}
	bare := stdio("", "mcp_servers.bad")
	withEnv := bare
	withEnv.Env = map[string]string{"GOOD": "1"}
	withArgs := bare
	withArgs.Args = []string{"serve"}
	unreadCommand := ir.MCPServer{Name: "bad", Transport: ir.TransportStdio, Location: at("mcp_servers.bad")}
	unreadCommandEnv := unreadCommand
	unreadCommandEnv.ForwardedEnv, unreadCommandEnv.Location = "GOOD", at("mcp_servers.bad.env_vars[0]")
	unreadCommandBesideURL := ir.MCPServer{Name: "bad", Transport: ir.TransportStdio, URL: "https://mcp.example.test/mcp", ForwardedEnv: "GOOD", Location: at("mcp_servers.bad.env_vars[0]")}
	unreadURL := ir.MCPServer{Name: "bad", Transport: ir.TransportHTTP, Location: at("mcp_servers.bad")}
	unreadURLEnv := unreadURL
	unreadURLEnv.ForwardedEnv, unreadURLEnv.Location = "TOKEN", at("mcp_servers.bad.bearer_token_env_var")

	tests := []struct {
		name   string
		server string
		want   string
		wantAt []ir.Entity
	}{
		{"server not a table", "[mcp_servers]\nbad = \"npx\"\n", "mcp_servers.bad: expected a table, found a string", nil},
		{"command not a string", "[mcp_servers.bad]\ncommand = [\"npx\"]\nenv_vars = [\"GOOD\"]\n", "mcp_servers.bad.command: expected a string, found an array", []ir.Entity{unreadCommand, unreadCommandEnv}},
		{"command not a string beside a url", "[mcp_servers.bad]\ncommand = [\"npx\"]\nurl = \"https://mcp.example.test/mcp\"\nenv_vars = [\"GOOD\"]\n", "mcp_servers.bad.command: expected a string, found an array", []ir.Entity{http("", "mcp_servers.bad"), unreadCommandBesideURL}},
		{"url not a string", "[mcp_servers.bad]\nurl = 7\nbearer_token_env_var = \"TOKEN\"\n", "mcp_servers.bad.url: expected a string, found a value of another type", []ir.Entity{unreadURL, unreadURLEnv}},
		{"arg not a string", "[mcp_servers.bad]\ncommand = \"npx\"\nargs = [\"serve\", 7]\n", "mcp_servers.bad.args[1]: expected a string, found a value of another type", []ir.Entity{withArgs}},
		{"env value not a string", "[mcp_servers.bad]\ncommand = \"npx\"\nenv = { BAD = 1, GOOD = \"1\" }\n", "mcp_servers.bad.env.BAD: expected a string, found a value of another type", []ir.Entity{withEnv}},
		{"env_vars entry of another form", "[mcp_servers.bad]\ncommand = \"npx\"\nenv_vars = [7, \"GOOD\"]\n", "mcp_servers.bad.env_vars[0]: expected a variable name or a table, found a value of another type", []ir.Entity{bare, stdio("GOOD", "mcp_servers.bad.env_vars[1]")}},
		{"env_vars name missing", "[mcp_servers.bad]\ncommand = \"npx\"\nenv_vars = [{ source = \"local\" }, \"GOOD\"]\n", "mcp_servers.bad.env_vars[0].name: expected a non-empty string, found none", []ir.Entity{bare, stdio("GOOD", "mcp_servers.bad.env_vars[1]")}},
		{"env_vars source unrecognised", "[mcp_servers.bad]\ncommand = \"npx\"\nenv_vars = [{ name = \"LOCALCAP\", source = \"Local\" }, \"GOOD\"]\n", `mcp_servers.bad.env_vars[0].source: expected one of local or remote, found "Local"`, []ir.Entity{bare, stdio("LOCALCAP", "mcp_servers.bad.env_vars[0]"), stdio("GOOD", "mcp_servers.bad.env_vars[1]")}},
		{"bearer not a string", "[mcp_servers.bad]\nurl = \"https://mcp.example.test/mcp\"\nbearer_token_env_var = 7\nenv_http_headers = { X-Team = \"TEAM_ID\" }\n", "mcp_servers.bad.bearer_token_env_var: expected a string, found a value of another type", []ir.Entity{http("", "mcp_servers.bad"), http("TEAM_ID", "mcp_servers.bad.env_http_headers.X-Team")}},
		{"env header not a string", "[mcp_servers.bad]\nurl = \"https://mcp.example.test/mcp\"\nenv_http_headers = { X-Bad = [\"A\"], X-Team = \"TEAM_ID\" }\n", "mcp_servers.bad.env_http_headers.X-Bad: expected a string, found an array", []ir.Entity{http("", "mcp_servers.bad"), http("TEAM_ID", "mcp_servers.bad.env_http_headers.X-Team")}},
		{"helper not a string", "[mcp_servers.bad]\nurl = \"https://mcp.example.test/mcp\"\nhttp_headers_helper = [\"./h.sh\"]\nbearer_token_env_var = \"TOKEN\"\n", "mcp_servers.bad.http_headers_helper: expected a string, found an array", []ir.Entity{http("", "mcp_servers.bad"), http("TOKEN", "mcp_servers.bad.bearer_token_env_var")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entities, warnings, err := New().Parse(configFS(tt.server + "\n[mcp_servers.zz]\ncommand = \"./ok.sh\"\n"))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil: a malformed value degrades", err)
			}
			if got := warningTexts(warnings); !reflect.DeepEqual(got, []string{tt.want}) {
				t.Fatalf("warnings = %q, want %q", got, tt.want)
			}
			want := append(tt.wantAt, ok)
			if !reflect.DeepEqual(entities, want) {
				t.Fatalf("Parse() entities = %+v, want the well-formed values %+v", entities, want)
			}
		})
	}
}

// An mcp_servers value that is not a table is named in a warning and leaves
// the rest of the document read.
func TestParseNamesAnMCPServersValueThatIsNotATable(t *testing.T) {
	entities, warnings, err := New().Parse(configFS("mcp_servers = [\"npx\"]\nsandbox_mode = \"danger-full-access\"\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got, want := warningTexts(warnings), []string{"mcp_servers: expected a table, found an array"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("warnings = %q, want %q", got, want)
	}
	if len(entities) != 1 || entities[0].Kind() != ir.KindSandbox {
		t.Fatalf("Parse() entities = %+v, want the sandbox mode beside it", entities)
	}
}
