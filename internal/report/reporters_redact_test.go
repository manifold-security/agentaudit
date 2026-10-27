package report_test

import (
	"bytes"
	stdjson "encoding/json"
	"html"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
	jsonreport "github.com/manifold-security/agentaudit/internal/report/json"
	mdreport "github.com/manifold-security/agentaudit/internal/report/md"
	"github.com/manifold-security/agentaudit/internal/report/pretty"
)

const canary = "c4n4ry0secret"

func credentialReport() finding.Report {
	entities := []ir.Entity{
		ir.MCPServer{Name: "args", Transport: ir.TransportStdio, Command: "npx", Args: []string{"--token", canary}},
		ir.MCPServer{Name: "remote", Transport: ir.TransportHTTP, URL: "https://u:" + canary + "@mcp.example.test/mcp?api_key=" + canary},
		ir.MCPServer{Name: "both", Transport: ir.TransportStdio, Command: "./srv", URL: "https://" + canary + "@both.example.test/"},
		ir.Hook{Event: "Stop", Command: "FOO_TOKEN=" + canary + " ./run.sh"},
		ir.EnvVar{Name: "API_KEY", Value: canary},
		ir.Hook{Event: "Stop", Command: `srv --env '{"token":"` + canary + `"}'`},
		ir.EnvVar{Name: "APP_CONFIG", Value: `{"Authorization": "Bearer ` + canary + `"}`},
		ir.MCPServer{Name: "json", Transport: ir.TransportStdio, Command: "srv", Args: []string{"--config", `{"password": "` + canary + `"}`}},
		ir.Hook{Event: "Stop", Command: `srv --password "correct ` + canary + ` battery" --verbose`},
		ir.MCPServer{Name: "spaced", Transport: ir.TransportStdio, Command: "srv", Args: []string{"--config", `{"token": "two ` + canary + `"}`}},
	}
	findings := make([]finding.Finding, len(entities))
	for i, e := range entities {
		findings[i] = finding.Finding{
			RuleID:     "test.rule",
			Agent:      "claude-code",
			Categories: []finding.Category{"code-execution"},
			Capability: finding.Capability{Entity: e, Provenance: finding.Provenance{File: ".mcp.json", Key: e.Kind()}},
		}
	}
	return finding.NewReport(findings)
}

// A rendered report shows each masked shape with its context and never the
// secret.
func TestReporters_PrintNoCredential(t *testing.T) {
	shared := []string{"https://***@mcp.example.test/mcp?api_key=***", `url="https://***@both.example.test/"`, "FOO_TOKEN=*** ./run.sh", "envVar API_KEY", `'{"token":"***"}'`, `{"Authorization": "Bearer ***"}`, `srv --password "***" --verbose`}
	withArgs := append([]string{"--token ***"}, shared...)
	prettyArgs := append([]string{`--config "{\\"password\\": \\"***\\"}"`, `--config "{\\"token\\": \\"***\\"}"`}, withArgs...)
	jsonArgs := append([]string{`--config {"password": "***"}`, `--config {"token": "***"}`}, withArgs...)

	tests := []struct {
		name    string
		render  func(*bytes.Buffer) error
		visible []string
		markup  bool
	}{
		{"pretty", func(b *bytes.Buffer) error {
			return pretty.Write(b, credentialReport(), pretty.Meta{Path: "."})
		}, prettyArgs, false},
		{"pretty explain", func(b *bytes.Buffer) error {
			return pretty.Write(b, credentialReport(), pretty.Meta{Path: ".", Explain: true})
		}, prettyArgs, false},
		{"md", func(b *bytes.Buffer) error {
			return mdreport.Write(b, credentialReport(), mdreport.Meta{Path: "."})
		}, shared, true},
		{"json", func(b *bytes.Buffer) error {
			var raw bytes.Buffer
			if err := jsonreport.Write(&raw, []jsonreport.Entry{{Report: credentialReport(), Meta: jsonreport.Meta{Path: "."}}}); err != nil {
				return err
			}
			b.Write(raw.Bytes())
			return decodedCapabilities(&raw, b)
		}, jsonArgs, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tt.render(&buf); err != nil {
				t.Fatalf("render error = %v", err)
			}
			out := buf.String()
			shown := out
			if tt.markup {
				shown = html.UnescapeString(out)
			}
			if strings.Contains(out, canary) || strings.Contains(shown, canary) {
				t.Errorf("output carries the secret %q:\n%s", canary, out)
			}
			for _, want := range tt.visible {
				if !strings.Contains(shown, want) {
					t.Errorf("output lacks %q:\n%s", want, shown)
				}
			}
		})
	}
}

func decodedCapabilities(raw, out *bytes.Buffer) error {
	var docs []struct {
		Findings []struct {
			Capability struct {
				What  string   `json:"what"`
				Value string   `json:"value"`
				Args  []string `json:"args"`
			} `json:"capability"`
		} `json:"findings"`
	}
	if err := stdjson.Unmarshal(raw.Bytes(), &docs); err != nil {
		return err
	}
	for _, d := range docs {
		for _, f := range d.Findings {
			c := f.Capability
			out.WriteString(c.What + " " + c.Value + " " + strings.Join(c.Args, " ") + "\n")
		}
	}
	return nil
}
