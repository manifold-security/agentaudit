package json_test

import (
	"bytes"
	"encoding/hex"
	stdjson "encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/finding"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/report"
	jsonreporter "github.com/manifold-security/agentaudit/internal/report/json"
	"github.com/manifold-security/agentaudit/internal/report/reportfixture"
)

var update = flag.Bool("update", false, "update golden files")

type findingDoc struct {
	ID         string   `json:"id"`
	Agent      string   `json:"agent"`
	RuleID     string   `json:"ruleId"`
	Categories []string `json:"categories"`
	Message    string   `json:"message"`
	References []string `json:"references"`
	Capability struct {
		Kind  string   `json:"kind"`
		What  string   `json:"what"`
		Value string   `json:"value"`
		Args  []string `json:"args"`
		File  string   `json:"file"`
		Key   string   `json:"key"`
	} `json:"capability"`
}

type reportDoc struct {
	Path          string       `json:"path"`
	ScannedAgents []string     `json:"scannedAgents"`
	Findings      []findingDoc `json:"findings"`
	Counts        struct {
		Findings          int `json:"findings"`
		Files             int `json:"files"`
		Categories        int `json:"categories"`
		UnreadableSources int `json:"unreadableSources"`
		UnparsedSources   int `json:"unparsedSources"`
	} `json:"counts"`
}

// Write's stdout/file contract is one JSON array for every N, including N=1:
// the decoded value is always a slice, its length equals the entry count,
// and each element's path distinguishes it.
func TestWrite_EncodesOneArrayElementPerEntry(t *testing.T) {
	tests := []struct {
		name    string
		entries []jsonreporter.Entry
	}{
		{"one entry", []jsonreporter.Entry{
			{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "a"}},
		}},
		{"two entries", []jsonreporter.Entry{
			{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "a"}},
			{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "b"}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := jsonreporter.Write(&buf, tt.entries); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}

			var docs []reportDoc
			if err := stdjson.Unmarshal(buf.Bytes(), &docs); err != nil {
				t.Fatalf("Unmarshal() error = %v, want a JSON array; got: %s", err, buf.String())
			}
			if len(docs) != len(tt.entries) {
				t.Fatalf("len(docs) = %d, want %d", len(docs), len(tt.entries))
			}
			for i, want := range tt.entries {
				if docs[i].Path != want.Meta.Path {
					t.Fatalf("docs[%d].Path = %q, want %q", i, docs[i].Path, want.Meta.Path)
				}
			}
		})
	}
}

// Each finding's decoded agent equals its own Finding.Agent (not a single
// document-wide label) and the decoded document itself carries no top-level
// "agent" key, while still carrying path/findings/counts — the companion
// proof the decode actually ran, so the absence assertion is not vacuous.
func TestWrite_PerFindingAgentPresentDocumentLevelAgentAbsent(t *testing.T) {
	findings := []finding.Finding{
		{
			RuleID: "secrets.env-plaintext",
			Agent:  "claude-code",
			Capability: finding.Capability{
				Entity:     ir.EnvVar{Name: "API_KEY", Value: "secret"},
				Provenance: finding.Provenance{File: "settings.json", Key: "env.API_KEY"},
			},
		},
		{
			RuleID: "secrets.env-plaintext",
			Agent:  "mirror-agent",
			Capability: finding.Capability{
				Entity:     ir.EnvVar{Name: "OTHER_KEY", Value: "secret"},
				Provenance: finding.Provenance{File: "settings.json", Key: "env.OTHER_KEY"},
			},
		},
	}
	rep := finding.NewReport(findings)

	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: rep, Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	var rawDocs []map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(buf.Bytes(), &rawDocs); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(rawDocs) != 1 {
		t.Fatalf("len(rawDocs) = %d, want 1", len(rawDocs))
	}
	doc := rawDocs[0]

	for _, key := range []string{"path", "findings", "counts"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("decoded document missing key %q, want it present (proves the decode ran)", key)
		}
	}
	if _, ok := doc["agent"]; ok {
		t.Fatalf("decoded document has a top-level %q key, want it absent", "agent")
	}

	var docFindings []findingDoc
	if err := stdjson.Unmarshal(doc["findings"], &docFindings); err != nil {
		t.Fatalf("Unmarshal(findings) error = %v", err)
	}
	if len(docFindings) != len(findings) {
		t.Fatalf("len(docFindings) = %d, want %d", len(docFindings), len(findings))
	}
	for i, f := range findings {
		if docFindings[i].Agent != f.Agent {
			t.Fatalf("docFindings[%d].Agent = %q, want %q", i, docFindings[i].Agent, f.Agent)
		}
	}
}

// The primary spec scenario: the shared reportfixture spanning multiple
// entity kinds, rendered deterministically and compared against a pinned
// golden file.
func TestWrite_Golden(t *testing.T) {
	const goldenPath = "testdata/report.golden"

	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	if *update {
		if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", goldenPath, err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to generate it)", goldenPath, err)
	}
	if buf.String() != string(want) {
		t.Fatalf("Write() output mismatch\n--- got ---\n%s\n--- want ---\n%s", buf.String(), string(want))
	}
}

// Two findings sharing one entity+provenance under different RuleIDs produce
// distinct id and message values, never a byte-identical pair.
func TestWrite_DuplicateEntityDistinctRuleIDsProduceDistinctEntries(t *testing.T) {
	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	var docs []reportDoc
	if err := stdjson.Unmarshal(buf.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	doc := docs[0]

	var shared []findingDoc
	for _, f := range doc.Findings {
		if f.Capability.Value == "npx mcp-fs" {
			shared = append(shared, f)
		}
	}
	if len(shared) != 2 {
		t.Fatalf("found %d findings sharing capability.value %q, want 2", len(shared), "npx mcp-fs")
	}
	if shared[0].ID == shared[1].ID {
		t.Fatalf("shared[0].ID == shared[1].ID == %q, want distinct ids", shared[0].ID)
	}
	if shared[0].Message == shared[1].Message {
		t.Fatalf("shared[0].Message == shared[1].Message == %q, want distinct messages", shared[0].Message)
	}
}

// Each finding's id is a fixed-width lowercase hex digest of Finding.ID():
// stable across independent renders of the same fixture, and distinct for
// the two findings that share one entity and provenance under different
// RuleIDs — the digest must not collapse that distinctness.
func TestWrite_IDIsDeterministicHexDigest(t *testing.T) {
	const wantIDLen = 32

	var first, second bytes.Buffer
	if err := jsonreporter.Write(&first, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() first render error = %v, want nil", err)
	}
	if err := jsonreporter.Write(&second, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() second render error = %v, want nil", err)
	}

	var firstDocs, secondDocs []reportDoc
	if err := stdjson.Unmarshal(first.Bytes(), &firstDocs); err != nil {
		t.Fatalf("Unmarshal(first) error = %v", err)
	}
	if err := stdjson.Unmarshal(second.Bytes(), &secondDocs); err != nil {
		t.Fatalf("Unmarshal(second) error = %v", err)
	}
	firstDoc, secondDoc := firstDocs[0], secondDocs[0]
	if len(firstDoc.Findings) != len(secondDoc.Findings) {
		t.Fatalf("first render has %d findings, second has %d, want equal", len(firstDoc.Findings), len(secondDoc.Findings))
	}

	var shared []string
	for i, f := range firstDoc.Findings {
		if len(f.ID) != wantIDLen {
			t.Fatalf("finding[%d].id = %q (len %d), want a %d-character hex digest", i, f.ID, len(f.ID), wantIDLen)
		}
		if _, err := hex.DecodeString(f.ID); err != nil {
			t.Fatalf("finding[%d].id = %q is not valid hex: %v", i, f.ID, err)
		}
		if f.ID != secondDoc.Findings[i].ID {
			t.Fatalf("finding[%d].id differs across independent renders of the same fixture: %q vs %q", i, f.ID, secondDoc.Findings[i].ID)
		}
		if f.Capability.Value == "npx mcp-fs" {
			shared = append(shared, f.ID)
		}
	}
	if len(shared) != 2 {
		t.Fatalf("found %d ids sharing capability.value %q, want 2", len(shared), "npx mcp-fs")
	}
	if shared[0] == shared[1] {
		t.Fatalf("digest collapsed two distinct RuleIDs to the same id %q", shared[0])
	}
}

// A finding whose Go References slice is nil still serializes as a JSON
// array, never null.
func TestWrite_ReferencesAndCategoriesAreArraysNeverNull(t *testing.T) {
	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	if bytes.Contains(buf.Bytes(), []byte(`"references":null`)) {
		t.Fatalf("Write() output contains a null references field, want it always normalized to an array")
	}
	if bytes.Contains(buf.Bytes(), []byte(`"categories":null`)) {
		t.Fatalf("Write() output contains a null categories field, want it always normalized to an array")
	}

	var docs []reportDoc
	if err := stdjson.Unmarshal(buf.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	doc := docs[0]
	var found bool
	for _, f := range doc.Findings {
		if f.RuleID == "mcp.unpinned-npx-command" {
			found = true
			if f.References == nil {
				t.Fatalf("finding %q References unmarshaled to nil, want a non-nil empty slice", f.RuleID)
			}
			if len(f.References) != 0 {
				t.Fatalf("finding %q References = %v, want empty", f.RuleID, f.References)
			}
		}
	}
	if !found {
		t.Fatalf("fixture missing expected RuleID %q", "mcp.unpinned-npx-command")
	}
}

// The document carries the scanned set whether or not the report holds a
// finding, so a consumer reading a clean scan branches on an empty list
// rather than on a missing key or on prose.
func TestWrite_ScannedAgentsIsNeverNullWithOrWithoutFindings(t *testing.T) {
	tests := []struct {
		name   string
		report finding.Report
		want   []string
	}{
		{"findings, no agent ran", reportfixture.Report(), []string{}},
		{"findings, two ran in the order given", reportfixture.Report().WithScannedAgents([]string{"cursor", "claude-code"}), []string{"cursor", "claude-code"}},
		{"no findings, no agent ran", finding.NewReport(nil), []string{}},
		{"no findings, one agent ran", finding.NewReport(nil).WithScannedAgents([]string{"claude-code"}), []string{"claude-code"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: tt.report, Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
				t.Fatalf("Write() error = %v, want nil", err)
			}
			if bytes.Contains(buf.Bytes(), []byte(`"scannedAgents": null`)) {
				t.Fatalf("Write() output = %s, want scannedAgents normalized to an array", buf.String())
			}

			var docs []reportDoc
			if err := stdjson.Unmarshal(buf.Bytes(), &docs); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if docs[0].ScannedAgents == nil {
				t.Fatalf("scannedAgents unmarshaled to nil, want a non-nil slice")
			}
			if got := docs[0].ScannedAgents; !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("scannedAgents = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The two counts under counts are what distinguish a clean render from a
// degraded one over the same fixture, and they move independently.
func TestWrite_DegradedReportDistinguishableFromClean(t *testing.T) {
	var clean, degraded bytes.Buffer
	if err := jsonreporter.Write(&clean, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() clean error = %v, want nil", err)
	}
	degradedReport := reportfixture.Report().WithUnreadableSources(3).WithUnparsedSources(2)
	if err := jsonreporter.Write(&degraded, []jsonreporter.Entry{{Report: degradedReport, Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() degraded error = %v, want nil", err)
	}

	var cleanDocs, degradedDocs []reportDoc
	if err := stdjson.Unmarshal(clean.Bytes(), &cleanDocs); err != nil {
		t.Fatalf("Unmarshal(clean) error = %v", err)
	}
	if err := stdjson.Unmarshal(degraded.Bytes(), &degradedDocs); err != nil {
		t.Fatalf("Unmarshal(degraded) error = %v", err)
	}
	cleanDoc, degradedDoc := cleanDocs[0], degradedDocs[0]

	if cleanDoc.Counts.UnreadableSources != 0 {
		t.Fatalf("clean render counts.unreadableSources = %d, want 0", cleanDoc.Counts.UnreadableSources)
	}
	if degradedDoc.Counts.UnreadableSources != 3 {
		t.Fatalf("degraded render counts.unreadableSources = %d, want 3", degradedDoc.Counts.UnreadableSources)
	}
	if cleanDoc.Counts.UnparsedSources != 0 {
		t.Fatalf("clean render counts.unparsedSources = %d, want 0", cleanDoc.Counts.UnparsedSources)
	}
	if degradedDoc.Counts.UnparsedSources != 2 {
		t.Fatalf("degraded render counts.unparsedSources = %d, want 2", degradedDoc.Counts.UnparsedSources)
	}
	if !bytes.Contains(degraded.Bytes(), []byte(`"unparsedSources": 2`)) {
		t.Fatalf("degraded render = %s, want the unparsedSources key spelled exactly", degraded.String())
	}
}

// TestWrite_NeverLeaksRawEntityIdentity proves that once the output is
// decoded back into Go values, no string field anywhere in the document
// contains the 0x1f control byte — neither id (which digests Finding.ID(),
// removing its embedded separator) nor capability.what/value (which must
// never surface the entity's raw Identity()). Asserting on the encoder's raw
// bytes would be vacuous: encoding/json always escapes control bytes to
// \uXXXX, so this must check the decoded values instead.
func TestWrite_NeverLeaksRawEntityIdentity(t *testing.T) {
	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: reportfixture.Report(), Meta: jsonreporter.Meta{Path: "."}}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	var decoded interface{}
	if err := stdjson.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	walkJSONStrings("$", decoded, func(path, s string) {
		if strings.ContainsRune(s, '\x1f') {
			t.Fatalf("decoded value at %s = %q contains a raw 0x1f control byte, want it never surfaced", path, s)
		}
	})
}

// The walker inspects a decoded object's keys, not only its values — a JSON
// object key is an ordinary Go string once decoded and could carry the same
// control byte a value could.
func TestWalkJSONStrings_VisitsMapKeysToo(t *testing.T) {
	sample := map[string]interface{}{
		"safe key":       "safe value",
		"leak\x1fed key": "another safe value",
	}

	var sawLeak bool
	walkJSONStrings("$", sample, func(path, s string) {
		if strings.ContainsRune(s, '\x1f') {
			sawLeak = true
		}
	})
	if !sawLeak {
		t.Fatalf("walkJSONStrings never visited the map key carrying a 0x1f control byte")
	}
}

// Every rendered field is checked independently, since report.Escape is the
// identity on printable text and so cannot be told apart from an untouched
// field by a golden comparison, only by an explicit per-field check like
// this one.
func TestWrite_HazardousReport_RoundTripsRawBytesUnescaped(t *testing.T) {
	rep := reportfixture.HazardousReport()
	meta := jsonreporter.Meta{Path: "target\x1b[2Jdir"}

	var buf bytes.Buffer
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{{Report: rep, Meta: meta}}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}

	var docs []reportDoc
	if err := stdjson.Unmarshal(buf.Bytes(), &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1", len(docs))
	}

	if docs[0].Path != meta.Path {
		t.Fatalf("decoded path = %q, want %q (byte-for-byte, unescaped by report.Escape)", docs[0].Path, meta.Path)
	}

	src := rep.Findings()
	if len(docs[0].Findings) != len(src) {
		t.Fatalf("decoded %d findings, want %d", len(docs[0].Findings), len(src))
	}
	for i, f := range src {
		wantWhat, wantValue := report.Describe(f.Capability.Entity)
		got := docs[0].Findings[i]

		if got.Capability.File != f.Capability.Provenance.File {
			t.Fatalf("finding %d: decoded capability.file = %q, want %q", i, got.Capability.File, f.Capability.Provenance.File)
		}
		if got.Capability.Key != f.Capability.Provenance.Key {
			t.Fatalf("finding %d: decoded capability.key = %q, want %q", i, got.Capability.Key, f.Capability.Provenance.Key)
		}
		if got.Capability.What != wantWhat {
			t.Fatalf("finding %d: decoded capability.what = %q, want %q", i, got.Capability.What, wantWhat)
		}
		if got.Capability.Value != wantValue {
			t.Fatalf("finding %d: decoded capability.value = %q, want %q", i, got.Capability.Value, wantValue)
		}
		if got.Message != f.Message {
			t.Fatalf("finding %d: decoded message = %q, want %q", i, got.Message, f.Message)
		}
		if got.Agent != f.Agent {
			t.Fatalf("finding %d: decoded agent = %q, want %q", i, got.Agent, f.Agent)
		}
	}
}

func renderOne(t *testing.T, findings ...finding.Finding) []byte {
	t.Helper()
	var buf bytes.Buffer
	entry := jsonreporter.Entry{Report: finding.NewReport(findings), Meta: jsonreporter.Meta{Path: "."}}
	if err := jsonreporter.Write(&buf, []jsonreporter.Entry{entry}); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
	return buf.Bytes()
}

// rawCapabilities decodes each finding's capability object into a key map
// rather than a struct, so a key's ABSENCE is observable instead of being
// smoothed into a zero value.
func rawCapabilities(t *testing.T, out []byte) []map[string]stdjson.RawMessage {
	t.Helper()
	var docs []struct {
		Findings []struct {
			Capability map[string]stdjson.RawMessage `json:"capability"`
		} `json:"findings"`
	}
	if err := stdjson.Unmarshal(out, &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v; got: %s", err, out)
	}
	if len(docs) != 1 {
		t.Fatalf("len(docs) = %d, want 1", len(docs))
	}
	caps := make([]map[string]stdjson.RawMessage, len(docs[0].Findings))
	for i, f := range docs[0].Findings {
		caps[i] = f.Capability
	}
	return caps
}

func mcpFinding(ruleID string, entity ir.MCPServer) finding.Finding {
	return finding.Finding{
		RuleID: ruleID,
		Capability: finding.Capability{
			Entity:     entity,
			Provenance: finding.Provenance{File: ".mcp.json", Key: "mcpServers." + entity.Name},
		},
	}
}

// A stdio server's bare command names only a runtime (npx, docker, uvx);
// the declared vector is what names the payload it actually runs.
func TestWrite_MCPServerArgsDecodeOneElementPerDeclaredArg(t *testing.T) {
	args := []string{"-y", "chrome-devtools-mcp@latest", "--headless"}
	out := renderOne(t, mcpFinding("mcp.stdio", ir.MCPServer{
		Name: "tools", Transport: ir.TransportStdio, Command: "npx", Args: args,
	}))

	var docs []reportDoc
	if err := stdjson.Unmarshal(out, &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v; got: %s", err, out)
	}
	got := docs[0].Findings[0].Capability
	if !reflect.DeepEqual(got.Args, args) {
		t.Fatalf("capability.args = %#v, want %#v", got.Args, args)
	}
	if got.Value != "npx" {
		t.Fatalf("capability.value = %q, want the endpoint alone, never the args joined into it", got.Value)
	}
}

// A hostile arg must decode back byte for byte as its own element: the
// array boundary is structural, so no declared byte can fabricate an extra
// element or merge two into one.
func TestWrite_MCPServerHostileArgsDecodeElementForElement(t *testing.T) {
	args := []string{"a · b", "c\nd", `e" f`, "--flag=g · npx · benign.json"}
	out := renderOne(t, mcpFinding("mcp.stdio", ir.MCPServer{
		Name: "srv", Transport: ir.TransportStdio, Command: "npx", Args: args,
	}))

	var docs []reportDoc
	if err := stdjson.Unmarshal(out, &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v; got: %s", err, out)
	}
	if got := docs[0].Findings[0].Capability.Args; !reflect.DeepEqual(got, args) {
		t.Fatalf("capability.args = %#v, want %#v", got, args)
	}
}

// The args-carrying finding is the positive control proving the key is
// emitted when there is something to emit.
func TestWrite_ArgsKeyAbsentWhenNoVectorWasDeclared(t *testing.T) {
	out := renderOne(t,
		finding.Finding{
			RuleID: "hook.autostart",
			Capability: finding.Capability{
				Entity:     ir.Hook{Event: "SessionStart", Command: "notify.sh"},
				Provenance: finding.Provenance{File: ".claude/settings.json", Key: "hooks[0]"},
			},
		},
		mcpFinding("mcp.stdio", ir.MCPServer{Name: "bare", Transport: ir.TransportStdio, Command: "srv-bin"}),
		mcpFinding("mcp.stdio", ir.MCPServer{Name: "armed", Transport: ir.TransportStdio, Command: "npx", Args: []string{"-y", "pkg"}}),
	)

	caps := rawCapabilities(t, out)
	if len(caps) != 3 {
		t.Fatalf("decoded %d capabilities, want 3", len(caps))
	}
	for i, want := range []bool{false, false, true} {
		if _, ok := caps[i]["args"]; ok != want {
			t.Fatalf("capability[%d] args key present = %v, want %v (capability: %v)", i, ok, want, caps[i])
		}
	}
	if bytes.Contains(out, []byte(`"args":null`)) {
		t.Fatalf("Write() output contains a null args field\noutput:\n%s", out)
	}
}

// An http server reaches a host rather than spawning a process, so value
// stays its url — but a config may still declare a vector beside that url,
// and dropping it would hide a declaration. It surfaces in its own array,
// never folded into the endpoint string.
func TestWrite_HTTPServerArgsStayStructuredBesideTheURL(t *testing.T) {
	args := []string{"--insecure"}
	out := renderOne(t,
		mcpFinding("mcp.http", ir.MCPServer{Name: "plain", Transport: ir.TransportHTTP, URL: "https://a.tld/mcp"}),
		mcpFinding("mcp.http", ir.MCPServer{Name: "armed", Transport: ir.TransportHTTP, URL: "https://b.tld/mcp", Args: args}),
	)

	var docs []reportDoc
	if err := stdjson.Unmarshal(out, &docs); err != nil {
		t.Fatalf("Unmarshal() error = %v; got: %s", err, out)
	}
	plain, armed := docs[0].Findings[0].Capability, docs[0].Findings[1].Capability
	if plain.Args != nil {
		t.Fatalf("plain http capability.args = %#v, want absent", plain.Args)
	}
	if plain.Value != "https://a.tld/mcp" {
		t.Fatalf("plain http capability.value = %q, want its url", plain.Value)
	}
	if !reflect.DeepEqual(armed.Args, args) {
		t.Fatalf("armed http capability.args = %#v, want %#v", armed.Args, args)
	}
	if armed.Value != "https://b.tld/mcp" {
		t.Fatalf("armed http capability.value = %q, want its url with no arg folded in", armed.Value)
	}
}

func walkJSONStrings(path string, v interface{}, fn func(path, s string)) {
	switch t := v.(type) {
	case string:
		fn(path, t)
	case []interface{}:
		for i, e := range t {
			walkJSONStrings(fmt.Sprintf("%s[%d]", path, i), e, fn)
		}
	case map[string]interface{}:
		for k, e := range t {
			keyPath := path + "." + k
			fn(keyPath+"#key", k)
			walkJSONStrings(keyPath, e, fn)
		}
	}
}
