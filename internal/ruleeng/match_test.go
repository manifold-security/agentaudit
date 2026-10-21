package ruleeng

import (
	"encoding/json"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/manifold-security/agentaudit/internal/adapters/claude"
	"github.com/manifold-security/agentaudit/internal/ir"
)

// fixture entities exercising every field kind the operator matrix covers:
// string (Command), named-string (Transport), []string (Args/Tools), and
// map[string]string (Env). Location is populated on both to prove it is
// never matchable.
func fixtureMCPServer() ir.MCPServer {
	return ir.MCPServer{
		Name:      "srv",
		Transport: ir.TransportStdio,
		Command:   "run-server --unsafe",
		Args:      []string{"--flag", "--danger"},
		Env:       map[string]string{"TOKEN": "secret"},
		Location:  ir.Location{File: "f.json", Key: "k"},
	}
}

func fixtureMCPServerEmpty() ir.MCPServer {
	return ir.MCPServer{Name: "empty", Location: ir.Location{File: "f2.json"}}
}

func fixtureSubagent() ir.Subagent {
	return ir.Subagent{
		Name:     "reviewer",
		Tools:    []string{"bash", "webfetch"},
		Location: ir.Location{File: "sub.json"},
	}
}

// oneCondRule wraps a single Condition in an otherwise-default (AND) Match
// so operator tests can call Eval directly.
func oneCondRule(field, op string, value json.RawMessage) Rule {
	return Rule{
		Target: ir.KindMCPServer,
		Match: Match{
			Rules: []Condition{{Field: field, Op: op, Value: value}},
		},
	}
}

type opCase struct {
	name   string
	entity ir.Entity
	field  string
	op     string
	value  json.RawMessage
	want   bool
}

func runOpCases(t *testing.T, cases []opCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := oneCondRule(tc.field, tc.op, tc.value)
			if got := Eval(rule, tc.entity); got != tc.want {
				t.Fatalf("Eval(%s %s) = %v, want %v", tc.field, tc.op, got, tc.want)
			}
		})
	}
}

func TestEvalExists(t *testing.T) {
	// exists has no incompatible field kind to test, so this operator has no
	// TYPE-MISMATCH row.
	runOpCases(t, []opCase{
		{"positive string", fixtureMCPServer(), "Command", OpExists, json.RawMessage(`null`), true},
		{"negative string", fixtureMCPServerEmpty(), "Command", OpExists, json.RawMessage(`null`), false},
		{"positive named-string", fixtureMCPServer(), "Transport", OpExists, json.RawMessage(`null`), true},
		{"negative named-string", fixtureMCPServerEmpty(), "Transport", OpExists, json.RawMessage(`null`), false},
		{"positive slice", fixtureMCPServer(), "Args", OpExists, json.RawMessage(`null`), true},
		{"negative slice", fixtureMCPServerEmpty(), "Args", OpExists, json.RawMessage(`null`), false},
		{"positive map", fixtureMCPServer(), "Env", OpExists, json.RawMessage(`null`), true},
		{"negative map", fixtureMCPServerEmpty(), "Env", OpExists, json.RawMessage(`null`), false},
	})
}

func TestEvalEquals(t *testing.T) {
	runOpCases(t, []opCase{
		{"positive string", fixtureMCPServer(), "Command", OpEquals, json.RawMessage(`"run-server --unsafe"`), true},
		{"negative string", fixtureMCPServer(), "Command", OpEquals, json.RawMessage(`"other"`), false},
		{"positive named-string", fixtureMCPServer(), "Transport", OpEquals, json.RawMessage(`"stdio"`), true},
		{"negative named-string", fixtureMCPServer(), "Transport", OpEquals, json.RawMessage(`"http"`), false},
		{"type-mismatch slice", fixtureMCPServer(), "Args", OpEquals, json.RawMessage(`"--flag"`), false},
		{"type-mismatch map", fixtureMCPServer(), "Env", OpEquals, json.RawMessage(`"secret"`), false},
	})
}

func TestEvalIn(t *testing.T) {
	runOpCases(t, []opCase{
		{"positive scalar", fixtureMCPServer(), "Transport", OpIn, json.RawMessage(`["stdio","http"]`), true},
		{"negative scalar", fixtureMCPServer(), "Transport", OpIn, json.RawMessage(`["http","sse"]`), false},
		{"positive slice element", fixtureMCPServer(), "Args", OpIn, json.RawMessage(`["--danger","--other"]`), true},
		{"negative slice element", fixtureMCPServer(), "Args", OpIn, json.RawMessage(`["--nope"]`), false},
		{"positive slice element tools", fixtureSubagent(), "Tools", OpIn, json.RawMessage(`["bash","other"]`), true},
		{"type-mismatch map", fixtureMCPServer(), "Env", OpIn, json.RawMessage(`["secret"]`), false},
	})
}

func TestEvalMatches(t *testing.T) {
	runOpCases(t, []opCase{
		{"positive string", fixtureMCPServer(), "Command", OpMatches, json.RawMessage(`"unsafe$"`), true},
		{"negative string", fixtureMCPServer(), "Command", OpMatches, json.RawMessage(`"^nomatch$"`), false},
		{"positive slice element", fixtureMCPServer(), "Args", OpMatches, json.RawMessage(`"^--dan.*"`), true},
		{"negative slice element", fixtureMCPServer(), "Args", OpMatches, json.RawMessage(`"^zzz$"`), false},
		{"type-mismatch map", fixtureMCPServer(), "Env", OpMatches, json.RawMessage(`"secret"`), false},
	})
}

// TestEvalNotIn is the inverse of TestEvalIn: notIn fires exactly when in
// would not, and vice versa, over the same fixtures/kinds (scalar,
// []string, and the map type-mismatch case).
func TestEvalNotIn(t *testing.T) {
	runOpCases(t, []opCase{
		{"fires: scalar absent from set", fixtureMCPServer(), "Transport", OpNotIn, json.RawMessage(`["http","sse"]`), true},
		{"silent: scalar present in set", fixtureMCPServer(), "Transport", OpNotIn, json.RawMessage(`["stdio","http"]`), false},
		{"fires: no slice element in set", fixtureMCPServer(), "Args", OpNotIn, json.RawMessage(`["--nope"]`), true},
		{"silent: a slice element is in set", fixtureMCPServer(), "Args", OpNotIn, json.RawMessage(`["--danger","--other"]`), false},
		{"silent: a slice element is in set (tools)", fixtureSubagent(), "Tools", OpNotIn, json.RawMessage(`["bash","other"]`), false},
		{"type-mismatch map is silent, never fires", fixtureMCPServer(), "Env", OpNotIn, json.RawMessage(`["secret"]`), false},
	})
}

// TestEvalNotMatches is the inverse of TestEvalMatches: notMatches fires
// exactly when matches would not, and vice versa.
func TestEvalNotMatches(t *testing.T) {
	runOpCases(t, []opCase{
		{"fires: string does not match", fixtureMCPServer(), "Command", OpNotMatches, json.RawMessage(`"^nomatch$"`), true},
		{"silent: string matches", fixtureMCPServer(), "Command", OpNotMatches, json.RawMessage(`"unsafe$"`), false},
		{"fires: no slice element matches", fixtureMCPServer(), "Args", OpNotMatches, json.RawMessage(`"^zzz$"`), true},
		{"silent: a slice element matches", fixtureMCPServer(), "Args", OpNotMatches, json.RawMessage(`"^--dan.*"`), false},
		{"type-mismatch map is silent, never fires", fixtureMCPServer(), "Env", OpNotMatches, json.RawMessage(`"secret"`), false},
	})
}

func TestEvalCombinators(t *testing.T) {
	trueCond := Condition{Field: "Command", Op: OpExists, Value: json.RawMessage(`null`)}
	falseCond := Condition{Field: "Command", Op: OpEquals, Value: json.RawMessage(`"nope"`)}

	tests := []struct {
		name  string
		match Match
		want  bool
	}{
		{"default-and empty condition, mixed truth is false", Match{Condition: "", Rules: []Condition{trueCond, falseCond}}, false},
		{"explicit and, mixed truth is false", Match{Condition: CondAnd, Rules: []Condition{trueCond, falseCond}}, false},
		{"explicit and, all true", Match{Condition: CondAnd, Rules: []Condition{trueCond, trueCond}}, true},
		{"or, mixed truth is true", Match{Condition: CondOr, Rules: []Condition{trueCond, falseCond}}, true},
		{"or, all false", Match{Condition: CondOr, Rules: []Condition{falseCond, falseCond}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{Target: ir.KindMCPServer, Match: tt.match}
			if got := Eval(rule, fixtureMCPServer()); got != tt.want {
				t.Fatalf("Eval() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A "command exists" condition must match an http server carrying a command
// alongside its url, with the entity produced by the REAL claude adapter
// path rather than hand-built: a hand-built ir.MCPServer only proves
// fieldValue's reflection sees a populated struct field, which is true even
// if the adapter that fills it in projected Command selectively by
// transport — a regression a hand-built fixture would leave entirely
// undetected.
func TestEvalCommandExistsOnNonStdioServer(t *testing.T) {
	fsys := fstest.MapFS{
		".mcp.json": &fstest.MapFile{Data: []byte(
			`{"mcpServers":{"api":{"type":"http","url":"https://a","command":"/bin/sh -c evil"}}}`,
		)},
	}
	entities, warnings, err := claude.New().Parse(fsys)
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Parse() warnings = %+v, want none", warnings)
	}

	var entity ir.Entity
	for _, e := range entities {
		if m, ok := e.(ir.MCPServer); ok && m.Name == "api" {
			entity = m
		}
	}
	if entity == nil {
		t.Fatalf("Parse() entities = %+v, want an mcpServer named api", entities)
	}

	// Lowercase, matching the field spelling shipped rules actually use
	// (e.g. rules/claude/credential-helpers.json), not just the Go struct
	// field name fieldValue's EqualFold happens to also accept.
	rule := oneCondRule("command", OpExists, json.RawMessage(`null`))
	if got := Eval(rule, entity); !got {
		t.Fatalf("Eval() = %v, want true (Command is populated regardless of Transport)", got)
	}
}

func TestEvalUnknownFieldAndLocation(t *testing.T) {
	entity := fixtureMCPServer()

	if got := Eval(oneCondRule("NotARealField", OpExists, json.RawMessage(`null`)), entity); got {
		t.Fatalf("unknown field matched, want no match")
	}

	if got := Eval(oneCondRule("Location", OpExists, json.RawMessage(`null`)), entity); got {
		t.Fatalf("Location field matched, want it excluded from field access")
	}

	if _, ok := fieldValue(entity, "Location"); ok {
		t.Fatalf("fieldValue resolved Location, want it excluded")
	}
}

func TestEvaluate(t *testing.T) {
	mcpMatch := fixtureMCPServer()
	mcpNoMatch := ir.MCPServer{Name: "other", Transport: ir.TransportHTTP, URL: "https://example.com"}
	sub := fixtureSubagent()

	mcpRule := Rule{
		ID:        "mcp-stdio",
		Target:    ir.KindMCPServer,
		AppliesTo: []string{"claude-code"},
		Match: Match{
			Rules: []Condition{{Field: "Transport", Op: OpEquals, Value: json.RawMessage(`"stdio"`)}},
		},
	}
	subRule := Rule{
		ID:     "subagent-has-tools",
		Target: ir.KindSubagent,
		Match: Match{
			Rules: []Condition{{Field: "Tools", Op: OpExists, Value: json.RawMessage(`null`)}},
		},
	}

	entities := []ir.Entity{mcpMatch, sub, mcpNoMatch}
	rules := []Rule{mcpRule, subRule}

	t.Run("filters by appliesTo and target kind, deterministic order", func(t *testing.T) {
		got := Evaluate(rules, entities, "claude-code")
		want := []Hit{
			{RuleID: "mcp-stdio", Entity: mcpMatch},
			{RuleID: "subagent-has-tools", Entity: sub},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Evaluate() = %+v, want %+v", got, want)
		}
	})

	t.Run("appliesTo excludes agent from mcp rule but not empty-appliesTo subagent rule", func(t *testing.T) {
		got := Evaluate(rules, entities, "cursor")
		want := []Hit{{RuleID: "subagent-has-tools", Entity: sub}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Evaluate() = %+v, want %+v", got, want)
		}
	})

	t.Run("only entities matching rule.Target are considered", func(t *testing.T) {
		got := Evaluate([]Rule{subRule}, []ir.Entity{mcpMatch}, "any")
		if len(got) != 0 {
			t.Fatalf("Evaluate() = %+v, want no hits (kind mismatch)", got)
		}
	})

	t.Run("empty inputs produce empty result", func(t *testing.T) {
		got := Evaluate(nil, nil, "any")
		if len(got) != 0 {
			t.Fatalf("Evaluate(nil, nil) = %+v, want empty", got)
		}
	})
}
