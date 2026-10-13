package ruleeng

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ir"
)

func validRule() Rule {
	return Rule{
		ID:     "r1",
		Name:   "Example",
		Target: ir.KindMCPServer,
		Match: Match{
			Rules: []Condition{
				{Field: "Transport", Op: OpEquals, Value: json.RawMessage(`"stdio"`)},
			},
		},
		Message: "example message",
	}
}

func TestValidateRule(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(Rule) Rule
		wantErr bool
	}{
		{"valid rule passes", func(r Rule) Rule { return r }, false},
		{"missing id fails", func(r Rule) Rule { r.ID = ""; return r }, true},
		{"unknown target fails", func(r Rule) Rule { r.Target = "not-a-real-kind"; return r }, true},
		{"unknown op fails", func(r Rule) Rule {
			r.Match.Rules[0].Op = "bogus"
			return r
		}, true},
		{"uncompilable regex fails", func(r Rule) Rule {
			r.Match.Rules[0].Op = OpMatches
			r.Match.Rules[0].Value = json.RawMessage(`"(unbalanced"`)
			return r
		}, true},
		{"empty match.rules fails", func(r Rule) Rule { r.Match.Rules = nil; return r }, true},
		{"unknown combinator fails", func(r Rule) Rule { r.Match.Condition = "xor"; return r }, true},
		{"decode mismatch fails", func(r Rule) Rule {
			r.Match.Rules[0].Value = json.RawMessage(`42`)
			return r
		}, true},
		{"missing field fails", func(r Rule) Rule {
			r.Match.Rules[0].Field = ""
			return r
		}, true},
		{"notIn op passes", func(r Rule) Rule {
			r.Match.Rules[0].Op = OpNotIn
			r.Match.Rules[0].Value = json.RawMessage(`["http","sse"]`)
			return r
		}, false},
		{"notMatches op passes", func(r Rule) Rule {
			r.Match.Rules[0].Op = OpNotMatches
			r.Match.Rules[0].Value = json.RawMessage(`"^http$"`)
			return r
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.mutate(validRule())
			err := ValidateRule(rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateRuleExamples exercises the examples-as-spec harness wired into
// ValidateRule: every Examples entry must match its own rule, every
// NegativeExamples entry must not, and a malformed example is an error.
func TestValidateRuleExamples(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(Rule) Rule
		wantErr bool
	}{
		{
			name: "POSITIVE: matching examples and silent negatives pass",
			mutate: func(r Rule) Rule {
				r.Examples = []json.RawMessage{json.RawMessage(`{"Transport":"stdio"}`)}
				r.NegativeExamples = []json.RawMessage{json.RawMessage(`{"Transport":"http"}`)}
				return r
			},
			wantErr: false,
		},
		{
			name: "NEGATIVE: no examples or negatives is trivially valid",
			mutate: func(r Rule) Rule {
				r.Examples = nil
				r.NegativeExamples = nil
				return r
			},
			wantErr: false,
		},
		{
			name: "NEGATIVE: an example that does not match its own rule fails",
			mutate: func(r Rule) Rule {
				r.Examples = []json.RawMessage{json.RawMessage(`{"Transport":"http"}`)}
				return r
			},
			wantErr: true,
		},
		{
			name: "NEGATIVE: a negative_example that matches its own rule fails",
			mutate: func(r Rule) Rule {
				r.NegativeExamples = []json.RawMessage{json.RawMessage(`{"Transport":"stdio"}`)}
				return r
			},
			wantErr: true,
		},
		{
			name: "NEGATIVE: malformed example JSON for the target fails",
			mutate: func(r Rule) Rule {
				r.Examples = []json.RawMessage{json.RawMessage(`{"Transport":`)}
				return r
			},
			wantErr: true,
		},
		{
			name: "POSITIVE: IR-shaped example with Args/Env materializes and matches",
			mutate: func(r Rule) Rule {
				r.Examples = []json.RawMessage{
					json.RawMessage(`{"Name":"fs","Transport":"stdio","Command":"npx","Args":["-y","@modelcontextprotocol/server-filesystem"],"Env":{"DEBUG":"1"}}`),
				}
				return r
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.mutate(validRule())
			err := ValidateRule(rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateRuleExamplesAcrossTargetKinds confirms materialization works
// for a non-mcpServer target (hook), exercising a different concrete
// ir.Entity shape (string-only fields, no slice/map).
func TestValidateRuleExamplesAcrossTargetKinds(t *testing.T) {
	rule := Rule{
		ID:     "hook-runs-curl",
		Name:   "Hook runs curl",
		Target: ir.KindHook,
		Match: Match{
			Rules: []Condition{
				{Field: "Command", Op: OpMatches, Value: json.RawMessage(`"curl"`)},
			},
		},
		Message: "hook command invokes curl",
		Examples: []json.RawMessage{
			json.RawMessage(`{"Event":"PreToolUse","Matcher":"Bash","Command":"curl https://evil.example"}`),
		},
		NegativeExamples: []json.RawMessage{
			json.RawMessage(`{"Event":"PreToolUse","Matcher":"Bash","Command":"echo hi"}`),
		},
	}
	if err := ValidateRule(rule); err != nil {
		t.Fatalf("ValidateRule() error = %v, want nil", err)
	}
}

func TestCheckExamplesErrorNamesFailingIndex(t *testing.T) {
	rule := validRule()
	rule.Examples = []json.RawMessage{
		json.RawMessage(`{"Transport":"stdio"}`),
		json.RawMessage(`{"Transport":"http"}`),
	}
	err := checkExamples(rule)
	if err == nil {
		t.Fatalf("checkExamples() error = nil, want error for examples[1]")
	}
	if !strings.Contains(err.Error(), "examples[1]") {
		t.Fatalf("checkExamples() error = %v, want it to name examples[1]", err)
	}
}
