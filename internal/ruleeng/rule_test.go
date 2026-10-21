package ruleeng

import (
	"encoding/json"
	"testing"
)

func TestDecodeValue(t *testing.T) {
	tests := []struct {
		name    string
		op      string
		raw     json.RawMessage
		wantErr bool
	}{
		{"exists ignores value", OpExists, json.RawMessage(`null`), false},
		{"equals string ok", OpEquals, json.RawMessage(`"stdio"`), false},
		{"equals number mismatch", OpEquals, json.RawMessage(`42`), true},
		{"matches string ok", OpMatches, json.RawMessage(`"^foo.*"`), false},
		{"matches array mismatch", OpMatches, json.RawMessage(`["a"]`), true},
		{"in string slice ok", OpIn, json.RawMessage(`["a","b"]`), false},
		{"in string mismatch", OpIn, json.RawMessage(`"a"`), true},
		{"notIn string slice ok", OpNotIn, json.RawMessage(`["a","b"]`), false},
		{"notIn string mismatch", OpNotIn, json.RawMessage(`"a"`), true},
		{"notMatches string ok", OpNotMatches, json.RawMessage(`"^foo.*"`), false},
		{"notMatches array mismatch", OpNotMatches, json.RawMessage(`["a"]`), true},
		{"unknown op errors", "bogus", json.RawMessage(`"x"`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := decodeValue(tt.op, tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeValue(%q, %s) error = %v, wantErr %v", tt.op, tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestDecodeString(t *testing.T) {
	got, err := decodeString(json.RawMessage(`"stdio"`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "stdio" {
		t.Fatalf("decodeString() = %q, want %q", got, "stdio")
	}

	if _, err := decodeString(json.RawMessage(`["a"]`)); err == nil {
		t.Fatalf("expected error decoding array as string")
	}
}

func TestDecodeStringSlice(t *testing.T) {
	got, err := decodeStringSlice(json.RawMessage(`["a","b"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "b"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("decodeStringSlice() = %v, want %v", got, want)
	}

	if _, err := decodeStringSlice(json.RawMessage(`"a"`)); err == nil {
		t.Fatalf("expected error decoding string as string slice")
	}
}

func TestAppliesTo(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		agentID string
		want    bool
	}{
		{"empty appliesTo matches any agent", Rule{}, "any-agent", true},
		{"non-empty appliesTo excludes unlisted agent", Rule{AppliesTo: []string{"claude-code"}}, "cursor", false},
		{"non-empty appliesTo includes listed agent", Rule{AppliesTo: []string{"claude-code"}}, "claude-code", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AppliesTo(tt.rule, tt.agentID); got != tt.want {
				t.Fatalf("AppliesTo() = %v, want %v", got, tt.want)
			}
		})
	}
}
