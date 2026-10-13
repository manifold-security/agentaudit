package ruleeng

import (
	"encoding/json"
	"fmt"
)

// Rule is a declarative detection rule loaded from JSON. Category and
// AppliesTo are lists of neutral tags/agent IDs; Examples and
// NegativeExamples stay as raw JSON until they are materialized against
// the entity type named by Target (see target.go).
type Rule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Category         []string          `json:"category"`
	AppliesTo        []string          `json:"appliesTo"`
	Target           string            `json:"target"`
	Match            Match             `json:"match"`
	Message          string            `json:"message"`
	References       []string          `json:"references"`
	Examples         []json.RawMessage `json:"examples"`
	NegativeExamples []json.RawMessage `json:"negative_examples"`
}

// Match is a combinator over Condition leaves. Condition is "" (default)
// or CondAnd for AND semantics, CondOr for OR semantics.
type Match struct {
	Condition string      `json:"condition"`
	Rules     []Condition `json:"rules"`
}

// Condition is a single field/operator/value leaf evaluated against an
// ir.Entity field (see match.go).
type Condition struct {
	Field string          `json:"field"`
	Op    string          `json:"op"`
	Value json.RawMessage `json:"value"`
}

// Known Match.Condition combinators.
const (
	CondAnd = "and"
	CondOr  = "or"
)

// Known Condition.Op operators.
const (
	OpExists     = "exists"
	OpEquals     = "equals"
	OpIn         = "in"
	OpMatches    = "matches"
	OpNotIn      = "notIn"
	OpNotMatches = "notMatches"
)

// AppliesTo reports whether rule applies to agentID. An empty AppliesTo
// list means the rule applies to every agent.
func AppliesTo(rule Rule, agentID string) bool {
	if len(rule.AppliesTo) == 0 {
		return true
	}
	for _, id := range rule.AppliesTo {
		if id == agentID {
			return true
		}
	}
	return false
}

// decodeString decodes raw as the JSON string the string-valued operators
// require.
func decodeString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("decode string value: %w", err)
	}
	return s, nil
}

// decodeStringSlice decodes raw as the JSON array of strings the set-membership
// operators require.
func decodeStringSlice(raw json.RawMessage) ([]string, error) {
	var s []string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("decode string slice value: %w", err)
	}
	return s, nil
}

// decodeValue decodes raw according to the shape its op requires. exists
// carries no value and always succeeds; unknown ops are rejected.
func decodeValue(op string, raw json.RawMessage) error {
	switch op {
	case OpExists:
		return nil
	case OpEquals, OpMatches, OpNotMatches:
		_, err := decodeString(raw)
		return err
	case OpIn, OpNotIn:
		_, err := decodeStringSlice(raw)
		return err
	default:
		return fmt.Errorf("unknown operator %q", op)
	}
}
