package ruleeng

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// ValidateRule validates rule structure — required fields, a known target,
// a known combinator, and per condition a known operator, a decodable
// value, and (for matches) a compilable regex — then runs checkExamples.
// Static checks run first, so a bad regex or unknown target is reported as a
// compile/schema error rather than an example failure.
func ValidateRule(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("ruleeng: rule has no id")
	}
	if !knownTarget(rule.Target) {
		return fmt.Errorf("ruleeng: rule %q: unknown target %q", rule.ID, rule.Target)
	}
	if err := validateMatch(rule.Match); err != nil {
		return fmt.Errorf("ruleeng: rule %q: %w", rule.ID, err)
	}
	if err := checkExamples(rule); err != nil {
		return fmt.Errorf("ruleeng: rule %q: %w", rule.ID, err)
	}
	return nil
}

func validateMatch(m Match) error {
	switch m.Condition {
	case "", CondAnd, CondOr:
	default:
		return fmt.Errorf("unknown condition combinator %q", m.Condition)
	}
	if len(m.Rules) == 0 {
		return fmt.Errorf("match.rules must not be empty")
	}
	for i, cond := range m.Rules {
		if err := validateCondition(cond); err != nil {
			return fmt.Errorf("condition %d: %w", i, err)
		}
	}
	return nil
}

func validateCondition(cond Condition) error {
	if cond.Field == "" {
		return fmt.Errorf("missing field")
	}
	switch cond.Op {
	case OpExists, OpEquals, OpIn, OpMatches, OpNotIn, OpNotMatches:
	default:
		return fmt.Errorf("unknown op %q", cond.Op)
	}
	if err := decodeValue(cond.Op, cond.Value); err != nil {
		return err
	}
	if cond.Op == OpMatches || cond.Op == OpNotMatches {
		pattern, _ := decodeString(cond.Value)
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
	}
	return nil
}

// checkExamples is the examples-as-spec harness: it materializes every
// Examples/NegativeExamples entry into rule.Target's concrete ir.Entity and
// runs Eval against it. Every Examples entry MUST match (fire); every
// NegativeExamples entry MUST NOT match (stay silent). A malformed example
// (invalid JSON for the target entity) is also an error. Errors name the
// failing index so a rule author can find the offending example.
func checkExamples(rule Rule) error {
	for i, raw := range rule.Examples {
		entity, err := materialize(rule.Target, raw)
		if err != nil {
			return fmt.Errorf("examples[%d]: %w", i, err)
		}
		if !Eval(rule, entity) {
			return fmt.Errorf("examples[%d] does not match its own rule", i)
		}
	}
	for i, raw := range rule.NegativeExamples {
		entity, err := materialize(rule.Target, raw)
		if err != nil {
			return fmt.Errorf("negative_examples[%d]: %w", i, err)
		}
		if Eval(rule, entity) {
			return fmt.Errorf("negative_examples[%d] unexpectedly matches its own rule", i)
		}
	}
	return nil
}

// materialize decodes raw JSON into a fresh concrete ir.Entity for target.
// IR structs carry no json tags, so encoding/json's case-insensitive
// exported-field match resolves Transport/Args/Env (and every other IR
// field) directly.
func materialize(target string, raw json.RawMessage) (ir.Entity, error) {
	factory, ok := targets[target]
	if !ok {
		return nil, fmt.Errorf("unknown target %q", target)
	}
	ptr := reflect.New(reflect.TypeOf(factory()))
	if err := json.Unmarshal(raw, ptr.Interface()); err != nil {
		return nil, fmt.Errorf("decode example: %w", err)
	}
	return ptr.Elem().Interface().(ir.Entity), nil
}
