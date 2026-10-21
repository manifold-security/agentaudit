package ruleeng

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"

	"github.com/manifold-security/agentaudit/internal/ir"
)

// Eval evaluates rule.Match against entity, applying the combinator over
// its Condition leaves. It never panics: an unknown field, an unknown
// operator, or an operator/field-kind mismatch all resolve to "no match".
func Eval(rule Rule, entity ir.Entity) bool {
	return evalMatch(rule.Match, entity)
}

func evalMatch(m Match, entity ir.Entity) bool {
	if m.Condition == CondOr {
		for _, cond := range m.Rules {
			if evalCondition(cond, entity) {
				return true
			}
		}
		return false
	}
	for _, cond := range m.Rules {
		if !evalCondition(cond, entity) {
			return false
		}
	}
	return true
}

func evalCondition(cond Condition, entity ir.Entity) bool {
	field, ok := fieldValue(entity, cond.Field)
	if !ok {
		return false
	}
	switch cond.Op {
	case OpExists:
		return existsOp(field)
	case OpEquals:
		return equalsOp(field, cond.Value)
	case OpIn:
		return inOp(field, cond.Value)
	case OpMatches:
		return matchesOp(field, cond.Value)
	case OpNotIn:
		return notInOp(field, cond.Value)
	case OpNotMatches:
		return notMatchesOp(field, cond.Value)
	default:
		return false
	}
}

// fieldValue resolves field case-insensitively against entity's concrete
// struct via reflect.FieldByNameFunc. Location is always excluded — it is
// provenance, never a matchable field. An unknown field reports ok=false.
func fieldValue(entity ir.Entity, field string) (reflect.Value, bool) {
	v := reflect.ValueOf(entity)
	if v.Kind() != reflect.Struct {
		return reflect.Value{}, false
	}
	fv := v.FieldByNameFunc(func(name string) bool {
		return !strings.EqualFold(name, "Location") && strings.EqualFold(name, field)
	})
	if !fv.IsValid() {
		return reflect.Value{}, false
	}
	return fv, true
}

// existsOp reports whether field is a non-empty string, slice, or map.
func existsOp(field reflect.Value) bool {
	switch field.Kind() {
	case reflect.String, reflect.Slice, reflect.Map:
		return field.Len() > 0
	default:
		return false
	}
}

// equalsOp compares a string-kind field (including named strings like
// ir.Transport) against the decoded value. Any other kind is a type
// mismatch: no match, never an error.
func equalsOp(field reflect.Value, raw json.RawMessage) bool {
	if field.Kind() != reflect.String {
		return false
	}
	want, err := decodeString(raw)
	if err != nil {
		return false
	}
	return field.String() == want
}

// inOp reports whether a string-kind field's value is a member of the
// decoded set, or — for a []string field — whether any element is a
// member. Any other kind is a type mismatch: no match.
func inOp(field reflect.Value, raw json.RawMessage) bool {
	set, err := decodeStringSlice(raw)
	if err != nil {
		return false
	}
	switch field.Kind() {
	case reflect.String:
		return containsString(set, field.String())
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return false
		}
		for i := 0; i < field.Len(); i++ {
			if containsString(set, field.Index(i).String()) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// matchesOp reports whether a string-kind field matches the regex decoded
// from raw, or — for a []string field — whether any element matches. The
// regex is compiled on demand (ValidateRule already guaranteed
// compilability at load time); a compile error here is "no match", never a
// panic. Any other field kind is a type mismatch: no match.
func matchesOp(field reflect.Value, raw json.RawMessage) bool {
	pattern, err := decodeString(raw)
	if err != nil {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	switch field.Kind() {
	case reflect.String:
		return re.MatchString(field.String())
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return false
		}
		for i := 0; i < field.Len(); i++ {
			if re.MatchString(field.Index(i).String()) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// notInOp is the exact inverse of inOp: it fires when the string value is
// NOT a member of the decoded set, or no []string element is.
func notInOp(field reflect.Value, raw json.RawMessage) bool {
	set, err := decodeStringSlice(raw)
	if err != nil {
		return false
	}
	switch field.Kind() {
	case reflect.String:
		return !containsString(set, field.String())
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return false
		}
		for i := 0; i < field.Len(); i++ {
			if containsString(set, field.Index(i).String()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// notMatchesOp is the exact inverse of matchesOp: it fires when the string
// value does NOT match the decoded regex, or no []string element does.
func notMatchesOp(field reflect.Value, raw json.RawMessage) bool {
	pattern, err := decodeString(raw)
	if err != nil {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	switch field.Kind() {
	case reflect.String:
		return !re.MatchString(field.String())
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return false
		}
		for i := 0; i < field.Len(); i++ {
			if re.MatchString(field.Index(i).String()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func containsString(set []string, s string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Evaluate is the match engine's entry point: for each rule that applies
// to agentID (AppliesTo), for each entity whose Kind matches rule.Target,
// it records a Hit when Eval matches. Order is deterministic — rules are
// walked in input order, and entities are walked in input order within
// each rule. finding.Finding construction from these Hits is left to the
// caller; this package returns only []Hit.
func Evaluate(rules []Rule, entities []ir.Entity, agentID string) []Hit {
	var hits []Hit
	for _, rule := range rules {
		if !AppliesTo(rule, agentID) {
			continue
		}
		for _, entity := range entities {
			if entity.Kind() != rule.Target {
				continue
			}
			if Eval(rule, entity) {
				hits = append(hits, Hit{RuleID: rule.ID, Entity: entity})
			}
		}
	}
	return hits
}
