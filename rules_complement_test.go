package agentaudit

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/manifold-security/agentaudit/internal/ruleeng"
)

// Two rules split one field between them by repeating the same values in
// separate bodies. One side edited alone either double-reports the entity or
// drops it from both rules; the per-adapter exclusivity tests name fixed
// examples, so they read those values only where an example happens to cover
// one.
func TestComplementaryRulesCarryTheSameValues(t *testing.T) {
	rules, err := ruleeng.LoadAll(embeddedRules, defaultRulesDir)
	if err != nil {
		t.Fatalf("LoadAll() error = %v, want nil", err)
	}

	byID := map[string]ruleeng.Rule{}
	for _, rule := range rules {
		byID[rule.ID] = rule
	}

	complementOf := map[string]string{
		ruleeng.OpIn:      ruleeng.OpNotIn,
		ruleeng.OpMatches: ruleeng.OpNotMatches,
	}

	decode := func(t *testing.T, raw json.RawMessage) any {
		t.Helper()
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v, want nil", raw, err)
		}
		return v
	}

	pairs := []struct {
		positive string
		negative string
		field    string
	}{
		{"claude.sandbox.dangerous-socket", "claude.sandbox.unix-socket", "socketPath"},
		{"claude.payload.referenced-script", "claude.payload.bundled-script", "referenced"},
		{"cursor.permissions.wildcard-grant", "cursor.permissions.granted-tool", "argument"},
	}

	for _, pair := range pairs {
		t.Run(pair.positive, func(t *testing.T) {
			positive, ok := byID[pair.positive]
			if !ok {
				t.Fatalf("rule %q is not in the shipped set", pair.positive)
			}
			negative, ok := byID[pair.negative]
			if !ok {
				t.Fatalf("rule %q is not in the shipped set", pair.negative)
			}

			negativeValues := map[string]json.RawMessage{}
			for _, cond := range negative.Match.Rules {
				if cond.Field == pair.field {
					negativeValues[cond.Op] = cond.Value
				}
			}

			compared := 0
			for _, cond := range positive.Match.Rules {
				complement, paired := complementOf[cond.Op]
				if cond.Field != pair.field || !paired {
					continue
				}
				compared++

				raw, present := negativeValues[complement]
				if !present {
					t.Errorf("%s carries no %s on %s, so %s %s %s goes unmatched",
						pair.negative, complement, pair.field, pair.positive, cond.Op, cond.Value)
					continue
				}
				if want, got := decode(t, cond.Value), decode(t, raw); !reflect.DeepEqual(want, got) {
					t.Errorf("%s %s %s = %s, want %s's %s value %s",
						pair.negative, pair.field, complement, raw, pair.positive, cond.Op, cond.Value)
				}
			}
			if compared == 0 {
				t.Fatalf("no in/matches condition on %s in %q, so the pair is compared on nothing",
					pair.field, pair.positive)
			}
		})
	}
}
