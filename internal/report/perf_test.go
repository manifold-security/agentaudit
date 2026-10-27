//go:build !race

package report

import (
	"strings"
	"testing"
	"time"
)

const redactBudget = time.Second

const adversarialBytes = 512 << 10

var adversarialUnits = []string{"KEY=./", "key=key=", "--token ./ ", "Authorization: ", "X-Api-Key:", "curl -u a: ", "a://", "ghp_", "a://x_/"}

func TestRedact_CompletesWithinBudget(t *testing.T) {
	for _, unit := range adversarialUnits {
		in := strings.Repeat(unit, adversarialBytes/len(unit))
		start := time.Now()
		Redact(in)
		if elapsed := time.Since(start); elapsed > redactBudget {
			t.Errorf("Redact over %d bytes of %q took %s, want under %s", len(in), unit, elapsed, redactBudget)
		}
	}
}

func BenchmarkRedact(b *testing.B) {
	in := strings.Repeat(adversarialUnits[0], adversarialBytes/len(adversarialUnits[0]))
	for b.Loop() {
		Redact(in)
	}
}
