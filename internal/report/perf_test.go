//go:build !race

package report

import (
	"strings"
	"testing"
	"time"
)

const redactBudget = time.Second

const adversarialBytes = 512 << 10

var adversarialUnits = []string{"KEY=./", "key=key=", "--token ./ ", "Authorization: ", "X-Api-Key:", "curl -u a: ", "a://", "ghp_", "a://x_/", "Authorization:-", "\"key\":\"-", "key=\"", "--token \"a ", "key=\"a\" "}

var unclosedQuotes = []string{"--token \"", "key=\"", "Authorization: \""}

const afterUnclosedQuote = "--token a key=b "

func TestRedact_CompletesWithinBudget(t *testing.T) {
	inputs := map[string]string{}
	for _, unit := range adversarialUnits {
		inputs["repeats of "+unit] = strings.Repeat(unit, adversarialBytes/len(unit))
	}
	for _, head := range unclosedQuotes {
		inputs[head+" before repeats of "+afterUnclosedQuote] = head + strings.Repeat(afterUnclosedQuote, adversarialBytes/len(afterUnclosedQuote))
	}
	for name, in := range inputs {
		start := time.Now()
		Redact(in)
		if elapsed := time.Since(start); elapsed > redactBudget {
			t.Errorf("Redact over %d bytes of %q took %s, want under %s", len(in), name, elapsed, redactBudget)
		}
	}
}

func BenchmarkRedact(b *testing.B) {
	in := strings.Repeat(adversarialUnits[0], adversarialBytes/len(adversarialUnits[0]))
	for b.Loop() {
		Redact(in)
	}
}
