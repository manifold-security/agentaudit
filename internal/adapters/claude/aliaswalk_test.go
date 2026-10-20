package claude

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const aliasWalkProbe = "AGENTAUDIT_ALIAS_WALK_PROBE"

// A walk down chained aliases fits a 1 MiB goroutine stack, which a recursive
// descent of the same chain overflows.
func TestAliasedNodesWalksAChainedAliasWithinAOneMiBStack(t *testing.T) {
	const levels = 500
	opening, closing := strings.Repeat("[", levels), strings.Repeat("]", levels)
	var b strings.Builder
	b.WriteString("a0: &a0 " + opening + "x" + closing + "\n")
	for i := 1; i < 50; i++ {
		fmt.Fprintf(&b, "a%d: &a%d %s*a%d%s\n", i, i, opening, i-1, closing)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	switch os.Getenv(aliasWalkProbe) {
	case "walk":
		debug.SetMaxStack(1 << 20)
		aliasedNodes(&doc, maxAliasedNodes)
		return
	case "recurse":
		debug.SetMaxStack(1 << 20)
		recurseAliases(&doc, map[*yaml.Node]bool{})
		return
	}

	if got := aliasedNodes(&doc, maxAliasedNodes); got > maxAliasedNodes {
		t.Fatalf("premise: aliasedNodes() = %d, want the whole chain walked within %d", got, maxAliasedNodes)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	for _, tc := range []struct {
		mode      string
		overflows bool
	}{
		{"recurse", true},
		{"walk", false},
	} {
		cmd := exec.Command(exe, "-test.run=^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), aliasWalkProbe+"="+tc.mode)
		out, err := cmd.CombinedOutput()
		overflowed := strings.Contains(string(out), "goroutine stack exceeds")
		if overflowed != tc.overflows || (err != nil) != tc.overflows {
			t.Errorf("%s under a 1 MiB stack: err = %v, overflowed = %v, want %v\n%.400s", tc.mode, err, overflowed, tc.overflows, out)
		}
	}
}

func recurseAliases(n *yaml.Node, expanding map[*yaml.Node]bool) {
	if n.Kind == yaml.AliasNode && n.Alias != nil && !expanding[n.Alias] {
		expanding[n.Alias] = true
		recurseAliases(n.Alias, expanding)
		delete(expanding, n.Alias)
	}
	for _, c := range n.Content {
		recurseAliases(c, expanding)
	}
}
