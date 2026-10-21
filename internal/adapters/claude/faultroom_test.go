package claude

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
)

func parseSubagentFile(data []byte, file string, isPlugin bool) ([]ir.Entity, *adapter.Warning) {
	return parseSubagent(data, file, isPlugin, math.MaxInt)
}

func parseSkillFile(data []byte, file string) ([]ir.Entity, *adapter.Warning) {
	return parseSkill(data, file, math.MaxInt)
}

func parseCommandFile(data []byte, file string) ([]ir.Entity, *adapter.Warning) {
	return parseCommand(data, file, math.MaxInt)
}

func hooksFromNode(node yaml.Node) (map[string][]hookGroup, error) {
	return hookGroupsFromNode(node, math.MaxInt)
}

func TestKeyFaultsCountsEveryFaultButWritesOnlyThoseItsRoomHolds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		faults keyFaults
		text   string
	}{
		{"room for two", keyFaults{room: 2}, "a: bad; b: bad"},
		{"no room limit", keyFaults{room: math.MaxInt}, "a: bad; b: bad; c: bad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := tc.faults
			for _, key := range []string{"a", "b", "c"} {
				k.mark(key, errors.New("bad"))
			}
			err := k.err()
			if got := limits.FaultCount(err); got != 3 {
				t.Errorf("FaultCount(err()) = %d, want 3", got)
			}
			if got := err.Error(); got != tc.text {
				t.Errorf("err() = %q, want %q", got, tc.text)
			}
		})
	}
}

// A nested resolver's faults reach the file's count whole, and its text
// stops at the room the file has left.
func TestParseSubagentCountsNestedFaultsAndStopsTheirTextAtItsRoom(t *testing.T) {
	data := []byte("---\nname: a\nmcpServers:\n  - 0\n  - 0\n  - 0\n---\n")
	for _, tc := range []struct {
		name    string
		room    int
		written bool
	}{
		{"room for one", 1, false},
		{"no room limit", math.MaxInt, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, w := parseSubagent(data, "a.md", false, tc.room)
			if w == nil {
				t.Fatal("parseSubagent() warning = nil, want the faults")
			}
			if got := limits.FaultCount(w.Err); got != 3 {
				t.Errorf("FaultCount() = %d, want 3", got)
			}
			if got := strings.Contains(w.Err.Error(), "entry 2"); got != tc.written {
				t.Errorf("warning %q names entry 2 = %v, want %v", w.Err, got, tc.written)
			}
		})
	}
}

func TestKeyFaultsStopsWritingPastItsTextCap(t *testing.T) {
	key := strings.Repeat("k", 1<<10)
	const faults = 1000
	for _, tc := range []struct {
		name   string
		record func(*keyFaults)
	}{
		{"mark", func(k *keyFaults) { k.mark(key, errors.New("bad")) }},
		{"add", func(k *keyFaults) { k.add(key + ": bad") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := keyFaults{room: math.MaxInt}
			for range faults {
				tc.record(&k)
			}
			err := k.err()
			if got := limits.FaultCount(err); got != faults {
				t.Errorf("FaultCount(err()) = %d, want %d", got, faults)
			}
			if got := len(err.Error()); got < maxFaultText || got > maxFaultText+2*len(key) {
				t.Errorf("len(err()) = %d, want from %d to %d", got, maxFaultText, maxFaultText+2*len(key))
			}
		})
	}
}

// Counting stops one node past the limit, and a block without aliases counts
// nothing.
func TestAliasedNodesStopsOnePastItsLimit(t *testing.T) {
	node := func(block string) *yaml.Node {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(block), &doc); err != nil {
			t.Fatalf("yaml.Unmarshal(%q) error = %v", block, err)
		}
		return &doc
	}
	aliased := node("a: &a [" + strings.Repeat("x, ", 99) + "x]\nb: [" + strings.Repeat("*a, ", 99) + "*a]\n")
	if got := aliasedNodes(aliased, math.MaxInt); got != 100*101 {
		t.Fatalf("premise: unlimited count = %d, want %d", got, 100*101)
	}
	for _, limit := range []int{0, 50, 1000} {
		if got := aliasedNodes(aliased, limit); got != limit+1 {
			t.Errorf("aliasedNodes(limit %d) = %d, want %d", limit, got, limit+1)
		}
	}
	if got := aliasedNodes(node("a: [x, y]\nb: {c: d}\n"), 0); got != 0 {
		t.Errorf("aliasedNodes(no aliases) = %d, want 0", got)
	}
}

// An alias inside its own anchor counts that anchor once, even with no limit
// to stop the walk.
func TestAliasedNodesCountsAnAliasInsideItsOwnAnchorOnce(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte("hooks: &h\n  E: [*h]\n"), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if got := aliasedNodes(&doc, math.MaxInt); got != 4 {
		t.Errorf("aliasedNodes(self-referencing anchor) = %d, want 4", got)
	}
}

// With no budget, or one past maxAliasedNodes, the walk stops at
// maxAliasedNodes and the block is refused there rather than charged.
func TestDecodeFrontmatterStopsAtItsAliasCeilingWhateverTheBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("l0: &l0 [" + strings.Repeat("x, ", 9) + "x]\n")
	for i := 1; i <= 7; i++ {
		fmt.Fprintf(&b, "l%d: &l%d [%s*l%d]\n", i, i, strings.Repeat(fmt.Sprintf("*l%d, ", i-1), 9), i-1)
	}
	for _, room := range []int{math.MaxInt, 2 * maxAliasedNodes} {
		var fm subagentFrontmatter
		if err := decodeFrontmatter([]byte(b.String()), &fm, room); !errors.Is(err, limits.ErrLimit) {
			t.Errorf("decodeFrontmatter(billion laughs, room %d) error = %v, want a refusal wrapping ErrLimit", room, err)
		}
	}
}
