package cursor

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/manifold-security/agentaudit/adapter"
	"github.com/manifold-security/agentaudit/internal/ir"
	"github.com/manifold-security/agentaudit/internal/limits"
	"github.com/manifold-security/agentaudit/internal/yamlconf"
)

func flowMapping(keys int) string {
	pairs := make([]string, keys)
	for i := range pairs {
		pairs[i] = fmt.Sprintf("k%d: 1", i)
	}
	return "{" + strings.Join(pairs, ", ") + "}"
}

// Reading a component's name warns each block yamlconf.Parse rejects, as a
// limit where Parse refuses it, and names the component of one it admits.
func TestFrontmatterReadersWarnTheMappingsParseRejects(t *testing.T) {
	for _, reader := range []struct {
		name string
		read func([]byte, string) ([]ir.Entity, []adapter.Warning)
	}{
		{"project subagent", projectSubagentFrom},
		{"plugin skill", skillFrom},
		{"plugin agent", agentFrom},
	} {
		for _, tc := range []struct {
			name, block  string
			warns, limit bool
		}{
			{"a mapping past the cap", "name: a\nx: " + flowMapping(yamlconf.MaxMappingKeys+1) + "\n", true, true},
			{"a duplicate key", "name: a\nx: {k: 1, k: 2}\n", true, false},
			{"an alias key repeating a key", "name: a\ne: &e k\nx: {k: 1, *e : 2}\n", true, false},
			{"a merge key beside a non-scalar key", "? [a, b]\n: x\n<<: {c: 1}\nname: a\n", true, false},
			{"none of them", "name: a\nx: " + flowMapping(yamlconf.MaxMappingKeys) + "\n", false, false},
		} {
			t.Run(reader.name+"/"+tc.name, func(t *testing.T) {
				got, warnings := reader.read([]byte("---\n"+tc.block+"---\n"), "a.md")
				if len(warnings) != map[bool]int{true: 1}[tc.warns] || len(got) != map[bool]int{false: 1}[tc.warns] {
					t.Fatalf("entities = %+v, warnings = %+v, want a warning %v", got, warnings, tc.warns)
				}
				if tc.warns && errors.Is(warnings[0].Err, limits.ErrLimit) != tc.limit {
					t.Errorf("warning = %v, want it to wrap ErrLimit %v", warnings[0].Err, tc.limit)
				}
			})
		}
	}
}

// Reading a component's name returns rather than panics on what the fuzzer
// offers as a frontmatter block.
func FuzzFrontmatterReaders(f *testing.F) {
	for _, seed := range []string{"name: a\ndescription: b\n", "? [a, b]\n: x\n<<: {c: 1}\nname: a\n", "name: {<<: {[a]: 1}}\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, block []byte) {
		data := []byte("---\n" + string(block) + "\n---\n")
		projectSubagentFrom(data, "a.md")
		skillFrom(data, "a.md")
		agentFrom(data, "a.md")
	})
}
