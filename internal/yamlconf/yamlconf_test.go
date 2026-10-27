package yamlconf

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/manifold-security/agentaudit/internal/limits"
)

func distinctPairs(keys int) []string {
	pairs := make([]string, keys)
	for i := range pairs {
		pairs[i] = fmt.Sprintf("k%d: 1", i)
	}
	return pairs
}

func flowMapping(keys int) string {
	return "{" + strings.Join(distinctPairs(keys), ", ") + "}"
}

func blockMapping(keys int, indent string) string {
	return indent + strings.Join(distinctPairs(keys), "\n"+indent) + "\n"
}

// A mapping past MaxMappingKeys is refused as a limit, and one at the cap
// parses.
func TestParseRefusesATopLevelOrNestedMappingPastTheKeyCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  func(keys int) string
	}{
		{"top-level block", func(n int) string { return blockMapping(n, "") }},
		{"top-level flow", func(n int) string { return flowMapping(n) + "\n" }},
		{"block under a key", func(n int) string { return "hooks:\n" + blockMapping(n, "  ") }},
		{"flow in a sequence", func(n int) string { return "tools:\n  - " + flowMapping(n) + "\n" }},
		{"flow in a hook group's hooks", func(n int) string {
			return "hooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - " + flowMapping(n) + "\n"
		}},
		{"flow as a key", func(n int) string { return "? " + flowMapping(n) + "\n: x\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.doc(MaxMappingKeys))); err != nil {
				t.Errorf("Parse(%d keys) error = %v, want nil", MaxMappingKeys, err)
			}
			if _, err := Parse([]byte(tc.doc(MaxMappingKeys + 1))); !errors.Is(err, limits.ErrLimit) {
				t.Errorf("Parse(%d keys) error = %v, want a refusal wrapping ErrLimit", MaxMappingKeys+1, err)
			}
		})
	}
}

// A merged mapping past the cap is refused as a limit, even when it also holds
// a non-scalar key.
func TestParseRefusesAMergedMappingPastTheCapAsALimit(t *testing.T) {
	doc := "m:\n  x: &a {[z]: 1, " + strings.Join(distinctPairs(MaxMappingKeys), ", ") + "}\n  <<: [*a, *a]\n"
	if _, err := Parse([]byte(doc)); !errors.Is(err, limits.ErrLimit) {
		t.Errorf("Parse() error = %v, want a refusal wrapping ErrLimit", err)
	}
}

// Checking mappings that each merge one aliased sequence allocates at most
// twice what the parse does: the merged value is expanded once, not once per
// mapping.
func TestParseExpandsARepeatedMergeOnce(t *testing.T) {
	const aliases, merges = 1000, 1000
	doc := []byte("a: &a {x: 1}\ns: &s [" + strings.TrimSuffix(strings.Repeat("*a,", aliases), ",") +
		"]\nm: [" + strings.TrimSuffix(strings.Repeat("{<<: *s},", merges), ",") + "]\n")
	allocated := func(f func()) uint64 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	parsed := allocated(func() {
		var n yaml.Node
		if err := yaml.Unmarshal(doc, &n); err != nil {
			t.Fatalf("yaml.Unmarshal() error = %v", err)
		}
	})
	checked := allocated(func() {
		if _, err := Parse(doc); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
	})
	if checked > 2*parsed {
		t.Errorf("Parse() allocated %d bytes, want at most twice the %d the parse alone takes", checked, parsed)
	}
}

// A duplicate key fails the document with yaml.v3's own message for the
// earliest duplicate pair, and is no limit.
func TestParseFailsADuplicateKeyWithYAMLsMessageForTheEarliestPair(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"one pair", "name: a\ntools: Bash\nname: b\n"},
		{"the earliest key's pair first", "a: 1\nb: 1\nb: 2\na: 2\n"},
		{"a key thrice", "a: 1\na: 2\na: 3\n"},
		{"flow", "{a: 1, b: 2, a: 3}\n"},
		{"nested block", "hooks:\n  PreToolUse:\n    - matcher: Bash\n      matcher: Read\n"},
		{"a later nested flow", "hooks:\n  PreToolUse:\n    - {matcher: Bash}\n    - {matcher: Read, matcher: Edit}\n"},
		{"inside a key", "? {k: 1, k: 2}\n: x\n"},
		{"an alias to a redefined anchor", "a0: &x v0\n*x : 0\na1: &x v1\n*x : 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var everything any
			var typeErr *yaml.TypeError
			if err := yaml.Unmarshal([]byte(tc.doc), &everything); !errors.As(err, &typeErr) {
				t.Fatalf("premise: yaml.Unmarshal() error = %v, want a *yaml.TypeError", err)
			}
			want := (&yaml.TypeError{Errors: typeErr.Errors[:1]}).Error()

			_, err := Parse([]byte(tc.doc))
			if err == nil || err.Error() != want {
				t.Errorf("Parse() error = %v, want %q", err, want)
			}
			if errors.Is(err, limits.ErrLimit) {
				t.Errorf("Parse() error = %v wraps ErrLimit, want a malformed document", err)
			}
		})
	}
}

// A merge key fails the document when its own mapping, or a mapping it
// merges, holds a key that is not a scalar, and neither half alone does.
func TestParseFailsAMergeKeyMixedWithANonScalarKey(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		line      int
	}{
		{"beside the merge key", "? [a, b]\n: x\n<<: {c: 1}\nname: a\n", 1},
		{"beside a merge of nothing", "? [a, b]\n: x\n<<: []\n", 1},
		{"an alias beside the merge key", "s: &s [a]\nm: {*s : x, <<: {c: 1}}\n", 2},
		{"in the merged mapping", "h: {1: x, <<: {[a]: 1}}\n", 1},
		{"in a mapping merged through an alias", "a: &a {[x]: 1}\nm: {<<: *a}\n", 1},
		{"in a merged sequence's mapping", "a: &a {[x]: 1}\nm: {<<: [{c: 1}, *a]}\n", 1},
		{"nested", "metadata:\n  ? [a]\n  : x\n  <<: {c: 1}\n", 2},
		{"a non-scalar key with no merge", "? [a, b]\n: x\nname: a\n", 0},
		{"a merge of scalar keys", "a: &a {b: 1}\nc: {<<: *a, d: 2}\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if tc.line == 0 {
				if err != nil {
					t.Errorf("Parse() error = %v, want nil", err)
				}
				return
			}
			want := (&yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: a merge key mixed with a non-scalar key", tc.line)}}).Error()
			if err == nil || err.Error() != want {
				t.Errorf("Parse() error = %v, want %q", err, want)
			}
		})
	}
}

// Two keys repeat each other when they resolve to the same kind and value,
// or when both are aliases naming the same anchor.
func TestParseComparesAKeyByWhatItResolvesTo(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"an alias repeating a plain key", "e: &e PreToolUse\nhooks:\n  PreToolUse: [1]\n  *e : [2]\n", `line 4: mapping key "PreToolUse" already defined at line 3`},
		{"two aliases to one key", "e: &e k\nm:\n  *e : 1\n  *e : 2\n", `line 4: mapping key "k" already defined at line 3`},
		{"an alias sharing a key's anchor name", "x: &k a\nk: 1\n*k : 2\n", ""},
		{"a sequence key beside an empty one", "? [a]\n: x\n\"\": y\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if tc.want == "" {
				if err != nil {
					t.Errorf("Parse() error = %v, want nil", err)
				}
				return
			}
			if want := (&yaml.TypeError{Errors: []string{tc.want}}).Error(); err == nil || err.Error() != want {
				t.Errorf("Parse() error = %v, want %q", err, want)
			}
		})
	}
}

// Failing a mapping of duplicate keys allocates fewer objects past the parse
// than the mapping has keys.
func TestParseFailsDuplicateKeysWithoutAnErrorPerPair(t *testing.T) {
	doc := []byte(strings.Repeat("k: 1\n", MaxMappingKeys))
	parse := func() *yaml.Node {
		var n yaml.Node
		if err := yaml.Unmarshal(doc, &n); err != nil {
			t.Fatalf("yaml.Unmarshal() error = %v", err)
		}
		return &n
	}
	parsed := testing.AllocsPerRun(5, func() { parse() })
	yamlDecoded := testing.AllocsPerRun(5, func() {
		var out struct{ K string }
		_ = parse().Decode(&out)
	})
	if extra := yamlDecoded - parsed; extra < MaxMappingKeys {
		t.Fatalf("premise: yaml.v3's Decode allocated %v past the parse, want at least %d", extra, MaxMappingKeys)
	}

	checked := testing.AllocsPerRun(5, func() {
		if _, err := Parse(doc); err == nil {
			t.Fatal("Parse() error = nil, want the duplicate key")
		}
	})
	if extra := checked - parsed; extra >= MaxMappingKeys {
		t.Errorf("Parse() allocated %v past the parse, want fewer than %d", extra, MaxMappingKeys)
	}
}

// A document Parse admits decodes exactly as yaml.Unmarshal decodes it, and
// one Parse refuses is not decoded.
func TestUnmarshalDecodesOnlyADocumentParseAdmits(t *testing.T) {
	type frontmatter struct {
		Name  string         `yaml:"name"`
		Tools []string       `yaml:"tools"`
		Hooks map[string]any `yaml:"hooks"`
	}
	legit := []byte("name: reviewer\ntools: [Read, Bash]\nhooks:\n  PreToolUse:\n    - matcher: &m Bash\n      hooks: [{type: command, command: *m}]\n")
	var want frontmatter
	if err := yaml.Unmarshal(legit, &want); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	var got frontmatter
	if err := Unmarshal(legit, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("Unmarshal() = %+v, %v, want %+v, nil", got, err, want)
	}

	for _, doc := range []string{"name: a\nx: " + flowMapping(MaxMappingKeys+1) + "\n", "name: a\nx: {k: 1, k: 2}\n", "? [a, b]\n: x\n<<: {c: 1}\nname: a\n"} {
		var out frontmatter
		if err := Unmarshal([]byte(doc), &out); err == nil || out.Name != "" {
			t.Errorf("Unmarshal(%.40q) = %+v, %v, want nothing decoded and an error", doc, out, err)
		}
	}
}

// Parse, and a decode of a document it admits, return rather than panic on
// what the fuzzer offers.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"name: a\ntools: [Read]\n",
		"? [a, b]\n: x\n<<: {c: 1}\nname: a\n",
		"h: {1: x, <<: {[a]: 1}}\n",
		"a: &a {b: 1}\nc: {<<: *a, d: 2}\n",
		"{k: 1, k: 2}\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Parse(data)
		if err != nil {
			return
		}
		var generic any
		_ = doc.Decode(&generic)
		var fields struct {
			Name  string         `yaml:"name"`
			Tools []string       `yaml:"tools"`
			Hooks map[string]any `yaml:"hooks"`
		}
		_ = doc.Decode(&fields)
	})
}
