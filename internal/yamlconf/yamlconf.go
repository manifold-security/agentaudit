package yamlconf

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/manifold-security/agentaudit/internal/limits"
)

// MaxMappingKeys is the most keys Parse admits in one mapping.
const MaxMappingKeys = 256

// Parse parses data into its document node, refusing a mapping past
// MaxMappingKeys as a scan limit and failing a duplicate or mixed-merge key.
func Parse(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if err := checkMappings(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Unmarshal decodes data into out once Parse admits it.
func Unmarshal(data []byte, out any) error {
	doc, err := Parse(data)
	if err != nil {
		return err
	}
	return doc.Decode(out)
}

func checkMappings(root *yaml.Node) error {
	nonScalarKey := map[*yaml.Node]*yaml.Node{}
	expanded := map[*yaml.Node]bool{}
	var merged []*yaml.Node
	stack := []*yaml.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Kind == yaml.MappingNode {
			sources, err := mappingFault(n, nonScalarKey, expanded)
			if err != nil {
				return err
			}
			merged = append(merged, sources...)
		}
		for i := len(n.Content) - 1; i >= 0; i-- {
			stack = append(stack, n.Content[i])
		}
	}
	for _, source := range merged {
		if key := nonScalarKey[source]; key != nil {
			return mixedMerge(key)
		}
	}
	return nil
}

func mappingFault(n *yaml.Node, nonScalarKey map[*yaml.Node]*yaml.Node, expanded map[*yaml.Node]bool) ([]*yaml.Node, error) {
	if len(n.Content)/2 > MaxMappingKeys {
		return nil, limits.Refusal(fmt.Sprintf("line %d: a mapping holds more than %d keys; not scanned", n.Line, MaxMappingKeys))
	}
	type key struct {
		kind  yaml.Kind
		value string
	}
	first := make(map[key]int, len(n.Content))
	dup, again, repeated := -1, -1, ""
	merges := false
	var sources []*yaml.Node
	for j := 0; j < len(n.Content); j += 2 {
		k := resolved(n.Content[j])
		if isMerge(n.Content[j]) {
			merges = true
			sources = append(sources, mergeSources(n.Content[j+1], expanded)...)
		}
		if k.Kind != yaml.ScalarNode && nonScalarKey[n] == nil {
			nonScalarKey[n] = n.Content[j]
		}
		for _, id := range [2]key{{k.Kind, k.Value}, {n.Content[j].Kind, n.Content[j].Value}} {
			i, seen := first[id]
			switch {
			case !seen:
				first[id] = j
			case i != j && (dup < 0 || i < dup):
				dup, again, repeated = i, j, id.value
			}
		}
	}
	if key := nonScalarKey[n]; key != nil && merges {
		return nil, mixedMerge(key)
	}
	if dup < 0 {
		return sources, nil
	}
	pair := fmt.Sprintf("line %d: mapping key %q already defined at line %d", n.Content[again].Line, repeated, n.Content[dup].Line)
	return nil, &yaml.TypeError{Errors: []string{pair}}
}

func mergeSources(value *yaml.Node, expanded map[*yaml.Node]bool) []*yaml.Node {
	value = resolved(value)
	if expanded[value] {
		return nil
	}
	expanded[value] = true
	if value.Kind != yaml.SequenceNode {
		return []*yaml.Node{value}
	}
	sources := make([]*yaml.Node, len(value.Content))
	for i, item := range value.Content {
		sources[i] = resolved(item)
	}
	return sources
}

func mixedMerge(key *yaml.Node) error {
	return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: a merge key mixed with a non-scalar key", key.Line)}}
}

func isMerge(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Value == "<<" && (n.Tag == "" || n.Tag == "!" || n.ShortTag() == "!!merge")
}

func resolved(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}
