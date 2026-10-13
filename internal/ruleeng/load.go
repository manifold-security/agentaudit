package ruleeng

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// LoadAll reads every agent subdirectory of root, in lexical order, and
// returns their rules concatenated. Walking for the subdirectories rather than
// naming them is what lets a new agent ship as an adapter plus a rules
// directory, with no Go change here.
//
// A rule file loose in root needs no type check to be passed over: Load globs
// one level below the name it is handed, so root/loose.json/*.json matches
// nothing.
//
// Rule ids must be unique across the whole set: the facade keys its rules by
// id when it turns a Hit into a Finding, so a duplicate would make the
// rendered message depend on which agent's file loaded last.
func LoadAll(fsys fs.FS, root string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("ruleeng: read %s: %w", root, err)
	}

	var rules []Rule
	seen := make(map[string]string)
	for _, e := range entries {
		dir := path.Join(root, e.Name())
		dirRules, err := Load(fsys, dir)
		if err != nil {
			return nil, err
		}
		for _, r := range dirRules {
			if prev, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("ruleeng: %s: rule id %q is already declared in %s", dir, r.ID, prev)
			}
			seen[r.ID] = dir
		}
		rules = append(rules, dirRules...)
	}
	return rules, nil
}

// Load reads every *.json file directly under dir on fsys, decodes each as
// a JSON array of Rule, and validates every rule. Files are processed in
// sorted-name order so the returned []Rule is deterministic across runs.
func Load(fsys fs.FS, dir string) ([]Rule, error) {
	matches, err := fs.Glob(fsys, path.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("ruleeng: glob %s: %w", dir, err)
	}
	sort.Strings(matches)

	var rules []Rule
	for _, file := range matches {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, wrapFile(file, err)
		}

		var fileRules []Rule
		if err := json.Unmarshal(data, &fileRules); err != nil {
			return nil, wrapFile(file, err)
		}

		for _, rule := range fileRules {
			if err := ValidateRule(rule); err != nil {
				return nil, wrapFile(file, err)
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// wrapFile wraps err with the "ruleeng: <file>: " prefix shared by every
// Load failure path, so callers can pinpoint which rule file misbehaved.
func wrapFile(file string, err error) error {
	return fmt.Errorf("ruleeng: %s: %w", file, err)
}
