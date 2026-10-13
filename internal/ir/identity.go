package ir

import "strings"

// identity joins kind and key fields with the ASCII Unit Separator (0x1f) to
// build a stable, globally unique identity string. The separator is chosen
// because it never appears in JSON, YAML, or frontmatter text produced by
// adapters, so field boundaries can never be ambiguously merged.
func identity(kind string, fields ...string) string {
	return strings.Join(append([]string{kind}, fields...), "\x1f")
}
