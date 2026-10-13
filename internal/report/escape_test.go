package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Each row names the codepoint by its class boundary and states the printable
// spelling Escape must produce for it.
func TestEscape_NeutralisesEachClassBoundary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"NUL", "a\x00b", `a\x00b`},
		{"BEL", "a\x07b", `a\ab`},
		{"BS", "a\x08b", `a\bb`},
		{"TAB", "a\tb", `a\tb`},
		{"LF", "a\nb", `a\nb`},
		{"VT", "a\vb", `a\vb`},
		{"FF", "a\fb", `a\fb`},
		{"CR", "a\rb", `a\rb`},
		{"ESC", "a\x1bb", `a\x1bb`},
		{"unit separator", "a\x1fb", `a\x1fb`},
		{"DEL", "a\x7fb", `a\x7fb`},
		{"NEL (C1)", "a\u0085b", `a\u0085b`},
		{"CSI (C1)", "a\u009bb", `a\u009bb`},
		{"arabic letter mark", "a\u061cb", `a\u061cb`},
		{"left-to-right mark", "a\u200eb", `a\u200eb`},
		{"right-to-left mark", "a\u200fb", `a\u200fb`},
		{"left-to-right embedding", "a\u202ab", `a\u202ab`},
		{"right-to-left override", "a\u202eb", `a\u202eb`},
		{"left-to-right isolate", "a\u2066b", `a\u2066b`},
		{"pop directional isolate", "a\u2069b", `a\u2069b`},
		{"line separator", "a\u2028b", `a\u2028b`},
		{"paragraph separator", "a\u2029b", `a\u2029b`},
		{"lone continuation byte", "a" + string([]byte{0x80}) + "b", `a\x80b`},
		{"truncated multi-byte lead byte", "a" + string([]byte{0xc2}) + "b", `a\xc2b`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Escape(tt.input); got != tt.want {
				t.Fatalf("Escape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Escape draws no distinction between a legitimate name and one that merely
// resembles a hazard: each of these passes through unchanged.
func TestEscape_LeavesPrintableTextUntouched(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"plain ASCII", "project-name"},
		{"space", "two words"},
		{"pipe", "a|b"},
		{"backslash", `a\b`},
		{"latin with diacritic", "caf\u00e9"},
		{"CJK", "\u65e5\u672c\u8a9e"},
		{"emoji", "\U0001f642"},
		{"no-break space", "a\u00a0b"},
		{"zero-width space", "a\u200bb"},
		{"soft hyphen", "a\u00adb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Escape(tt.input); got != tt.input {
				t.Fatalf("Escape(%q) = %q, want it unchanged", tt.input, got)
			}
		})
	}
}

// A single input carrying several hazard classes at once must still yield a
// result that is valid UTF-8 and free of every neutralised rune - the
// property the two tables above check one row at a time.
func TestEscape_MixedHazardsProduceValidUTF8WithNoNeutralisedRune(t *testing.T) {
	input := "before\x1b\t\u202e" + string([]byte{0x80}) + "after"

	got := Escape(input)

	if !utf8.ValidString(got) {
		t.Fatalf("Escape(%q) = %q, not valid UTF-8", input, got)
	}
	for _, r := range got {
		if neutralised(r) {
			t.Fatalf("Escape(%q) = %q, still contains neutralised rune %U", input, got, r)
		}
	}
	for _, want := range []string{`\x1b`, `\t`, `\u202e`, `\x80`} {
		if !strings.Contains(got, want) {
			t.Fatalf("Escape(%q) = %q, want it to contain %q", input, got, want)
		}
	}
}
