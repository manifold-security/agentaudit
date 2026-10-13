package report

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape returns s with every control byte, bidirectional-formatting
// character, line/paragraph separator and invalid UTF-8 byte replaced by its
// printable Go escape spelling; every other byte is copied verbatim. A
// terminal or a Markdown renderer acts on these bytes rather than merely
// drawing them, so leaving one raw lets a scanned name erase, conceal,
// reorder or fabricate report content instead of simply reading oddly. The
// escaped spelling keeps that anomaly visible: a dropped or folded byte would
// let a hostile name render as an ordinary one.
func Escape(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, neutralised) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(goEscape(s[i : i+1]))
		case neutralised(r):
			b.WriteString(goEscape(string(r)))
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// goEscape yields strconv's escape spelling for item without its surrounding
// quotes. Callers pass only a single rune or a single invalid byte, so the
// quotes are the sole leading and trailing byte of Quote's result.
func goEscape(item string) string {
	q := strconv.Quote(item)
	return q[1 : len(q)-1]
}

// neutralised reports whether r is a control byte (Unicode Cc, which spans
// C0, DEL and C1), one of the Bidi_Control characters, or a Unicode
// line/paragraph separator. Cf is not used as a category test: it also
// contains zero-width joiners and soft hyphens that legitimate scripts and
// emoji sequences require, so the bidi characters are enumerated instead.
func neutralised(r rune) bool {
	if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
		return true
	}
	switch r {
	case 0x061C,
		0x200E, 0x200F,
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069:
		return true
	}
	return false
}
