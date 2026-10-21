package ir

// InlineShell is a shell command extracted from a skill or command
// markdown body — either an inline !`cmd` placeholder or a line inside a
// ```! fenced block. Body scanning and extraction are adapter-owned; this
// Kind only carries the located result.
type InlineShell struct {
	Command string
	// Form is "inline" or "fenced".
	Form string
	// Shell is "bash" (documented default) or "powershell", or any other
	// value carried verbatim — the adapter parses, it never judges.
	Shell    string
	Location Location
}

func (InlineShell) Kind() string { return KindInlineShell }

// Identity returns a stable identity built from Location.File and Command
// — NOT the line number, so reformatting a file (which shifts line
// numbers) never changes identity; two identical commands in the same file
// stay distinguishable through Location.Key instead.
func (i InlineShell) Identity() string {
	return identity(KindInlineShell, i.Location.File, i.Command)
}
