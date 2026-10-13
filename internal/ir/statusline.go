package ir

// StatusLine is a configured status line command.
type StatusLine struct {
	Command  string
	Type     string
	Location Location
}

func (StatusLine) Kind() string { return KindStatusLine }

// Identity returns a stable identity built from Command only. Type is
// excluded because the command is the capability: re-declaring the same
// command under a different type is the same capability, not a new one.
func (s StatusLine) Identity() string {
	return identity(KindStatusLine, s.Command)
}
