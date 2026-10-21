package ir

// InstructionText is prose a configuration file declares for a model to
// read, carried as a raw Setting/Text pair. The adapter carries the words
// and judges none of them.
type InstructionText struct {
	// Setting is the key the prose was declared under.
	Setting string
	// Text is the prose, carried verbatim.
	Text     string
	Location Location
}

func (InstructionText) Kind() string { return KindInstructionText }

func (i InstructionText) Identity() string {
	return identity(KindInstructionText, i.Setting, i.Text)
}
