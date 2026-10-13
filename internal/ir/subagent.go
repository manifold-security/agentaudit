package ir

// Subagent is a declared subagent definition.
type Subagent struct {
	Name           string
	PermissionMode string
	Tools          []string
	Location       Location
}

func (Subagent) Kind() string { return KindSubagent }

// Identity returns a stable identity built from Name only. PermissionMode
// and Tools are excluded — they do not affect deduplication.
func (s Subagent) Identity() string {
	return identity(KindSubagent, s.Name)
}
