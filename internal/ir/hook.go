package ir

// Hook is a lifecycle hook command bound to an event/matcher pair.
type Hook struct {
	Event   string
	Matcher string
	Command string
	// MCPServer and MCPTool name the tool a hook calls in place of a command.
	// They sit outside Identity.
	MCPServer string
	MCPTool   string
	Location  Location
}

func (Hook) Kind() string { return KindHook }

func (h Hook) Identity() string {
	return identity(KindHook, h.Event, h.Matcher, h.Command)
}
