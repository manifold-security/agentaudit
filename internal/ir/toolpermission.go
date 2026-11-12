package ir

// ToolPermission is one entry of a CLI permission list, decomposed into the
// tool it names and the argument scoping that tool.
type ToolPermission struct {
	// Tool is the permission type the entry names, or the whole entry when
	// it spelled no argument the adapter could separate out.
	Tool string
	// Argument is what the entry scopes Tool to — a command, a glob, a
	// domain or a server:tool pair.
	Argument string
	Location Location
}

func (ToolPermission) Kind() string { return KindToolPermission }

func (t ToolPermission) Identity() string {
	return identity(KindToolPermission, t.Tool, t.Argument)
}
