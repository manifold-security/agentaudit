package ir

// PluginExecutable is a file directly under a plugin root's bin/ directory.
// The official Claude Code plugins reference describes bin/ as holding
// "Executables added to the Bash tool's PATH. Files here are invokable as
// bare commands in any Bash tool call while the plugin is enabled". That
// makes it a STRONGER code-execution surface than BundledPayload — no
// markdown reference, no skill invocation, and no prompt naming the file's
// path is required — which is why it has its own Kind instead of reusing
// BundledPayload (reuse would force Referenced=="" on every bin/ file and
// route 100% of them to claude.payload.bundled-script, the weaker half of
// the mutually-exclusive pair in rules/claude/bundled-payloads.json).
type PluginExecutable struct {
	Path string
	// Name is path.Base(Path) — the exact BARE COMMAND name the file becomes
	// on the Bash tool's PATH. It is a first-class field, not a derived
	// convenience, because that bare name is what a rule must be able to
	// match (a PATH lookup never sees Path).
	Name string
	// Plugin is the owning plugin's resolved name (manifest name, or the
	// plugin root's basename).
	Plugin string
	// Extension is the lowercased path.Ext(Path), "" when there is none.
	Extension string
	// Executable is "true" when the file's mode has any +x bit set, ""
	// otherwise.
	Executable string
	Location   Location
}

func (PluginExecutable) Kind() string { return KindPluginExecutable }

// Identity returns a stable identity built from Path ALONE. Path is already
// globally unique within one scan, and Name/Plugin/Extension are pure
// functions of Path or of provenance while Executable is a mutable file-mode
// fact — including any of them would let a chmod or a plugin rename mint a
// second identity for the same file. Mirrors BundledPayload.Identity.
func (e PluginExecutable) Identity() string {
	return identity(KindPluginExecutable, e.Path)
}
