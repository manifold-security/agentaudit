package ir

// BundledPayload is a file a scanned configuration ships as a script or
// executable payload. Referenced/ReferencedBy are populated by the
// reference correlator and stay "" until then.
type BundledPayload struct {
	Path string // duplicates Location.File on purpose: Location is unmatchable by rules
	// Extension is the lowercased path.Ext(Path), "" when the path has none.
	Extension string
	// Executable is "true" when the file's mode has any of the +x bits set,
	// "" otherwise — a string, not a Go bool, so the rule engine's
	// reflect.String-based operators accept it with zero engine change.
	Executable string
	// Referenced is "true" when the owning SKILL.md/command file mentions
	// this payload's path, "" otherwise.
	Referenced string
	// ReferencedBy is the owning markdown file's path, "" when unreferenced.
	ReferencedBy string
	// Origin names the kind of payload directory the file sits in, "" when
	// the producer does not classify it. A string rather than an enum, for
	// the reason Executable gives.
	Origin   string
	Location Location
}

func (BundledPayload) Kind() string { return KindBundledPayload }

// Identity returns a stable identity built from Path alone — Executable,
// Referenced, ReferencedBy, and Location are provenance/derived facts, not
// identity fields.
func (b BundledPayload) Identity() string {
	return identity(KindBundledPayload, b.Path)
}
