package ir

// Entity is the contract every normalized IR entity satisfies. Both tokens it
// exposes are frozen; see kind.go and doc.go.
type Entity interface {
	Kind() string
	Identity() string
}

// Location records where an entity was declared. It is provenance, not
// identity.
type Location struct {
	File string
	Key  string
}
