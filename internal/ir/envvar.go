package ir

// EnvVar is a declared environment variable assignment.
type EnvVar struct {
	Name     string
	Value    string
	Location Location
}

func (EnvVar) Kind() string { return KindEnvVar }

func (e EnvVar) Identity() string {
	return identity(KindEnvVar, e.Name, e.Value)
}
