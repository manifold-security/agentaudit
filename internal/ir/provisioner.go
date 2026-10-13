package ir

// Provisioner is a setup command an agent runs to prepare a workspace. It is
// a kind of its own rather than a Hook because a hook arbitrates: it receives
// an input envelope and its reply can veto the action it fired on.
type Provisioner struct {
	// Phase is the configuration key that declared the command, verbatim.
	Phase string
	// Name identifies one entry within a phase that declares several. A
	// phase carrying a single command leaves it empty.
	Name     string
	Command  string
	Location Location
}

func (Provisioner) Kind() string { return KindProvisioner }

func (p Provisioner) Identity() string {
	return identity(KindProvisioner, p.Phase, p.Name, p.Command)
}
