package ir

// Skill is a declared skill definition.
type Skill struct {
	Name     string
	Location Location
}

func (Skill) Kind() string { return KindSkill }

func (s Skill) Identity() string {
	return identity(KindSkill, s.Name)
}
