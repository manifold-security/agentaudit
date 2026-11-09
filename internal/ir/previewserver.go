package ir

// PreviewServer is a Claude Desktop preview server configuration.
type PreviewServer struct {
	Name        string
	Command     string
	Args        []string
	Program     string
	ProgramArgs []string
	Cwd         string
	Env         map[string]string
	URL         string
	Location    Location
}

func (PreviewServer) Kind() string { return KindPreviewServer }

func (p PreviewServer) Identity() string {
	return identity(KindPreviewServer, p.Name, p.Command)
}
