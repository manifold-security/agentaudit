package ir

// Frozen CredentialHelper variant tokens.
const (
	VariantAPIKeyHelper        = "apiKeyHelper"
	VariantAWSAuthRefresh      = "awsAuthRefresh"
	VariantAWSCredentialExport = "awsCredentialExport"
)

// CredentialHelper is a configured credential helper command.
type CredentialHelper struct {
	Variant  string
	Command  string
	Location Location
}

func (CredentialHelper) Kind() string { return KindCredentialHelper }

func (c CredentialHelper) Identity() string {
	return identity(KindCredentialHelper, c.Variant, c.Command)
}
