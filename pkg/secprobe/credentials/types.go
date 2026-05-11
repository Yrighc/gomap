package credentials

type Tier string

const (
	TierTop      Tier = "top"
	TierCommon   Tier = "common"
	TierExtended Tier = "extended"
)

type ScanProfile string

const (
	ScanProfileFast    ScanProfile = "fast"
	ScanProfileDefault ScanProfile = "default"
	ScanProfileFull    ScanProfile = "full"
)

type CredentialProfile struct {
	Protocol           string
	DefaultUsers       []string
	PasswordSource     string
	ExtraPasswords     []string
	DefaultPairs        []CredentialPair
	DefaultTiers       []Tier
	ScanProfile        ScanProfile
	AllowEmptyUsername bool
	AllowEmptyPassword bool
	ExpansionProfile   string
}

type CredentialPair struct {
	Username string
	Password string
}
