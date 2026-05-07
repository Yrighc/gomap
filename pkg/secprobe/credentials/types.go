package credentials

type Tier string

const (
	TierTop    Tier = "top"
	TierCommon Tier = "common"
)

type ScanProfile struct {
	Sources        []string
	Tiers          []Tier
	Expansion      string
	AllowEmptyUser bool
	AllowEmptyPass bool
}

type CredentialProfile struct {
	Protocol string
	Scan     ScanProfile
}
