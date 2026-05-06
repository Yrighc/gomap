package metadata

type Spec struct {
	Name         string        `yaml:"name"`
	Aliases      []string      `yaml:"aliases"`
	Ports        []int         `yaml:"ports"`
	Capabilities Capabilities  `yaml:"capabilities"`
	PolicyTags   PolicyTags    `yaml:"policy_tags"`
	Dictionary   Dictionary    `yaml:"dictionary"`
	Results      ResultProfile `yaml:"results"`
	Templates    TemplateRefs  `yaml:"templates"`
}

type Capabilities struct {
	Credential   bool `yaml:"credential"`
	Unauthorized bool `yaml:"unauthorized"`
	Enrichment   bool `yaml:"enrichment"`
}

type PolicyTags struct {
	LockoutRisk string `yaml:"lockout_risk"`
	AuthFamily  string `yaml:"auth_family"`
	Transport   string `yaml:"transport"`
}

type Dictionary struct {
	DefaultSources     []string `yaml:"default_sources"`
	AllowEmptyUsername bool     `yaml:"allow_empty_username"`
	AllowEmptyPassword bool     `yaml:"allow_empty_password"`
	ExpansionProfile   string   `yaml:"expansion_profile"`
}

type ResultProfile struct {
	CredentialSuccessType   string `yaml:"credential_success_type"`
	UnauthorizedSuccessType string `yaml:"unauthorized_success_type"`
	EvidenceProfile         string `yaml:"evidence_profile"`
}

type TemplateRefs struct {
	Unauthorized string `yaml:"unauthorized"`
}
