package strategy

type Capability string

const (
	CapabilityCredential   Capability = "credential"
	CapabilityUnauthorized Capability = "unauthorized"
	CapabilityEnrichment   Capability = "enrichment"
)

type Plan struct {
	Target       Target
	Capabilities []Capability
	Credentials  CredentialSet
	Execution    ExecutionPolicy
	Results      ResultPolicy
}

type Target struct {
	Host     string
	IP       string
	Port     int
	Protocol string
}

type CredentialSet struct {
	Source           string
	Dictionaries     []string
	ExpansionProfile string
	AllowEmptyUser   bool
	AllowEmptyPass   bool
}

type ExecutionPolicy struct {
	StopOnFirstSuccess bool
	ConcurrencyScope   string
	ConcurrencyValue   int
	TimeoutSeconds     int
}

type ResultPolicy struct {
	CredentialSuccessType   string
	UnauthorizedSuccessType string
	EnrichOnSuccess         bool
	EvidenceProfile         string
}
