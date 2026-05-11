package strategy

type Capability string

const (
	CapabilityCredential   Capability = "credential"
	CapabilityUnauthorized Capability = "unauthorized"
)

type CredentialSource string

const (
	CredentialSourceBuiltin   CredentialSource = "builtin"
	CredentialSourceInline    CredentialSource = "inline"
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

type Credential struct {
	Username string
	Password string
}

type CredentialSet struct {
	Source           CredentialSource
	InlineCount      int
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
