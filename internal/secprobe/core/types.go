package core

import "time"

type ProbeKind string

const (
	ProbeKindCredential   ProbeKind = "credential"
	ProbeKindUnauthorized ProbeKind = "unauthorized"
)

const (
	FindingTypeCredentialValid    = "credential-valid"
	FindingTypeUnauthorizedAccess = "unauthorized-access"
)

type SecurityCandidate struct {
	Target     string
	ResolvedIP string
	Port       int
	Service    string
	Version    string
	Banner     string
}

type Credential struct {
	Username string
	Password string
}

type CredentialProbeOptions struct {
	Protocols          []string
	Concurrency        int
	Timeout            time.Duration
	StopOnSuccess      bool
	DictDir            string
	Credentials        []Credential
	EnableUnauthorized bool
	EnableEnrichment   bool
}

type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	ProbeKind   ProbeKind
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Enrichment  map[string]any
	Error       string
}

type SecurityMeta struct {
	Candidates int
	Attempted  int
	Succeeded  int
	Failed     int
	Skipped    int
}

type RunResult struct {
	Meta    SecurityMeta
	Results []SecurityResult
}
