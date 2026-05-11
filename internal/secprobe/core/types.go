package core

import (
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
)

type ProbeKind string
type ResultStage string
type SkipReason string
type Capability string
type RiskLevel string

type FailureReason = result.ErrorCode

const (
	ProbeKindCredential   ProbeKind = "credential"
	ProbeKindUnauthorized ProbeKind = "unauthorized"
)

const (
	StageMatched   ResultStage = "matched"
	StageAttempted ResultStage = "attempted"
	StageConfirmed ResultStage = "confirmed"
	StageEnriched  ResultStage = "enriched"
)

const (
	SkipReasonUnsupportedProtocol SkipReason = "unsupported-protocol"
	SkipReasonProbeDisabled       SkipReason = "probe-disabled"
	SkipReasonNoCredentials       SkipReason = "no-credentials"
)

const (
	FailureReasonConnection               = result.ErrorCodeConnection
	FailureReasonAuthentication           = result.ErrorCodeAuthentication
	FailureReasonTimeout                  = result.ErrorCodeTimeout
	FailureReasonCanceled                 = result.ErrorCodeCanceled
	FailureReasonInsufficientConfirmation = result.ErrorCodeInsufficientConfirmation
)

const (
	CapabilityEnumerable Capability = "enumerable"
	CapabilityReadable   Capability = "readable"
)

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
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
	Credentials        []Credential
	EnableUnauthorized bool
	EnableEnrichment   bool
}

type SecurityResult struct {
	Target        string
	ResolvedIP    string
	Port          int
	Service       string
	ProbeKind     ProbeKind
	FindingType   string
	Success       bool
	Username      string
	Password      string
	Evidence      string
	Enrichment    map[string]any
	Error         string
	Stage         ResultStage   `json:"-"`
	SkipReason    SkipReason    `json:"-"`
	FailureReason FailureReason `json:"-"`
	Capabilities  []Capability  `json:"-"`
	Risk          RiskLevel     `json:"-"`
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
