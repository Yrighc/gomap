package secprobe

import "github.com/yrighc/gomap/internal/secprobe/core"

type ProbeKind = core.ProbeKind

const (
	FindingTypeCredentialValid    = core.FindingTypeCredentialValid
	FindingTypeUnauthorizedAccess = core.FindingTypeUnauthorizedAccess
)

const (
	ProbeKindCredential   = core.ProbeKindCredential
	ProbeKindUnauthorized = core.ProbeKindUnauthorized
)

type SecurityCandidate = core.SecurityCandidate
type Credential = core.Credential
type CredentialProbeOptions = core.CredentialProbeOptions
type SecurityResult = core.SecurityResult
type SecurityMeta = core.SecurityMeta
type RunResult = core.RunResult
