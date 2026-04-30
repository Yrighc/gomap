package strategy

import (
	"math"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

type CompileInput struct {
	Target             string
	IP                 string
	Port               int
	EnableUnauthorized bool
	EnableEnrichment   bool
	StopOnSuccess      bool
	Timeout            time.Duration
}

func Compile(spec metadata.Spec, in CompileInput) Plan {
	capabilities := make([]Capability, 0, 3)
	if in.EnableUnauthorized && spec.Capabilities.Unauthorized {
		capabilities = append(capabilities, CapabilityUnauthorized)
	}
	if spec.Capabilities.Credential {
		capabilities = append(capabilities, CapabilityCredential)
	}

	return Plan{
		Target: Target{
			Host:     in.Target,
			IP:       in.IP,
			Port:     in.Port,
			Protocol: spec.Name,
		},
		Capabilities: capabilities,
		Credentials: CredentialSet{
			Source:           "builtin",
			Dictionaries:     append([]string(nil), spec.Dictionary.DefaultSources...),
			ExpansionProfile: spec.Dictionary.ExpansionProfile,
			AllowEmptyUser:   spec.Dictionary.AllowEmptyUsername,
			AllowEmptyPass:   spec.Dictionary.AllowEmptyPassword,
		},
		Execution: ExecutionPolicy{
			StopOnFirstSuccess: in.StopOnSuccess,
			ConcurrencyScope:   "per_host",
			ConcurrencyValue:   defaultConcurrency(spec.PolicyTags.LockoutRisk),
			TimeoutSeconds:     durationSeconds(in.Timeout),
		},
		Results: ResultPolicy{
			CredentialSuccessType:   spec.Results.CredentialSuccessType,
			UnauthorizedSuccessType: spec.Results.UnauthorizedSuccessType,
			EnrichOnSuccess:         in.EnableEnrichment && spec.Capabilities.Enrichment,
			EvidenceProfile:         spec.Results.EvidenceProfile,
		},
	}
}

func defaultConcurrency(lockoutRisk string) int {
	switch lockoutRisk {
	case "high":
		return 1
	case "medium":
		return 3
	default:
		return 10
	}
}

func durationSeconds(timeout time.Duration) int {
	if timeout <= 0 {
		return 0
	}
	return int(math.Ceil(timeout.Seconds()))
}
