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
	DictDir            string
	Credentials        []Credential
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
		Credentials:  selectCredentialSet(spec, in),
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

func selectCredentialSet(spec metadata.Spec, in CompileInput) CredentialSet {
	set := CredentialSet{
		Source:           CredentialSourceBuiltin,
		Dictionaries:     dictionarySources(spec),
		ExpansionProfile: spec.Dictionary.ExpansionProfile,
		AllowEmptyUser:   spec.Dictionary.AllowEmptyUsername,
		AllowEmptyPass:   spec.Dictionary.AllowEmptyPassword,
	}

	if len(in.Credentials) > 0 {
		set.Source = CredentialSourceInline
		set.InlineCount = len(dedupeCredentials(in.Credentials))
		return set
	}

	if in.DictDir != "" {
		set.Source = CredentialSourceDirectory
		set.Directory = in.DictDir
	}

	return set
}

func dictionarySources(spec metadata.Spec) []string {
	passwordSource := spec.Dictionary.PasswordSource
	if passwordSource == "" {
		if !spec.Capabilities.Credential {
			return nil
		}
		passwordSource = spec.Name
	}
	if passwordSource == "" {
		return nil
	}
	return []string{passwordSource}
}

func dedupeCredentials(in []Credential) []Credential {
	seen := make(map[string]struct{}, len(in))
	out := make([]Credential, 0, len(in))
	for _, cred := range in {
		key := cred.Username + "\x00" + cred.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cred)
	}
	return out
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
