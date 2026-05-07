package credentials

import (
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func ProfileFromMetadata(spec metadata.Spec) CredentialProfile {
	return CredentialProfile{
		Protocol: spec.Name,
		Scan: ScanProfile{
			Sources:        append([]string(nil), spec.Dictionary.DefaultSources...),
			Tiers:          normalizeTiers(spec.Dictionary.DefaultTiers),
			Expansion:      spec.Dictionary.ExpansionProfile,
			AllowEmptyUser: spec.Dictionary.AllowEmptyUsername,
			AllowEmptyPass: spec.Dictionary.AllowEmptyPassword,
		},
	}
}

func normalizeTiers(values []string) []Tier {
	if len(values) == 0 {
		return []Tier{TierTop, TierCommon}
	}

	out := make([]Tier, 0, len(values))
	seen := make(map[Tier]struct{}, len(values))
	for _, value := range values {
		tier := Tier(strings.ToLower(strings.TrimSpace(value)))
		if tier == "" {
			continue
		}
		if _, ok := seen[tier]; ok {
			continue
		}
		seen[tier] = struct{}{}
		out = append(out, tier)
	}

	if len(out) == 0 {
		return []Tier{TierTop, TierCommon}
	}
	return out
}
