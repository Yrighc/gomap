package credentials

import (
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func ProfileFromMetadata(protocol string, dict metadata.Dictionary) CredentialProfile {
	return CredentialProfile{
		Protocol:           strings.ToLower(strings.TrimSpace(protocol)),
		DefaultSources:     append([]string(nil), dict.DefaultSources...),
		DefaultTiers:       normalizeTiers(dict.DefaultTiers),
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: dict.AllowEmptyUsername,
		AllowEmptyPassword: dict.AllowEmptyPassword,
		ExpansionProfile:   dict.ExpansionProfile,
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
