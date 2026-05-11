package credentials

import "strings"

var scanProfileTierSets = map[ScanProfile][]Tier{
	ScanProfileFast:    {TierTop},
	ScanProfileDefault: {TierTop, TierCommon},
	ScanProfileFull:    {TierTop, TierCommon, TierExtended},
}

func normalizeScanProfile(value string) ScanProfile {
	switch ScanProfile(strings.ToLower(strings.TrimSpace(value))) {
	case ScanProfileFast:
		return ScanProfileFast
	case ScanProfileFull:
		return ScanProfileFull
	default:
		return ScanProfileDefault
	}
}

func ResolveTiers(profile CredentialProfile) []Tier {
	defaultTiers := normalizeResolvedTiers(profile.DefaultTiers)
	allowed := scanProfileTierSets[normalizeCredentialScanProfile(profile.ScanProfile)]

	out := make([]Tier, 0, len(defaultTiers))
	for _, tier := range defaultTiers {
		if containsTier(allowed, tier) {
			out = append(out, tier)
		}
	}
	return out
}

func normalizeResolvedTiers(values []Tier) []Tier {
	if len(values) == 0 {
		return []Tier{TierTop, TierCommon}
	}

	out := make([]Tier, 0, len(values))
	seen := make(map[Tier]struct{}, len(values))
	for _, value := range values {
		tier := normalizeTier(value)
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

func normalizeCredentialScanProfile(profile ScanProfile) ScanProfile {
	switch normalizeScanProfile(string(profile)) {
	case ScanProfileFast:
		return ScanProfileFast
	case ScanProfileFull:
		return ScanProfileFull
	default:
		return ScanProfileDefault
	}
}

func normalizeTier(value Tier) Tier {
	switch Tier(strings.ToLower(strings.TrimSpace(string(value)))) {
	case TierTop:
		return TierTop
	case TierCommon:
		return TierCommon
	case TierExtended:
		return TierExtended
	default:
		return ""
	}
}

func containsTier(values []Tier, target Tier) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
