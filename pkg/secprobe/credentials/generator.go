package credentials

import (
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type DictionaryProfileInput struct {
	DefaultSources     []string
	DefaultTiers       []string
	AllowEmptyUsername bool
	AllowEmptyPassword bool
	ExpansionProfile   string
}

type GenerateInput struct {
	Profile CredentialProfile
	DictDir string
	Inline  []strategy.Credential
}

type GenerateMeta struct {
	Source        SourceDescriptor
	SelectedTiers []Tier
}

type Generator struct{}

func ProfileFromMetadata(protocol string, dict metadata.Dictionary) CredentialProfile {
	return ProfileFromDictionary(protocol, DictionaryProfileInput{
		DefaultSources:     dict.DefaultSources,
		DefaultTiers:       dict.DefaultTiers,
		AllowEmptyUsername: dict.AllowEmptyUsername,
		AllowEmptyPassword: dict.AllowEmptyPassword,
		ExpansionProfile:   dict.ExpansionProfile,
	})
}

func ProfileFromDictionary(protocol string, dict DictionaryProfileInput) CredentialProfile {
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

func (p CredentialProfile) WithScanProfile(profile string) CredentialProfile {
	normalized := normalizeScanProfile(profile)
	switch ScanProfile(strings.ToLower(strings.TrimSpace(profile))) {
	case ScanProfileFast, ScanProfileDefault, ScanProfileFull:
		p.ScanProfile = normalized
	}
	return p
}

func (g Generator) Generate(in GenerateInput) ([]strategy.Credential, GenerateMeta, error) {
	selectedTiers := ResolveTiers(in.Profile)
	meta := GenerateMeta{SelectedTiers: append([]Tier(nil), selectedTiers...)}

	if creds := dedupeStrategyCredentials(in.Inline); len(creds) > 0 {
		meta.Source = SourceDescriptor{
			Kind: SourceInline,
			Name: "inline",
		}
		return Expand(creds, Options{
			Profile:        in.Profile.ExpansionProfile,
			AllowEmptyUser: in.Profile.AllowEmptyUsername,
			AllowEmptyPass: in.Profile.AllowEmptyPassword,
		}), meta, nil
	}

	trimmedDir := strings.TrimSpace(in.DictDir)
	if trimmedDir != "" {
		creds, source, err := LoadDirectorySource(in.Profile.Protocol, trimmedDir)
		if err == nil {
			meta.Source = source
			return Expand(creds, Options{
				Profile:        in.Profile.ExpansionProfile,
				AllowEmptyUser: in.Profile.AllowEmptyUsername,
				AllowEmptyPass: in.Profile.AllowEmptyPassword,
			}), meta, nil
		}
		if !IsMissingSource(err) {
			return nil, GenerateMeta{}, err
		}
	}

	creds, source, err := LoadBuiltinSource(in.Profile.Protocol)
	if err != nil {
		return nil, GenerateMeta{}, err
	}
	meta.Source = source
	return Expand(creds, Options{
		Profile:        in.Profile.ExpansionProfile,
		AllowEmptyUser: in.Profile.AllowEmptyUsername,
		AllowEmptyPass: in.Profile.AllowEmptyPassword,
	}), meta, nil
}

func dedupeStrategyCredentials(in []strategy.Credential) []strategy.Credential {
	seen := make(map[string]struct{}, len(in))
	out := make([]strategy.Credential, 0, len(in))
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

func normalizeTiers(values []string) []Tier {
	if len(values) == 0 {
		return []Tier{TierTop, TierCommon}
	}

	out := make([]Tier, 0, len(values))
	seen := make(map[Tier]struct{}, len(values))
	for _, value := range values {
		tier := normalizeTier(Tier(value))
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
