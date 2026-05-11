package credentials

import (
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type DictionaryProfileInput struct {
	DefaultUsers       []string
	PasswordSource     string
	ExtraPasswords     []string
	DefaultPairs        []CredentialPair
	DefaultTiers       []string
	AllowEmptyUsername bool
	AllowEmptyPassword bool
	ExpansionProfile   string
}

type GenerateInput struct {
	Profile CredentialProfile
	Inline  []strategy.Credential
}

type GenerateMeta struct {
	Source        SourceDescriptor
	SelectedTiers []Tier
}

type Generator struct{}

func ProfileFromMetadata(protocol string, dict metadata.Dictionary) CredentialProfile {
	return ProfileFromDictionary(protocol, DictionaryProfileInput{
		DefaultUsers:       dict.DefaultUsers,
		PasswordSource:     dict.PasswordSource,
		ExtraPasswords:     dict.ExtraPasswords,
		DefaultPairs:        metadataPairsToCredentialPairs(dict.DefaultPairs),
		DefaultTiers:       dict.DefaultTiers,
		AllowEmptyUsername: dict.AllowEmptyUsername,
		AllowEmptyPassword: dict.AllowEmptyPassword,
		ExpansionProfile:   dict.ExpansionProfile,
	})
}

func ProfileFromDictionary(protocol string, dict DictionaryProfileInput) CredentialProfile {
	return CredentialProfile{
		Protocol:           strings.ToLower(strings.TrimSpace(protocol)),
		DefaultUsers:       normalizeUsers(dict.DefaultUsers),
		PasswordSource:     strings.ToLower(strings.TrimSpace(dict.PasswordSource)),
		ExtraPasswords:     normalizePasswords(dict.ExtraPasswords),
		DefaultPairs:        normalizeCredentialPairs(dict.DefaultPairs),
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
		return creds, meta, nil
	}

	passwords, source, err := loadBuiltinSourceNameByTiers(sourceNameForProfile(in.Profile), selectedTiers)
	if err != nil {
		return nil, GenerateMeta{}, err
	}
	meta.Source = source
	creds := buildGeneratedCredentials(in.Profile, passwords)
	expanded := Expand(creds, Options{
		Profile:        in.Profile.ExpansionProfile,
		AllowEmptyUser: in.Profile.AllowEmptyUsername,
		AllowEmptyPass: in.Profile.AllowEmptyPassword,
	})
	return appendExactPairs(expanded, in.Profile.DefaultPairs), meta, nil
}

func buildGeneratedCredentials(profile CredentialProfile, passwords []strategy.Credential) []strategy.Credential {
	out := make([]strategy.Credential, 0, len(profile.DefaultUsers)*(len(passwords)+len(profile.ExtraPasswords)))
	for _, user := range profile.DefaultUsers {
		for _, password := range passwords {
			out = append(out, strategy.Credential{
				Username: user,
				Password: strings.ReplaceAll(password.Password, "{user}", user),
			})
		}
		for _, password := range profile.ExtraPasswords {
			out = append(out, strategy.Credential{
				Username: user,
				Password: strings.ReplaceAll(password, "{user}", user),
			})
		}
	}
	return out
}

func appendExactPairs(creds []strategy.Credential, pairs []CredentialPair) []strategy.Credential {
	if len(pairs) == 0 {
		return creds
	}
	out := make([]strategy.Credential, 0, len(creds)+len(pairs))
	seen := make(map[string]struct{}, len(creds)+len(pairs))
	appendUniqueCredential := func(cred strategy.Credential) {
		key := cred.Username + "\x00" + cred.Password
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, cred)
	}
	for _, cred := range creds {
		appendUniqueCredential(cred)
	}
	for _, pair := range pairs {
		appendUniqueCredential(strategy.Credential{Username: pair.Username, Password: pair.Password})
	}
	return out
}

func metadataPairsToCredentialPairs(values []metadata.CredentialPair) []CredentialPair {
	out := make([]CredentialPair, 0, len(values))
	for _, value := range values {
		out = append(out, CredentialPair{Username: value.Username, Password: value.Password})
	}
	return out
}

func sourceNameForProfile(profile CredentialProfile) string {
	if source := strings.TrimSpace(profile.PasswordSource); source != "" {
		return source
	}
	return profile.Protocol
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

func normalizeUsers(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizePasswords(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeCredentialPairs(values []CredentialPair) []CredentialPair {
	if len(values) == 0 {
		return nil
	}
	out := make([]CredentialPair, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		user := strings.TrimSpace(value.Username)
		pass := strings.TrimSpace(value.Password)
		if user == "" || pass == "" {
			continue
		}
		key := user + "\x00" + pass
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, CredentialPair{Username: user, Password: pass})
	}
	if len(out) == 0 {
		return nil
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
