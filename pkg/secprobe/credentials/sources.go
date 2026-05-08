package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	appassets "github.com/yrighc/gomap/app"
	"github.com/yrighc/gomap/pkg/secprobe/metadata"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type SourceKind string

const (
	SourceInline  SourceKind = "inline"
	SourceDictDir SourceKind = "dict_dir"
	SourceBuiltin SourceKind = "builtin"
)

type SourceDescriptor struct {
	Kind SourceKind
	Name string
	Path string
}

type credentialEntry struct {
	Tier       Tier
	Credential strategy.Credential
}

type missingSourceError struct {
	kind   SourceKind
	target string
	err    error
}

func (e *missingSourceError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("%s source %q not found", e.kind, e.target)
	}
	return fmt.Sprintf("%s source %q not found: %v", e.kind, e.target, e.err)
}

func (e *missingSourceError) Unwrap() error {
	return e.err
}

func IsMissingSource(err error) bool {
	var target *missingSourceError
	return errors.As(err, &target)
}

var builtinLoader = func(protocol string) ([]strategy.Credential, error) {
	data, err := appassets.SecprobeDict(protocol)
	if err != nil {
		return nil, err
	}
	return parseStrategyCredentialLines(string(data))
}

var builtinEntryLoader = func(protocol string) ([]credentialEntry, error) {
	data, err := appassets.SecprobeDict(protocol)
	if err != nil {
		return nil, err
	}
	return parseStrategyCredentialEntries(string(data))
}

func stubBuiltinLoader(fn func(string) ([]strategy.Credential, error)) func() {
	previous := builtinLoader
	previousEntries := builtinEntryLoader
	builtinLoader = fn
	builtinEntryLoader = func(protocol string) ([]credentialEntry, error) {
		creds, err := fn(protocol)
		if err != nil {
			return nil, err
		}
		return wrapCredentialsAsTierEntries(creds, TierTop), nil
	}
	return func() {
		builtinLoader = previous
		builtinEntryLoader = previousEntries
	}
}

func LoadDirectorySource(protocol, dictDir string) ([]strategy.Credential, SourceDescriptor, error) {
	if strings.TrimSpace(dictDir) == "" {
		return nil, SourceDescriptor{}, &missingSourceError{
			kind:   SourceDictDir,
			target: protocol,
			err:    os.ErrNotExist,
		}
	}

	for _, path := range dictionaryCandidatePaths(protocol, dictDir) {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, SourceDescriptor{}, err
		}

		creds, err := parseStrategyCredentialLines(string(data))
		if err != nil {
			return nil, SourceDescriptor{}, fmt.Errorf("parse %s: %w", path, err)
		}
		return creds, SourceDescriptor{
			Kind: SourceDictDir,
			Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Path: path,
		}, nil
	}

	return nil, SourceDescriptor{}, &missingSourceError{
		kind:   SourceDictDir,
		target: protocol,
		err:    os.ErrNotExist,
	}
}

func LoadBuiltinSource(protocol string) ([]strategy.Credential, SourceDescriptor, error) {
	names := builtinSourceCandidates(protocol)
	var lastErr error
	for _, name := range names {
		creds, err := builtinLoader(name)
		if err != nil {
			lastErr = err
			continue
		}
		return creds, SourceDescriptor{
			Kind: SourceBuiltin,
			Name: name,
		}, nil
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, SourceDescriptor{}, lastErr
}

func LoadDirectorySourceByTiers(protocol, dictDir string, tiers []Tier) ([]strategy.Credential, SourceDescriptor, error) {
	if strings.TrimSpace(dictDir) == "" {
		return nil, SourceDescriptor{}, &missingSourceError{
			kind:   SourceDictDir,
			target: protocol,
			err:    os.ErrNotExist,
		}
	}

	for _, path := range dictionaryCandidatePaths(protocol, dictDir) {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, SourceDescriptor{}, err
		}

		entries, err := parseStrategyCredentialEntries(string(data))
		if err != nil {
			return nil, SourceDescriptor{}, fmt.Errorf("parse %s: %w", path, err)
		}
		filtered := flattenCredentialEntries(filterCredentialEntriesByTiers(entries, tiers))
		if len(filtered) == 0 {
			return nil, SourceDescriptor{}, &missingSourceError{
				kind:   SourceDictDir,
				target: protocol,
				err:    os.ErrNotExist,
			}
		}
		return filtered, SourceDescriptor{
			Kind: SourceDictDir,
			Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Path: path,
		}, nil
	}

	return nil, SourceDescriptor{}, &missingSourceError{
		kind:   SourceDictDir,
		target: protocol,
		err:    os.ErrNotExist,
	}
}

func LoadBuiltinSourceByTiers(protocol string, tiers []Tier) ([]strategy.Credential, SourceDescriptor, error) {
	names := builtinSourceCandidates(protocol)
	var lastErr error
	for _, name := range names {
		entries, err := builtinEntryLoader(name)
		if err != nil {
			lastErr = err
			continue
		}
		filtered := flattenCredentialEntries(filterCredentialEntriesByTiers(entries, tiers))
		if len(filtered) == 0 {
			lastErr = &missingSourceError{
				kind:   SourceBuiltin,
				target: protocol,
				err:    os.ErrNotExist,
			}
			continue
		}
		return filtered, SourceDescriptor{
			Kind: SourceBuiltin,
			Name: name,
		}, nil
	}
	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, SourceDescriptor{}, lastErr
}

func dictionaryCandidatePaths(protocol, dictDir string) []string {
	names := builtinSourceCandidates(protocol)
	out := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		path := filepath.Join(dictDir, name+".txt")
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func builtinSourceCandidates(protocol string) []string {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	if normalized == "" {
		return nil
	}

	profile := protocolDictionaryProfile(normalized)
	out := make([]string, 0, len(profile.DefaultSources)+1)
	seen := make(map[string]struct{}, len(profile.DefaultSources)+1)
	for _, source := range profile.DefaultSources {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	if _, ok := seen[normalized]; !ok {
		out = append(out, normalized)
	}
	return out
}

func protocolDictionaryProfile(protocol string) CredentialProfile {
	if spec, ok := lookupProtocolDictionarySpec(protocol); ok {
		return ProfileFromDictionary(spec.Name, DictionaryProfileInput{
			DefaultSources:     spec.Dictionary.DefaultSources,
			DefaultTiers:       spec.Dictionary.DefaultTiers,
			AllowEmptyUsername: spec.Dictionary.AllowEmptyUsername,
			AllowEmptyPassword: spec.Dictionary.AllowEmptyPassword,
			ExpansionProfile:   spec.Dictionary.ExpansionProfile,
		})
	}

	return CredentialProfile{
		Protocol:       protocol,
		DefaultSources: []string{protocol},
		DefaultTiers:   []Tier{TierTop, TierCommon},
		ScanProfile:    ScanProfileDefault,
	}
}

func parseStrategyCredentialLines(raw string) ([]strategy.Credential, error) {
	entries, err := parseStrategyCredentialEntries(raw)
	if err != nil {
		return nil, err
	}
	return flattenCredentialEntries(entries), nil
}

func parseStrategyCredentialEntries(raw string) ([]credentialEntry, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]credentialEntry, 0, len(lines))
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		tier := TierTop
		content := line
		if strings.HasPrefix(trimmed, "[") {
			end := strings.Index(trimmed, "]")
			if end <= 1 {
				return nil, fmt.Errorf("invalid credential tier line %d: %q", idx+1, line)
			}
			tier = normalizeTier(Tier(trimmed[1:end]))
			if tier == "" {
				return nil, fmt.Errorf("invalid credential tier line %d: %q", idx+1, line)
			}
			content = strings.TrimSpace(trimmed[end+1:])
		}

		parts := strings.SplitN(content, " : ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid credential line %d: %q", idx+1, line)
		}
		out = append(out, credentialEntry{
			Tier: tier,
			Credential: strategy.Credential{
				Username: strings.TrimSpace(parts[0]),
				Password: strings.TrimSpace(parts[1]),
			},
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid credentials found")
	}
	return out, nil
}

func wrapCredentialsAsTierEntries(creds []strategy.Credential, tier Tier) []credentialEntry {
	out := make([]credentialEntry, 0, len(creds))
	for _, cred := range creds {
		out = append(out, credentialEntry{Tier: tier, Credential: cred})
	}
	return out
}

func filterCredentialEntriesByTiers(entries []credentialEntry, tiers []Tier) []credentialEntry {
	if len(tiers) == 0 {
		return nil
	}

	out := make([]credentialEntry, 0, len(entries))
	for _, entry := range entries {
		if containsTier(tiers, entry.Tier) {
			out = append(out, entry)
		}
	}
	return out
}

func flattenCredentialEntries(entries []credentialEntry) []strategy.Credential {
	out := make([]strategy.Credential, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry.Credential)
	}
	return out
}

func lookupProtocolDictionarySpec(protocol string) (metadata.Spec, bool) {
	specs, err := metadata.LoadBuiltin()
	if err != nil {
		return metadata.Spec{}, false
	}

	token := strings.ToLower(strings.TrimSpace(protocol))
	for _, spec := range specs {
		if spec.Name == token {
			return spec, true
		}
		for _, alias := range spec.Aliases {
			if alias == token {
				return spec, true
			}
		}
	}
	return metadata.Spec{}, false
}
