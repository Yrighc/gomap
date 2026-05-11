package credentials

import (
	"errors"
	"fmt"
	"os"
	"strings"

	appassets "github.com/yrighc/gomap/app"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type SourceKind string

const (
	SourceInline  SourceKind = "inline"
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

var builtinPasswordEntryLoader = func(source string) ([]credentialEntry, error) {
	data, err := appassets.SecprobePasswordSource(source)
	if err != nil {
		return nil, err
	}
	return parsePasswordEntries(string(data))
}

func stubBuiltinPasswordEntryLoader(fn func(string) ([]credentialEntry, error)) func() {
	previous := builtinPasswordEntryLoader
	builtinPasswordEntryLoader = fn
	return func() {
		builtinPasswordEntryLoader = previous
	}
}

func loadBuiltinSourceNameByTiers(name string, tiers []Tier) ([]strategy.Credential, SourceDescriptor, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return nil, SourceDescriptor{}, &missingSourceError{
			kind:   SourceBuiltin,
			target: name,
			err:    os.ErrNotExist,
		}
	}

	entries, err := builtinPasswordEntryLoader(name)
	if err != nil {
		return nil, SourceDescriptor{}, &missingSourceError{
			kind:   SourceBuiltin,
			target: name,
			err:    err,
		}
	}
	filtered := flattenCredentialEntries(filterCredentialEntriesByTiers(entries, tiers))
	if len(filtered) == 0 {
		return nil, SourceDescriptor{}, &missingSourceError{
			kind:   SourceBuiltin,
			target: name,
			err:    os.ErrNotExist,
		}
	}
	return filtered, SourceDescriptor{
		Kind: SourceBuiltin,
		Name: name,
	}, nil
}

func parsePasswordEntries(raw string) ([]credentialEntry, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]credentialEntry, 0, len(lines))
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		tier := TierTop
		content := trimmed
		if strings.HasPrefix(trimmed, "[") {
			end := strings.Index(trimmed, "]")
			if end <= 1 {
				return nil, fmt.Errorf("invalid password tier line %d: %q", idx+1, line)
			}
			tier = normalizeTier(Tier(trimmed[1:end]))
			if tier == "" {
				return nil, fmt.Errorf("invalid password tier line %d: %q", idx+1, line)
			}
			content = strings.TrimSpace(trimmed[end+1:])
		}
		if content == "" {
			continue
		}
		out = append(out, credentialEntry{
			Tier:       tier,
			Credential: strategy.Credential{Password: content},
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid passwords found")
	}
	return out, nil
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
