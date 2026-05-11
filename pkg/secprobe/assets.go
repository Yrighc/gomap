package secprobe

import (
	"fmt"
	"strings"

	appassets "github.com/yrighc/gomap/app"
)

func BuiltinCredentials(protocol string) ([]Credential, error) {
	dictNames := builtinCredentialDictNames(protocol)
	var lastErr error
	for _, name := range dictNames {
		data, err := appassets.SecprobePasswordSource(name)
		if err != nil {
			lastErr = err
			continue
		}
		return parseCredentialLines(string(data))
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", strings.ToLower(strings.TrimSpace(protocol)))
}

func CredentialsFor(protocol string, opts CredentialProbeOptions) ([]Credential, error) {
	if len(opts.Credentials) > 0 {
		return dedupeCredentials(opts.Credentials), nil
	}
	return BuiltinCredentials(protocol)
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

func builtinCredentialDictNames(protocol string) []string {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	if normalized == "" {
		return nil
	}

	if spec, ok := LookupProtocolSpec(normalized, 0); ok && len(spec.DictNames) > 0 {
		names := make([]string, 0, len(spec.DictNames)+1)
		seen := make(map[string]struct{}, len(spec.DictNames)+1)
		for _, name := range spec.DictNames {
			if _, ok := seen[name]; ok || strings.TrimSpace(name) == "" {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
		if _, ok := seen[spec.Name]; !ok && strings.TrimSpace(spec.Name) != "" {
			seen[spec.Name] = struct{}{}
			names = append(names, spec.Name)
		}
		if _, ok := seen[normalized]; !ok {
			names = append(names, normalized)
		}
		return names
	}

	return []string{normalized}
}

func parseCredentialLines(raw string) ([]Credential, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]Credential, 0, len(lines))
	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid credential line %d: %q", idx+1, line)
		}
		out = append(out, Credential{
			Username: strings.TrimSpace(parts[0]),
			Password: strings.TrimSpace(parts[1]),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid credentials found")
	}
	return out, nil
}
