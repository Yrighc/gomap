package secprobe

import (
	"fmt"
	"strings"

	appassets "github.com/yrighc/gomap/app"
)

func BuiltinCredentials(protocol string) ([]Credential, error) {
	data, err := appassets.SecprobeDict(strings.ToLower(strings.TrimSpace(protocol)))
	if err != nil {
		return nil, err
	}
	return parseCredentialLines(string(data))
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

func parseCredentialLines(raw string) ([]Credential, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]Credential, 0, len(lines))
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
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
