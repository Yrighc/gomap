package secprobe

import (
	"fmt"

	"github.com/yrighc/gomap/pkg/secprobe/credentials"
)

func BuiltinCredentials(protocol string) ([]Credential, error) {
	spec, ok, err := lookupRuntimeMetadataSpec(normalizeProtocolToken(protocol), 0)
	if err != nil {
		return nil, fmt.Errorf("load secprobe metadata: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("unsupported secprobe credential protocol: %s", normalizeProtocolToken(protocol))
	}

	profile := credentials.ProfileFromMetadata(spec.Name, spec.Dictionary)
	profile = profile.WithScanProfile(string(credentials.ScanProfileDefault))
	generated, _, err := (credentials.Generator{}).Generate(credentials.GenerateInput{Profile: profile})
	if err != nil {
		return nil, translateCredentialGenerationError(protocol, err)
	}
	return coreCredentials(generated), nil
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
