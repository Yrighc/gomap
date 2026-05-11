package secprobe

import (
	"fmt"
	"strings"
	"sync"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

type ProtocolSpec struct {
	Name               string
	Aliases            []string
	Ports              []int
	DefaultUsers       []string
	PasswordSource     string
	ProbeKinds         []ProbeKind
	SupportsEnrichment bool
}

var metadataSpecLoader = metadata.LoadBuiltin

var (
	builtinMetadataSpecsOnce sync.Once
	builtinMetadataSpecs     map[string]metadata.Spec
	builtinMetadataSpecsErr  error
)

var legacyProtocolSpecs = []ProtocolSpec{}

func LookupProtocolSpec(service string, port int) (ProtocolSpec, bool) {
	rawToken := rawProtocolToken(service)
	token := normalizeProtocolToken(service)
	spec, ok, err := lookupMetadataProtocolSpec(rawToken, token, port)
	if ok {
		return spec, true
	}
	if err != nil {
		panic(fmt.Errorf("load secprobe metadata: %w", err))
	}
	return lookupLegacyProtocolSpec(rawToken, token, port)
}

func lookupMetadataProtocolSpec(rawToken, token string, port int) (ProtocolSpec, bool, error) {
	specs, err := builtinMetadataSpecsOnceValue()
	if err != nil {
		return ProtocolSpec{}, false, err
	}

	if rawToken != "" {
		for _, spec := range specs {
			if spec.Name == rawToken || containsString(spec.Aliases, rawToken) {
				protocolSpec := fromMetadataSpec(spec)
				if !tokenSupportsPort(rawToken, port) {
					return ProtocolSpec{}, false, nil
				}
				if port != 0 && requiresStrictPortMatch(protocolSpec.Name) && !specSupportsPort(protocolSpec, port) {
					return ProtocolSpec{}, false, nil
				}
				return protocolSpec, true, nil
			}
		}
	}

	if token != "" {
		for _, spec := range specs {
			if spec.Name == token || containsString(spec.Aliases, token) {
				protocolSpec := fromMetadataSpec(spec)
				if rawToken != "" && !tokenSupportsPort(rawToken, port) {
					return ProtocolSpec{}, false, nil
				}
				if port != 0 && requiresStrictPortMatch(protocolSpec.Name) && !specSupportsPort(protocolSpec, port) {
					return ProtocolSpec{}, false, nil
				}
				return protocolSpec, true, nil
			}
		}
	}

	if port != 0 {
		for _, spec := range specs {
			if containsPort(spec.Ports, port) {
				return fromMetadataSpec(spec), true, nil
			}
		}
	}

	return ProtocolSpec{}, false, nil
}

func lookupLegacyProtocolSpec(rawToken, token string, port int) (ProtocolSpec, bool) {
	if rawToken != "" {
		for _, spec := range legacyProtocolSpecs {
			matched := spec.Name == rawToken
			if !matched {
				for _, alias := range spec.Aliases {
					if alias == rawToken {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
			if !tokenSupportsPort(rawToken, port) {
				return ProtocolSpec{}, false
			}
			if port != 0 && requiresStrictPortMatch(spec.Name) && !specSupportsPort(spec, port) {
				return ProtocolSpec{}, false
			}
			return cloneProtocolSpec(spec), true
		}
	}

	if token != "" {
		for _, spec := range legacyProtocolSpecs {
			matched := spec.Name == token
			if !matched {
				for _, alias := range spec.Aliases {
					if alias == token {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
			if rawToken != "" && !tokenSupportsPort(rawToken, port) {
				return ProtocolSpec{}, false
			}
			if port != 0 && requiresStrictPortMatch(spec.Name) && !specSupportsPort(spec, port) {
				return ProtocolSpec{}, false
			}
			return cloneProtocolSpec(spec), true
		}
	}

	if port != 0 {
		for _, spec := range legacyProtocolSpecs {
			for _, candidatePort := range spec.Ports {
				if candidatePort == port {
					return cloneProtocolSpec(spec), true
				}
			}
		}
	}

	return ProtocolSpec{}, false
}

func ProtocolSupportsKind(service string, kind ProbeKind) bool {
	spec, ok := LookupProtocolSpec(service, 0)
	if !ok {
		return false
	}
	for _, declared := range spec.ProbeKinds {
		if declared == kind {
			return true
		}
	}
	return false
}

func rawProtocolToken(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	return strings.TrimSuffix(service, "?")
}

func normalizeProtocolToken(service string) string {
	service = rawProtocolToken(service)
	service = strings.TrimSuffix(service, "/ssl")
	return service
}

func cloneProtocolSpec(spec ProtocolSpec) ProtocolSpec {
	spec.Aliases = append([]string(nil), spec.Aliases...)
	spec.Ports = append([]int(nil), spec.Ports...)
	spec.DefaultUsers = append([]string(nil), spec.DefaultUsers...)
	spec.ProbeKinds = append([]ProbeKind(nil), spec.ProbeKinds...)
	return spec
}

func requiresStrictPortMatch(name string) bool {
	return name == "oracle" || name == "snmp"
}

func specSupportsPort(spec ProtocolSpec, port int) bool {
	for _, candidatePort := range spec.Ports {
		if candidatePort == port {
			return true
		}
	}
	return false
}

func tokenSupportsPort(token string, port int) bool {
	if port == 0 {
		return true
	}

	if required, ok := secureAliasPort(token); ok {
		return port == required
	}

	return true
}

func secureAliasPort(token string) (int, bool) {
	switch token {
	case "imaps", "imap/ssl":
		return 993, true
	case "pop3s", "pop3/ssl":
		return 995, true
	case "ldaps":
		return 636, true
	default:
		return 0, false
	}
}

func fromMetadataSpec(spec metadata.Spec) ProtocolSpec {
	probeKinds := make([]ProbeKind, 0, 2)
	if spec.Capabilities.Credential {
		probeKinds = append(probeKinds, ProbeKindCredential)
	}
	if spec.Capabilities.Unauthorized {
		probeKinds = append(probeKinds, ProbeKindUnauthorized)
	}

	return ProtocolSpec{
		Name:               spec.Name,
		Aliases:            append([]string(nil), spec.Aliases...),
		Ports:              append([]int(nil), spec.Ports...),
		DefaultUsers:       append([]string(nil), spec.Dictionary.DefaultUsers...),
		PasswordSource:     spec.Dictionary.PasswordSource,
		ProbeKinds:         probeKinds,
		SupportsEnrichment: spec.Capabilities.Enrichment,
	}
}

func uniqueNonEmptyStrings(values []string) []string {
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsPort(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func builtinMetadataSpecsOnceValue() (map[string]metadata.Spec, error) {
	builtinMetadataSpecsOnce.Do(func() {
		builtinMetadataSpecs, builtinMetadataSpecsErr = metadataSpecLoader()
	})
	return builtinMetadataSpecs, builtinMetadataSpecsErr
}

func resetBuiltinMetadataSpecsForTest() {
	builtinMetadataSpecsOnce = sync.Once{}
	builtinMetadataSpecs = nil
	builtinMetadataSpecsErr = nil
}
