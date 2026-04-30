package secprobe

import (
	"strings"
	"sync"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

type ProtocolSpec struct {
	Name               string
	Aliases            []string
	Ports              []int
	DictNames          []string
	ProbeKinds         []ProbeKind
	SupportsEnrichment bool
}

var builtinMetadataSpecs = sync.OnceValues(func() (map[string]metadata.Spec, error) {
	return metadata.LoadBuiltin()
})

var legacyProtocolSpecs = []ProtocolSpec{
	{
		Name:       "ftp",
		Ports:      []int{21},
		DictNames:  []string{"ftp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "mssql",
		Ports:      []int{1433},
		DictNames:  []string{"mssql"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "ssh",
		Ports:      []int{22},
		DictNames:  []string{"ssh"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "telnet",
		Ports:      []int{23},
		DictNames:  []string{"telnet"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "smtp",
		Aliases:    []string{"smtps"},
		Ports:      []int{25, 465, 587},
		DictNames:  []string{"smtp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "mysql",
		Ports:      []int{3306},
		DictNames:  []string{"mysql"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "memcached",
		Ports:      []int{11211},
		ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
	},
	{
		Name:       "oracle",
		Aliases:    []string{"oracle-tns"},
		Ports:      []int{1521},
		DictNames:  []string{"oracle"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "rdp",
		Ports:      []int{3389},
		DictNames:  []string{"rdp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "postgresql",
		Aliases:    []string{"postgres", "pgsql"},
		Ports:      []int{5432},
		DictNames:  []string{"postgresql", "postgres"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "amqp",
		Aliases:    []string{"amqps"},
		Ports:      []int{5672, 5671},
		DictNames:  []string{"amqp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:               "redis",
		Aliases:            []string{"redis/tls", "redis/ssl"},
		Ports:              []int{6379},
		DictNames:          []string{"redis"},
		ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
		SupportsEnrichment: true,
	},
	{
		Name:       "smb",
		Aliases:    []string{"cifs"},
		Ports:      []int{445, 139},
		DictNames:  []string{"smb"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "snmp",
		Ports:      []int{161},
		DictNames:  []string{"snmp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:               "mongodb",
		Aliases:            []string{"mongo"},
		Ports:              []int{27017},
		DictNames:          []string{"mongodb", "mongo"},
		ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
		SupportsEnrichment: true,
	},
	{
		Name:       "vnc",
		Ports:      []int{5900},
		DictNames:  []string{"vnc"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "zookeeper",
		Ports:      []int{2181},
		ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
	},
}

func LookupProtocolSpec(service string, port int) (ProtocolSpec, bool) {
	token := normalizeProtocolToken(service)
	if spec, ok := lookupMetadataProtocolSpec(token, port); ok {
		return spec, true
	}
	return lookupLegacyProtocolSpec(token, port)
}

func lookupMetadataProtocolSpec(token string, port int) (ProtocolSpec, bool) {
	specs, err := builtinMetadataSpecs()
	if err != nil {
		return ProtocolSpec{}, false
	}

	if token != "" {
		for _, spec := range specs {
			if spec.Name == token || containsString(spec.Aliases, token) {
				return fromMetadataSpec(spec), true
			}
		}
	}

	if port != 0 {
		for _, spec := range specs {
			if containsPort(spec.Ports, port) {
				return fromMetadataSpec(spec), true
			}
		}
	}

	return ProtocolSpec{}, false
}

func lookupLegacyProtocolSpec(token string, port int) (ProtocolSpec, bool) {
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

func normalizeProtocolToken(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	service = strings.TrimSuffix(service, "?")
	service = strings.TrimSuffix(service, "/ssl")
	return service
}

func cloneProtocolSpec(spec ProtocolSpec) ProtocolSpec {
	spec.Aliases = append([]string(nil), spec.Aliases...)
	spec.Ports = append([]int(nil), spec.Ports...)
	spec.DictNames = append([]string(nil), spec.DictNames...)
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
		DictNames:          append([]string(nil), spec.Dictionary.DefaultSources...),
		ProbeKinds:         probeKinds,
		SupportsEnrichment: spec.Capabilities.Enrichment,
	}
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
