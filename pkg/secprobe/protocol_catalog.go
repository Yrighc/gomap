package secprobe

import "strings"

type ProtocolSpec struct {
	Name               string
	Aliases            []string
	Ports              []int
	DictNames          []string
	ProbeKinds         []ProbeKind
	SupportsEnrichment bool
}

var builtinProtocolSpecs = []ProtocolSpec{
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
		Name:       "mysql",
		Ports:      []int{3306},
		DictNames:  []string{"mysql"},
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
		Name:               "mongodb",
		Aliases:            []string{"mongo"},
		Ports:              []int{27017},
		DictNames:          []string{"mongodb", "mongo"},
		ProbeKinds:         []ProbeKind{ProbeKindUnauthorized},
		SupportsEnrichment: true,
	},
	{
		Name:       "vnc",
		Ports:      []int{5900},
		DictNames:  []string{"vnc"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
}

func LookupProtocolSpec(service string, port int) (ProtocolSpec, bool) {
	token := normalizeProtocolToken(service)
	if token != "" {
		for _, spec := range builtinProtocolSpecs {
			if spec.Name == token {
				return cloneProtocolSpec(spec), true
			}
			for _, alias := range spec.Aliases {
				if alias == token {
					return cloneProtocolSpec(spec), true
				}
			}
		}
	}

	if port != 0 {
		for _, spec := range builtinProtocolSpecs {
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
