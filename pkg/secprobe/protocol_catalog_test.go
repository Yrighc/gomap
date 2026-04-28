package secprobe

import (
	"reflect"
	"testing"
)

func TestLookupProtocolSpecSupportsAliasesAndPortFallback(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    string
		dicts   []string
		enrich  bool
	}{
		{name: "postgres alias", service: "postgres", want: "postgresql", dicts: []string{"postgresql", "postgres"}},
		{name: "pgsql alias", service: "pgsql", want: "postgresql", dicts: []string{"postgresql", "postgres"}},
		{name: "mongo alias", service: "mongo", want: "mongodb", dicts: []string{"mongodb", "mongo"}, enrich: true},
		{name: "redis tls alias", service: "redis/tls", want: "redis", dicts: []string{"redis"}, enrich: true},
		{name: "mongodb port fallback", port: 27017, want: "mongodb", dicts: []string{"mongodb", "mongo"}, enrich: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if spec.Name != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, spec.Name)
			}
			if !reflect.DeepEqual(spec.DictNames, tt.dicts) {
				t.Fatalf("expected dict names %v, got %v", tt.dicts, spec.DictNames)
			}
			if spec.SupportsEnrichment != tt.enrich {
				t.Fatalf("expected SupportsEnrichment=%v, got %v", tt.enrich, spec.SupportsEnrichment)
			}
		})
	}
}

func TestLookupProtocolSpecReturnsIsolatedSlices(t *testing.T) {
	spec, ok := LookupProtocolSpec("redis", 0)
	if !ok {
		t.Fatal("expected redis protocol spec")
	}

	spec.Aliases[0] = "mutated"
	spec.Ports[0] = 1
	spec.DictNames[0] = "changed"
	spec.ProbeKinds[0] = ProbeKindUnauthorized

	again, ok := LookupProtocolSpec("redis", 0)
	if !ok {
		t.Fatal("expected redis protocol spec on second lookup")
	}

	if again.Aliases[0] != "redis/tls" {
		t.Fatalf("expected aliases to stay isolated, got %v", again.Aliases)
	}
	if again.Ports[0] != 6379 {
		t.Fatalf("expected ports to stay isolated, got %v", again.Ports)
	}
	if again.DictNames[0] != "redis" {
		t.Fatalf("expected dict names to stay isolated, got %v", again.DictNames)
	}
	if again.ProbeKinds[0] != ProbeKindCredential {
		t.Fatalf("expected probe kinds to stay isolated, got %v", again.ProbeKinds)
	}
}

func TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "mssql by name",
			service: "mssql",
			want: ProtocolSpec{
				Name:       "mssql",
				Ports:      []int{1433},
				DictNames:  []string{"mssql"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name: "rdp by port",
			port: 3389,
			want: ProtocolSpec{
				Name:       "rdp",
				Ports:      []int{3389},
				DictNames:  []string{"rdp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name:    "vnc by name",
			service: "vnc",
			want: ProtocolSpec{
				Name:       "vnc",
				Ports:      []int{5900},
				DictNames:  []string{"vnc"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name:    "smb alias",
			service: "cifs",
			want: ProtocolSpec{
				Name:       "smb",
				Aliases:    []string{"cifs"},
				Ports:      []int{445, 139},
				DictNames:  []string{"smb"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if !reflect.DeepEqual(spec, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, spec)
			}
		})
	}
}

func TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "smtp alias",
			service: "smtps",
			want: ProtocolSpec{
				Name:       "smtp",
				Aliases:    []string{"smtps"},
				Ports:      []int{25, 465, 587},
				DictNames:  []string{"smtp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name: "amqp port fallback",
			port: 5672,
			want: ProtocolSpec{
				Name:       "amqp",
				Aliases:    []string{"amqps"},
				Ports:      []int{5672, 5671},
				DictNames:  []string{"amqp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if !reflect.DeepEqual(spec, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, spec)
			}
			if !ProtocolSupportsKind(tt.want.Name, ProbeKindCredential) {
				t.Fatalf("expected %s credential probing to be declared", tt.want.Name)
			}
		})
	}
}

func TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "oracle alias",
			service: "oracle-tns",
			want: ProtocolSpec{
				Name:       "oracle",
				Aliases:    []string{"oracle-tns"},
				Ports:      []int{1521},
				DictNames:  []string{"oracle"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name: "snmp port fallback",
			port: 161,
			want: ProtocolSpec{
				Name:       "snmp",
				Ports:      []int{161},
				DictNames:  []string{"snmp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if !reflect.DeepEqual(spec, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, spec)
			}
			if !ProtocolSupportsKind(tt.want.Name, ProbeKindCredential) {
				t.Fatalf("expected %s credential probing to be declared", tt.want.Name)
			}
		})
	}
}

func TestProtocolSupportsKindUsesCatalogDeclaration(t *testing.T) {
	if !ProtocolSupportsKind("redis", ProbeKindCredential) {
		t.Fatal("expected redis to support credential probing")
	}
	if !ProtocolSupportsKind("redis", ProbeKindUnauthorized) {
		t.Fatal("expected redis to support unauthorized probing")
	}
	if ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to stay unsupported")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to be declared")
	}
}
