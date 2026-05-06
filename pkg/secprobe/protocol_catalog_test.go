package secprobe

import (
	"errors"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
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

	if again.Aliases[0] != "redis/ssl" {
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

func TestLookupProtocolSpecPrefersYAMLMetadata(t *testing.T) {
	spec, ok := LookupProtocolSpec("redis/tls", 6379)
	if !ok {
		t.Fatal("expected redis/tls alias to resolve")
	}
	if spec.Name != "redis" {
		t.Fatalf("expected redis spec, got %+v", spec)
	}
	if !spec.SupportsEnrichment {
		t.Fatalf("expected redis enrichment support, got %+v", spec)
	}
}

func TestLookupProtocolSpecPanicsWhenMetadataLoadFailsForMigratedProtocol(t *testing.T) {
	restore := swapMetadataSpecLoaderForTest(func() (map[string]metadata.Spec, error) {
		return nil, errors.New("boom")
	})
	defer restore()

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("expected metadata loader failure to panic for migrated protocol")
		}
	}()

	LookupProtocolSpec("redis/tls", 6379)
}

func TestLookupProtocolSpecRejectsStrictMetadataTokenMatchOnWrongPort(t *testing.T) {
	restore := swapMetadataSpecLoaderForTest(func() (map[string]metadata.Spec, error) {
		return map[string]metadata.Spec{
			"oracle": {
				Name:       "oracle",
				Aliases:    []string{"oracle-tns"},
				Ports:      []int{1521},
				Dictionary: metadata.Dictionary{DefaultSources: []string{"oracle"}},
				Capabilities: metadata.Capabilities{
					Credential: true,
				},
			},
		}, nil
	})
	defer restore()

	spec, ok := LookupProtocolSpec("oracle-tns", 3306)
	if ok {
		t.Fatalf("expected strict metadata token match to reject wrong port, got %+v", spec)
	}
}

func TestLookupProtocolSpecPhase2MetadataMatchesHistoricalLegacyContracts(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			service: "ftp",
			want: ProtocolSpec{
				Name:       "ftp",
				Ports:      []int{21},
				DictNames:  []string{"ftp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			service: "memcached",
			want: ProtocolSpec{
				Name:       "memcached",
				Ports:      []int{11211},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
			},
		},
		{
			service: "mongo",
			want: ProtocolSpec{
				Name:               "mongodb",
				Aliases:            []string{"mongo"},
				Ports:              []int{27017},
				DictNames:          []string{"mongodb", "mongo"},
				ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
				SupportsEnrichment: true,
			},
		},
	}

	for _, tt := range tests {
		spec, ok := LookupProtocolSpec(tt.service, tt.port)
		if !ok {
			t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
		}
		if !reflect.DeepEqual(spec, tt.want) {
			t.Fatalf("expected %#v, got %#v", tt.want, spec)
		}
	}
}

func TestLookupProtocolSpecPhase2BatchAMetadataProtocols(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			service: "ftp",
			want: ProtocolSpec{
				Name:       "ftp",
				Ports:      []int{21},
				DictNames:  []string{"ftp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			service: "mssql",
			want: ProtocolSpec{
				Name:       "mssql",
				Ports:      []int{1433},
				DictNames:  []string{"mssql"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			port: 3306,
			want: ProtocolSpec{
				Name:       "mysql",
				Ports:      []int{3306},
				DictNames:  []string{"mysql"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			service: "telnet",
			want: ProtocolSpec{
				Name:       "telnet",
				Ports:      []int{23},
				DictNames:  []string{"telnet"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
	}

	for _, tt := range tests {
		spec, ok := LookupProtocolSpec(tt.service, tt.port)
		if !ok {
			t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
		}
		if !reflect.DeepEqual(spec, tt.want) {
			t.Fatalf("expected %#v, got %#v", tt.want, spec)
		}
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

func TestLookupProtocolSpecIncludesPhaseThreeUnauthorizedProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "memcached by name",
			service: "memcached",
			want: ProtocolSpec{
				Name:       "memcached",
				Ports:      []int{11211},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
			},
		},
		{
			name: "zookeeper by port",
			port: 2181,
			want: ProtocolSpec{
				Name:       "zookeeper",
				Ports:      []int{2181},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
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

func TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized(t *testing.T) {
	spec, ok := LookupProtocolSpec("mongodb", 27017)
	if !ok {
		t.Fatal("expected mongodb protocol spec")
	}
	wantKinds := []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized}
	if !reflect.DeepEqual(spec.ProbeKinds, wantKinds) {
		t.Fatalf("expected mongodb probe kinds %v, got %v", wantKinds, spec.ProbeKinds)
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to be declared")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to stay declared")
	}
}

func TestProtocolSupportsKindUsesCatalogDeclaration(t *testing.T) {
	if !ProtocolSupportsKind("redis", ProbeKindCredential) {
		t.Fatal("expected redis to support credential probing")
	}
	if !ProtocolSupportsKind("redis", ProbeKindUnauthorized) {
		t.Fatal("expected redis to support unauthorized probing")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to be declared")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to be declared")
	}
	if !ProtocolSupportsKind("memcached", ProbeKindUnauthorized) {
		t.Fatal("expected memcached unauthorized probing to be declared")
	}
	if ProtocolSupportsKind("memcached", ProbeKindCredential) {
		t.Fatal("expected memcached credential probing to stay unsupported")
	}
	if !ProtocolSupportsKind("zookeeper", ProbeKindUnauthorized) {
		t.Fatal("expected zookeeper unauthorized probing to be declared")
	}
	if ProtocolSupportsKind("zookeeper", ProbeKindCredential) {
		t.Fatal("expected zookeeper credential probing to stay unsupported")
	}
}
