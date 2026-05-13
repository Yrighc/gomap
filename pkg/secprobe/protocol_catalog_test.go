package secprobe

import (
	"errors"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

const sharedPasswordSource = "builtin:passwords/global"

func TestLookupProtocolSpecSupportsAliasesAndPortFallback(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    string
		users   []string
		enrich  bool
	}{
		{name: "postgres alias", service: "postgres", want: "postgresql", enrich: true},
		{name: "pgsql alias", service: "pgsql", want: "postgresql", enrich: true},
		{name: "mongo alias", service: "mongo", want: "mongodb", users: []string{"root", "admin"}, enrich: true},
		{name: "redis tls alias", service: "redis/tls", want: "redis", users: []string{""}, enrich: true},
		{name: "mongodb port fallback", port: 27017, want: "mongodb", users: []string{"root", "admin"}, enrich: true},
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
			if spec.PasswordSource != sharedPasswordSource {
				t.Fatalf("expected shared password source, got %q", spec.PasswordSource)
			}
			if tt.users != nil && !reflect.DeepEqual(spec.DefaultUsers, tt.users) {
				t.Fatalf("expected default users %v, got %v", tt.users, spec.DefaultUsers)
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
	spec.DefaultUsers[0] = "changed"
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
	if again.DefaultUsers[0] != "" {
		t.Fatalf("expected default users to stay isolated, got %v", again.DefaultUsers)
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
				Dictionary: metadata.Dictionary{PasswordSource: sharedPasswordSource},
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

func TestLookupProtocolSpecRejectsSNMPMetadataTokenMatchOnWrongPort(t *testing.T) {
	restore := swapMetadataSpecLoaderForTest(func() (map[string]metadata.Spec, error) {
		return map[string]metadata.Spec{
			"snmp": {
				Name:  "snmp",
				Ports: []int{161},
				Dictionary: metadata.Dictionary{
					PasswordSource: sharedPasswordSource,
				},
				Capabilities: metadata.Capabilities{
					Credential: true,
				},
			},
		}, nil
	})
	defer restore()

	spec, ok := LookupProtocolSpec("snmp", 162)
	if ok {
		t.Fatalf("expected strict snmp metadata token match to reject wrong port, got %+v", spec)
	}
}

func TestLookupProtocolSpecRejectsSecureAliasOnNonTLSPort(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
	}{
		{name: "imaps on 143", service: "imaps", port: 143},
		{name: "imap ssl on 143", service: "imap/ssl", port: 143},
		{name: "pop3s on 110", service: "pop3s", port: 110},
		{name: "pop3 ssl on 110", service: "pop3/ssl", port: 110},
		{name: "ldaps on 389", service: "ldaps", port: 389},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if ok {
				t.Fatalf("expected secure alias %q to reject port %d, got %+v", tt.service, tt.port, spec)
			}
		})
	}
}

func TestLookupProtocolSpecIncludesCredentialProtocols(t *testing.T) {
	tests := []struct {
		name string
		in   SecurityCandidate
		want ProtocolSpec
	}{
		{
			name: "ftp",
			in:   SecurityCandidate{Service: "ftp"},
			want: ProtocolSpec{Name: "ftp", Ports: []int{21}, DefaultUsers: []string{"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "mssql",
			in:   SecurityCandidate{Service: "mssql"},
			want: ProtocolSpec{Name: "mssql", Ports: []int{1433}, DefaultUsers: []string{"sa", "sql"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "mysql by port",
			in:   SecurityCandidate{Port: 3306},
			want: ProtocolSpec{Name: "mysql", Ports: []int{3306}, DefaultUsers: []string{"root", "mysql"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}, SupportsEnrichment: true},
		},
		{
			name: "telnet",
			in:   SecurityCandidate{Service: "telnet"},
			want: ProtocolSpec{Name: "telnet", Ports: []int{23}, DefaultUsers: []string{"root", "admin", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "rdp by port",
			in:   SecurityCandidate{Port: 3389},
			want: ProtocolSpec{Name: "rdp", Ports: []int{3389}, DefaultUsers: []string{"administrator", "admin", "guest"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "vnc",
			in:   SecurityCandidate{Service: "vnc"},
			want: ProtocolSpec{Name: "vnc", Ports: []int{5900}, DefaultUsers: []string{""}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "smb alias",
			in:   SecurityCandidate{Service: "cifs"},
			want: ProtocolSpec{Name: "smb", Aliases: []string{"cifs"}, Ports: []int{445, 139}, DefaultUsers: []string{"administrator", "admin", "guest"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "smtp alias",
			in:   SecurityCandidate{Service: "smtps"},
			want: ProtocolSpec{Name: "smtp", Aliases: []string{"smtps"}, Ports: []int{25, 465, 587}, DefaultUsers: []string{"admin", "root", "postmaster", "mail", "smtp", "administrator"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "amqp port fallback",
			in:   SecurityCandidate{Port: 5672},
			want: ProtocolSpec{Name: "amqp", Aliases: []string{"amqps"}, Ports: []int{5672, 5671}, DefaultUsers: []string{"guest", "admin", "administrator", "rabbit", "rabbitmq", "root"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "oracle alias",
			in:   SecurityCandidate{Service: "oracle-tns"},
			want: ProtocolSpec{Name: "oracle", Aliases: []string{"oracle-tns"}, Ports: []int{1521}, DefaultUsers: []string{"sys", "system", "admin", "test", "web", "orcl"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "snmp port fallback",
			in:   SecurityCandidate{Port: 161},
			want: ProtocolSpec{Name: "snmp", Ports: []int{161}, DefaultUsers: []string{""}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "elasticsearch",
			in:   SecurityCandidate{Service: "elasticsearch", Port: 9200},
			want: ProtocolSpec{Name: "elasticsearch", Aliases: []string{"elastic"}, Ports: []int{9200}, DefaultUsers: []string{"elastic", "admin", "kibana"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}, SupportsEnrichment: true},
		},
		{
			name: "imap service",
			in:   SecurityCandidate{Service: "imap"},
			want: ProtocolSpec{Name: "imap", Aliases: []string{"imaps", "imap/ssl"}, Ports: []int{143, 993}, DefaultUsers: []string{"admin", "mail", "postmaster", "root", "user", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "imap alias",
			in:   SecurityCandidate{Service: "imaps"},
			want: ProtocolSpec{Name: "imap", Aliases: []string{"imaps", "imap/ssl"}, Ports: []int{143, 993}, DefaultUsers: []string{"admin", "mail", "postmaster", "root", "user", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "pop3 alias",
			in:   SecurityCandidate{Service: "pop3s"},
			want: ProtocolSpec{Name: "pop3", Aliases: []string{"pop3s", "pop3/ssl"}, Ports: []int{110, 995}, DefaultUsers: []string{"admin", "root", "mail", "user", "test", "postmaster"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "pop3 port fallback",
			in:   SecurityCandidate{Port: 995},
			want: ProtocolSpec{Name: "pop3", Aliases: []string{"pop3s", "pop3/ssl"}, Ports: []int{110, 995}, DefaultUsers: []string{"admin", "root", "mail", "user", "test", "postmaster"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "kafka service",
			in:   SecurityCandidate{Service: "kafka"},
			want: ProtocolSpec{Name: "kafka", Ports: []int{9092}, DefaultUsers: []string{"admin", "kafka", "root", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "kafka port fallback",
			in:   SecurityCandidate{Port: 9092},
			want: ProtocolSpec{Name: "kafka", Ports: []int{9092}, DefaultUsers: []string{"admin", "kafka", "root", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "ldap service",
			in:   SecurityCandidate{Service: "ldap"},
			want: ProtocolSpec{Name: "ldap", Aliases: []string{"ldaps"}, Ports: []int{389, 636}, DefaultUsers: []string{"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "ldap alias",
			in:   SecurityCandidate{Service: "ldaps"},
			want: ProtocolSpec{Name: "ldap", Aliases: []string{"ldaps"}, Ports: []int{389, 636}, DefaultUsers: []string{"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "ldap port fallback",
			in:   SecurityCandidate{Port: 636},
			want: ProtocolSpec{Name: "ldap", Aliases: []string{"ldaps"}, Ports: []int{389, 636}, DefaultUsers: []string{"admin", "administrator", "root", "cn=admin", "cn=administrator", "cn=manager"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.in.Service, tt.in.Port)
			if !ok {
				t.Fatalf("expected protocol spec for %+v", tt.in)
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

func TestLookupProtocolSpecIncludesMetadataProtocols(t *testing.T) {
	tests := []struct {
		name string
		in   SecurityCandidate
		want ProtocolSpec
	}{
		{
			name: "activemq service",
			in:   SecurityCandidate{Service: "activemq"},
			want: ProtocolSpec{Name: "activemq", Ports: []int{61613}, DefaultUsers: []string{"admin", "root", "activemq", "system", "user"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "zabbix service",
			in:   SecurityCandidate{Service: "zabbix"},
			want: ProtocolSpec{Name: "zabbix", Ports: []int{80, 443, 8080, 8443}, DefaultUsers: []string{"admin", "admin", "guest", "user"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
		{
			name: "neo4j port fallback",
			in:   SecurityCandidate{Port: 7474},
			want: ProtocolSpec{Name: "neo4j", Ports: []int{7474, 7473}, DefaultUsers: []string{"neo4j", "admin", "root", "test"}, PasswordSource: sharedPasswordSource, ProbeKinds: []ProbeKind{ProbeKindCredential}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.in.Service, tt.in.Port)
			if !ok {
				t.Fatalf("expected protocol spec for %+v", tt.in)
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

func TestLookupProtocolSpecIncludesUnauthorizedProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "memcached by name",
			service: "memcached",
			want:    ProtocolSpec{Name: "memcached", Ports: []int{11211}, ProbeKinds: []ProbeKind{ProbeKindUnauthorized}},
		},
		{
			name: "zookeeper by port",
			port: 2181,
			want: ProtocolSpec{Name: "zookeeper", Ports: []int{2181}, ProbeKinds: []ProbeKind{ProbeKindUnauthorized}},
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

func TestLookupProtocolSpecSupportsElasticsearchCredentialOnly(t *testing.T) {
	spec, ok := LookupProtocolSpec("elasticsearch", 9200)
	if !ok {
		t.Fatal("expected elasticsearch protocol spec")
	}
	wantKinds := []ProbeKind{ProbeKindCredential}
	if !reflect.DeepEqual(spec.ProbeKinds, wantKinds) {
		t.Fatalf("expected elasticsearch probe kinds %v, got %v", wantKinds, spec.ProbeKinds)
	}
	if spec.PasswordSource != sharedPasswordSource {
		t.Fatalf("expected shared password source, got %q", spec.PasswordSource)
	}
	if !reflect.DeepEqual(spec.DefaultUsers, []string{"elastic", "admin", "kibana"}) {
		t.Fatalf("expected elasticsearch default users, got %v", spec.DefaultUsers)
	}
	if !spec.SupportsEnrichment {
		t.Fatalf("expected elasticsearch enrichment support, got %+v", spec)
	}
	if !ProtocolSupportsKind("elasticsearch", ProbeKindCredential) {
		t.Fatal("expected elasticsearch credential probing to be declared")
	}
	if ProtocolSupportsKind("elasticsearch", ProbeKindUnauthorized) {
		t.Fatal("expected elasticsearch unauthorized probing to stay unsupported")
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
	if !ProtocolSupportsKind("elasticsearch", ProbeKindCredential) {
		t.Fatal("expected elasticsearch credential probing to be declared")
	}
	if ProtocolSupportsKind("elasticsearch", ProbeKindUnauthorized) {
		t.Fatal("expected elasticsearch unauthorized probing to stay unsupported")
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
