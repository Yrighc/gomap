package secprobe

import "testing"

func TestRegisterDefaultProbersKeepsBuiltinCredentialsAtomicOnly(t *testing.T) {
	r := NewRegistry()
	RegisterDefaultProbers(r)

	tests := []SecurityCandidate{
		{Service: "ftp", Port: 21},
		{Service: "imap", Port: 143},
		{Service: "ssh", Port: 22},
		{Service: "telnet", Port: 23},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "redis", Port: 6379},
		{Service: "elasticsearch", Port: 9200},
		{Service: "mssql", Port: 1433},
		{Service: "smtp", Port: 587},
		{Service: "oracle", Port: 1521},
		{Service: "snmp", Port: 161},
		{Service: "amqp", Port: 5672},
		{Service: "rdp", Port: 3389},
		{Service: "vnc", Port: 5900},
		{Service: "smb", Port: 445},
		{Service: "mongodb", Port: 27017},
	}

	for _, candidate := range tests {
		t.Run(candidate.Service, func(t *testing.T) {
			if _, ok := r.lookupAtomicCredential(candidate); !ok {
				t.Fatalf("expected atomic credential plugin for %+v", candidate)
			}
			if _, ok := r.Lookup(candidate, ProbeKindCredential); ok {
				t.Fatalf("expected builtin credential lookup miss for %+v", candidate)
			}
			if _, ok := r.lookupCore(candidate, ProbeKindCredential); ok {
				t.Fatalf("expected builtin credential core lookup miss for %+v", candidate)
			}
		})
	}
}

func TestDefaultRegistryBuiltinCredentialCapabilityIsAtomicOnly(t *testing.T) {
	r := DefaultRegistry()

	tests := []SecurityCandidate{
		{Service: "ftp", Port: 21},
		{Service: "imap", Port: 143},
		{Service: "ssh", Port: 22},
		{Service: "telnet", Port: 23},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "redis", Port: 6379},
		{Service: "elasticsearch", Port: 9200},
		{Service: "mssql", Port: 1433},
		{Service: "smtp", Port: 587},
		{Service: "oracle", Port: 1521},
		{Service: "snmp", Port: 161},
		{Service: "amqp", Port: 5672},
		{Service: "rdp", Port: 3389},
		{Service: "vnc", Port: 5900},
		{Service: "smb", Port: 445},
		{Service: "mongodb", Port: 27017},
	}

	for _, candidate := range tests {
		t.Run(candidate.Service, func(t *testing.T) {
			if !r.hasCapability(candidate, ProbeKindCredential) {
				t.Fatalf("expected credential capability for %+v", candidate)
			}
			if _, ok := r.lookupAtomicCredential(candidate); !ok {
				t.Fatalf("expected atomic credential plugin for %+v", candidate)
			}
			if _, ok := r.Lookup(candidate, ProbeKindCredential); ok {
				t.Fatalf("expected builtin credential public lookup miss for %+v", candidate)
			}
			if _, ok := r.lookupCore(candidate, ProbeKindCredential); ok {
				t.Fatalf("expected builtin credential core lookup miss for %+v", candidate)
			}
		})
	}
}

func TestDefaultRegistryUnauthorizedLookupStillUsesLegacyCoreProbers(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		name      string
		candidate SecurityCandidate
		wantName  string
	}{
		{name: "redis", candidate: SecurityCandidate{Service: "redis", Port: 6379}, wantName: "redis-unauthorized"},
		{name: "mongodb", candidate: SecurityCandidate{Service: "mongodb", Port: 27017}, wantName: "mongodb-unauthorized"},
		{name: "zookeeper", candidate: SecurityCandidate{Service: "zookeeper", Port: 2181}, wantName: "zookeeper-unauthorized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, ok := r.Lookup(tt.candidate, ProbeKindUnauthorized)
			if !ok {
				t.Fatalf("expected unauthorized lookup hit for %+v", tt.candidate)
			}
			if got := prober.Name(); got != tt.wantName {
				t.Fatalf("expected unauthorized public prober %q, got %q", tt.wantName, got)
			}

			coreProber, ok := r.lookupCore(tt.candidate, ProbeKindUnauthorized)
			if !ok {
				t.Fatalf("expected internal unauthorized lookup hit for %+v", tt.candidate)
			}
			wrapped, ok := coreProber.(*registryProber)
			if !ok {
				t.Fatalf("expected wrapped registry prober for %+v, got %T", tt.candidate, coreProber)
			}
			if _, ok := wrapped.public.(corePublicProber); !ok {
				t.Fatalf("expected unauthorized lookup for %+v to keep core-backed public wrapper", tt.candidate)
			}
		})
	}
}

func TestDefaultRegistryRegistersMemcachedUnauthorizedAsAtomicOnly(t *testing.T) {
	r := DefaultRegistry()
	candidate := SecurityCandidate{Service: "memcached", Port: 11211}

	if !r.hasCapability(candidate, ProbeKindUnauthorized) {
		t.Fatalf("expected memcached unauthorized capability for %+v", candidate)
	}
	if _, ok := r.lookupAtomicUnauthorized(candidate); !ok {
		t.Fatalf("expected memcached unauthorized atomic checker for %+v", candidate)
	}
	if _, ok := r.Lookup(candidate, ProbeKindUnauthorized); ok {
		t.Fatalf("expected memcached unauthorized public lookup miss for %+v", candidate)
	}
	if _, ok := r.lookupCore(candidate, ProbeKindUnauthorized); ok {
		t.Fatalf("expected memcached unauthorized core lookup miss for %+v", candidate)
	}
}

func TestDefaultRegistryDelegatesToRegisterDefaultProbers(t *testing.T) {
	defaultRegistry := DefaultRegistry()
	registeredRegistry := NewRegistry()
	RegisterDefaultProbers(registeredRegistry)

	tests := []struct {
		name      string
		candidate SecurityCandidate
		kind      ProbeKind
	}{
		{
			name:      "ssh credential",
			candidate: SecurityCandidate{Service: "ssh", Port: 22},
			kind:      ProbeKindCredential,
		},
		{
			name:      "redis unauthorized",
			candidate: SecurityCandidate{Service: "redis", Port: 6379},
			kind:      ProbeKindUnauthorized,
		},
		{
			name:      "mongodb unauthorized",
			candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
			kind:      ProbeKindUnauthorized,
		},
		{
			name:      "zookeeper unauthorized",
			candidate: SecurityCandidate{Service: "zookeeper", Port: 2181},
			kind:      ProbeKindUnauthorized,
		},
		{
			name:      "mongodb credential hit",
			candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
			kind:      ProbeKindCredential,
		},
		{
			name:      "memcached unauthorized capability parity",
			candidate: SecurityCandidate{Service: "memcached", Port: 11211},
			kind:      ProbeKindUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDefault, okDefault := defaultRegistry.Lookup(tt.candidate, tt.kind)
			gotRegistered, okRegistered := registeredRegistry.Lookup(tt.candidate, tt.kind)
			if okDefault != okRegistered {
				t.Fatalf("expected lookup parity for %+v/%s, got default=%t registered=%t", tt.candidate, tt.kind, okDefault, okRegistered)
			}
			if !okDefault {
				if tt.candidate.Service == "memcached" && tt.kind == ProbeKindUnauthorized {
					if !defaultRegistry.hasCapability(tt.candidate, tt.kind) || !registeredRegistry.hasCapability(tt.candidate, tt.kind) {
						t.Fatalf("expected memcached unauthorized capability parity for %+v/%s", tt.candidate, tt.kind)
					}
				}
				return
			}
			if gotDefault.Name() != gotRegistered.Name() {
				t.Fatalf("expected same prober for %+v/%s, got default=%q registered=%q", tt.candidate, tt.kind, gotDefault.Name(), gotRegistered.Name())
			}
		})
	}
}

func TestDefaultRegistryRegistersAtomicRedisAndSSHPlugins(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "ssh", Port: 22}); !ok {
		t.Fatal("expected ssh atomic credential plugin")
	}
	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "redis", Port: 6379}); !ok {
		t.Fatal("expected redis atomic credential plugin")
	}
	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "elasticsearch", Port: 9200}); !ok {
		t.Fatal("expected elasticsearch atomic credential plugin")
	}
	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "imap", Port: 143}); !ok {
		t.Fatal("expected imap atomic credential plugin")
	}
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "redis", Port: 6379}); !ok {
		t.Fatal("expected redis atomic unauthorized plugin")
	}
}

func TestDefaultRegistryRegistersMemcachedUnauthorizedTemplateChecker(t *testing.T) {
	r := DefaultRegistry()
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "memcached", Port: 11211}); !ok {
		t.Fatal("expected memcached unauthorized template checker")
	}
}

func TestDefaultRegistryKeepsStrictPortSemanticsForAtomicSNMP(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "snmp", Port: 161}); !ok {
		t.Fatal("expected snmp atomic credential plugin on port 161")
	}
	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "snmp", Port: 162}); ok {
		t.Fatal("expected snmp atomic credential plugin to reject non-161 port")
	}
}

func TestDefaultRegistryRegistersAtomicCredentialPluginsForAllBuiltinCredentialProtocols(t *testing.T) {
	r := DefaultRegistry()

	tests := []SecurityCandidate{
		{Service: "ftp", Port: 21},
		{Service: "imap", Port: 143},
		{Service: "ssh", Port: 22},
		{Service: "mssql", Port: 1433},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "redis", Port: 6379},
		{Service: "smtp", Port: 25},
		{Service: "telnet", Port: 23},
		{Service: "amqp", Port: 5672},
		{Service: "oracle", Port: 1521},
		{Service: "rdp", Port: 3389},
		{Service: "vnc", Port: 5900},
		{Service: "smb", Port: 445},
		{Service: "snmp", Port: 161},
		{Service: "mongodb", Port: 27017},
	}

	for _, candidate := range tests {
		if _, ok := r.lookupAtomicCredential(candidate); !ok {
			t.Fatalf("expected atomic credential plugin for %+v", candidate)
		}
	}
}

func TestDefaultRegistryBuiltinCredentialCapabilityIncludesIMAP(t *testing.T) {
	r := DefaultRegistry()
	candidate := SecurityCandidate{Service: "imap", Port: 143}

	if !r.hasCapability(candidate, ProbeKindCredential) {
		t.Fatalf("expected imap credential capability for %+v", candidate)
	}
	if _, ok := r.lookupAtomicCredential(candidate); !ok {
		t.Fatalf("expected imap atomic credential plugin for %+v", candidate)
	}
	if _, ok := r.Lookup(candidate, ProbeKindCredential); ok {
		t.Fatalf("expected builtin credential public lookup miss for %+v", candidate)
	}
	if _, ok := r.lookupCore(candidate, ProbeKindCredential); ok {
		t.Fatalf("expected builtin credential core lookup miss for %+v", candidate)
	}
}

func TestDefaultRegistryLeavesOnlyZookeeperOnBuiltinCoreUnauthorizedPath(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "ftp", Port: 21}); !ok {
		t.Fatal("expected ftp atomic credential plugin")
	}
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "memcached", Port: 11211}); !ok {
		t.Fatal("expected memcached atomic unauthorized checker")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "zookeeper", Port: 2181}, ProbeKindUnauthorized); !ok {
		t.Fatal("expected zookeeper compatibility prober to remain")
	}
}
