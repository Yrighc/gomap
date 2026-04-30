package secprobe

import "testing"

func TestRegisterDefaultProbersRegistersBuiltinLookupTargets(t *testing.T) {
	r := NewRegistry()
	RegisterDefaultProbers(r)

	tests := []struct {
		name      string
		candidate SecurityCandidate
		kind      ProbeKind
		want      string
	}{
		{
			name:      "ssh credential",
			candidate: SecurityCandidate{Service: "ssh", Port: 22},
			kind:      ProbeKindCredential,
			want:      "ssh",
		},
		{
			name:      "redis credential",
			candidate: SecurityCandidate{Service: "redis", Port: 6379},
			kind:      ProbeKindCredential,
			want:      "redis",
		},
		{
			name:      "mssql credential",
			candidate: SecurityCandidate{Service: "mssql", Port: 1433},
			kind:      ProbeKindCredential,
			want:      "mssql",
		},
		{
			name:      "rdp credential",
			candidate: SecurityCandidate{Service: "rdp", Port: 3389},
			kind:      ProbeKindCredential,
			want:      "rdp",
		},
		{
			name:      "smtp credential",
			candidate: SecurityCandidate{Service: "smtp", Port: 587},
			kind:      ProbeKindCredential,
			want:      "smtp",
		},
		{
			name:      "oracle credential",
			candidate: SecurityCandidate{Service: "oracle", Port: 1521},
			kind:      ProbeKindCredential,
			want:      "oracle",
		},
		{
			name:      "snmp credential",
			candidate: SecurityCandidate{Service: "snmp", Port: 161},
			kind:      ProbeKindCredential,
			want:      "snmp",
		},
		{
			name:      "amqp credential",
			candidate: SecurityCandidate{Service: "amqp", Port: 5672},
			kind:      ProbeKindCredential,
			want:      "amqp",
		},
		{
			name:      "vnc credential",
			candidate: SecurityCandidate{Service: "vnc", Port: 5900},
			kind:      ProbeKindCredential,
			want:      "vnc",
		},
		{
			name:      "smb credential",
			candidate: SecurityCandidate{Service: "smb", Port: 445},
			kind:      ProbeKindCredential,
			want:      "smb",
		},
		{
			name:      "redis unauthorized",
			candidate: SecurityCandidate{Service: "redis", Port: 6379},
			kind:      ProbeKindUnauthorized,
			want:      "redis-unauthorized",
		},
		{
			name:      "mongodb unauthorized",
			candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
			kind:      ProbeKindUnauthorized,
			want:      "mongodb-unauthorized",
		},
		{
			name:      "mongodb credential",
			candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
			kind:      ProbeKindCredential,
			want:      "mongodb",
		},
		{
			name:      "memcached unauthorized",
			candidate: SecurityCandidate{Service: "memcached", Port: 11211},
			kind:      ProbeKindUnauthorized,
			want:      "memcached-unauthorized",
		},
		{
			name:      "zookeeper unauthorized",
			candidate: SecurityCandidate{Service: "zookeeper", Port: 2181},
			kind:      ProbeKindUnauthorized,
			want:      "zookeeper-unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, ok := r.Lookup(tt.candidate, tt.kind)
			if !ok {
				t.Fatalf("expected built-in prober for %+v", tt.candidate)
			}
			if got := prober.Name(); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDefaultRegistryContainsBuiltinCredentialContract(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		name      string
		candidate SecurityCandidate
		kind      ProbeKind
		wantOK    bool
		wantName  string
	}{
		{name: "ftp credential", candidate: SecurityCandidate{Service: "ftp", Port: 21}, kind: ProbeKindCredential, wantOK: true, wantName: "ftp"},
		{name: "ssh credential", candidate: SecurityCandidate{Service: "ssh", Port: 22}, kind: ProbeKindCredential, wantOK: true, wantName: "ssh"},
		{name: "telnet credential", candidate: SecurityCandidate{Service: "telnet", Port: 23}, kind: ProbeKindCredential, wantOK: true, wantName: "telnet"},
		{name: "mysql credential", candidate: SecurityCandidate{Service: "mysql", Port: 3306}, kind: ProbeKindCredential, wantOK: true, wantName: "mysql"},
		{name: "postgresql credential", candidate: SecurityCandidate{Service: "postgresql", Port: 5432}, kind: ProbeKindCredential, wantOK: true, wantName: "postgresql"},
		{name: "redis credential", candidate: SecurityCandidate{Service: "redis", Port: 6379}, kind: ProbeKindCredential, wantOK: true, wantName: "redis"},
		{name: "mssql credential", candidate: SecurityCandidate{Service: "mssql", Port: 1433}, kind: ProbeKindCredential, wantOK: true, wantName: "mssql"},
		{name: "smtp credential", candidate: SecurityCandidate{Service: "smtp", Port: 587}, kind: ProbeKindCredential, wantOK: true, wantName: "smtp"},
		{name: "oracle credential", candidate: SecurityCandidate{Service: "oracle", Port: 1521}, kind: ProbeKindCredential, wantOK: true, wantName: "oracle"},
		{name: "snmp credential", candidate: SecurityCandidate{Service: "snmp", Port: 161}, kind: ProbeKindCredential, wantOK: true, wantName: "snmp"},
		{name: "amqp credential", candidate: SecurityCandidate{Service: "amqp", Port: 5672}, kind: ProbeKindCredential, wantOK: true, wantName: "amqp"},
		{name: "rdp credential", candidate: SecurityCandidate{Service: "rdp", Port: 3389}, kind: ProbeKindCredential, wantOK: true, wantName: "rdp"},
		{name: "vnc credential", candidate: SecurityCandidate{Service: "vnc", Port: 5900}, kind: ProbeKindCredential, wantOK: true, wantName: "vnc"},
		{name: "smb credential", candidate: SecurityCandidate{Service: "smb", Port: 445}, kind: ProbeKindCredential, wantOK: true, wantName: "smb"},
		{name: "memcached credential miss", candidate: SecurityCandidate{Service: "memcached", Port: 11211}, kind: ProbeKindCredential, wantOK: false},
		{name: "memcached unauthorized hit", candidate: SecurityCandidate{Service: "memcached", Port: 11211}, kind: ProbeKindUnauthorized, wantOK: true, wantName: "memcached-unauthorized"},
		{name: "mongodb credential hit", candidate: SecurityCandidate{Service: "mongodb", Port: 27017}, kind: ProbeKindCredential, wantOK: true, wantName: "mongodb"},
		{name: "mongodb unauthorized hit", candidate: SecurityCandidate{Service: "mongodb", Port: 27017}, kind: ProbeKindUnauthorized, wantOK: true, wantName: "mongodb-unauthorized"},
		{name: "zookeeper credential miss", candidate: SecurityCandidate{Service: "zookeeper", Port: 2181}, kind: ProbeKindCredential, wantOK: false},
		{name: "zookeeper unauthorized hit", candidate: SecurityCandidate{Service: "zookeeper", Port: 2181}, kind: ProbeKindUnauthorized, wantOK: true, wantName: "zookeeper-unauthorized"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, ok := r.Lookup(tt.candidate, tt.kind)
			if ok != tt.wantOK {
				t.Fatalf("expected lookup result %t for %+v/%s, got %t", tt.wantOK, tt.candidate, tt.kind, ok)
			}
			if !tt.wantOK {
				return
			}
			if got := prober.Name(); got != tt.wantName {
				t.Fatalf("expected default registry to resolve %q, got %q", tt.wantName, got)
			}
		})
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
			name:      "memcached unauthorized",
			candidate: SecurityCandidate{Service: "memcached", Port: 11211},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDefault, okDefault := defaultRegistry.Lookup(tt.candidate, tt.kind)
			gotRegistered, okRegistered := registeredRegistry.Lookup(tt.candidate, tt.kind)
			if okDefault != okRegistered {
				t.Fatalf("expected lookup parity for %+v/%s, got default=%t registered=%t", tt.candidate, tt.kind, okDefault, okRegistered)
			}
			if !okDefault {
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
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "redis", Port: 6379}); !ok {
		t.Fatal("expected redis atomic unauthorized plugin")
	}
}
