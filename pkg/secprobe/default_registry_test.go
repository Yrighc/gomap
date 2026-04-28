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
			name:      "vnc credential",
			candidate: SecurityCandidate{Service: "vnc", Port: 5900},
			kind:      ProbeKindCredential,
			want:      "vnc",
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

func TestDefaultRegistryDelegatesToRegisterDefaultProbers(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.Lookup(SecurityCandidate{Service: "ssh", Port: 22}, ProbeKindCredential); !ok {
		t.Fatal("expected default registry to contain ssh credential prober")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "mssql", Port: 1433}, ProbeKindCredential); !ok {
		t.Fatal("expected default registry to contain mssql credential prober")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "rdp", Port: 3389}, ProbeKindCredential); !ok {
		t.Fatal("expected default registry to contain rdp credential prober")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "redis", Port: 6379}, ProbeKindUnauthorized); !ok {
		t.Fatal("expected default registry to contain redis unauthorized prober")
	}
}
