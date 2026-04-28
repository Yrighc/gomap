package secprobe

import "testing"

func supportsKind(spec ProtocolSpec, kind ProbeKind) bool {
	for _, declared := range spec.ProbeKinds {
		if declared == kind {
			return true
		}
	}
	return false
}

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

	for _, spec := range builtinProtocolSpecs {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			candidate := SecurityCandidate{Service: spec.Name, Port: spec.Ports[0]}
			prober, ok := r.Lookup(candidate, ProbeKindCredential)
			if supportsKind(spec, ProbeKindCredential) {
				if !ok {
					t.Fatalf("expected default registry to contain credential prober for %+v", candidate)
				}
				if got := prober.Name(); got != spec.Name {
					t.Fatalf("expected default registry to resolve %q, got %q", spec.Name, got)
				}
				return
			}

			if ok {
				t.Fatalf("expected default registry to reject credential lookup for %+v, got %q", candidate, prober.Name())
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
			name:      "mongodb credential miss",
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
