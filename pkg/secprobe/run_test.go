package secprobe

import (
	"context"
	"testing"
)

func TestRunSkipsUnsupportedCandidates(t *testing.T) {
	r := NewRegistry()
	result := RunWithRegistry(context.Background(), r, []SecurityCandidate{{Service: "http", Port: 80}}, CredentialProbeOptions{})
	if result.Meta.Candidates != 1 {
		t.Fatalf("expected one candidate, got %+v", result.Meta)
	}
	if result.Meta.Skipped != 1 {
		t.Fatalf("expected one skipped candidate, got %+v", result.Meta)
	}
}

func TestDefaultRegistryRegistersProtocolProbers(t *testing.T) {
	r := DefaultRegistry()
	for _, candidate := range []SecurityCandidate{
		{Service: "ssh", Port: 22},
		{Service: "ftp", Port: 21},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "redis", Port: 6379},
		{Service: "telnet", Port: 23},
	} {
		if _, ok := r.Lookup(candidate); !ok {
			t.Fatalf("expected prober for service %q", candidate.Service)
		}
	}
}
