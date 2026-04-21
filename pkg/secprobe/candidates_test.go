package secprobe

import (
	"context"
	"testing"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

func TestBuildCandidatesFiltersSupportedOpenPorts(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh?"},
			{Port: 80, Open: true, Service: "http"},
			{Port: 6379, Open: true, Service: "redis/ssl"},
		},
	}
	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 2 {
		t.Fatalf("expected 2 secprobe candidates, got %d", len(candidates))
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "redis" {
		t.Fatalf("unexpected services: %#v", candidates)
	}
}

func TestNormalizeServiceNameUsesKnownPortFallback(t *testing.T) {
	got := NormalizeServiceName("", 5432)
	if got != "postgresql" {
		t.Fatalf("expected postgresql, got %q", got)
	}
}

func TestRegisterAndLookupProber(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProber{name: "ssh"})
	if _, ok := r.Lookup(SecurityCandidate{Service: "ssh", Port: 22}); !ok {
		t.Fatal("expected ssh prober")
	}
}

type stubProber struct{ name string }

func (s stubProber) Name() string { return s.name }

func (s stubProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s stubProber) Probe(_ context.Context, _ SecurityCandidate, _ CredentialProbeOptions, _ []Credential) SecurityResult {
	return SecurityResult{Service: s.name}
}
