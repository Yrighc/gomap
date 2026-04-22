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

func TestNormalizeServiceNameSupportsWeakAuthAliases(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    string
	}{
		{name: "postgres alias", service: "postgres", want: "postgresql"},
		{name: "pgsql alias", service: "pgsql", want: "postgresql"},
		{name: "mongo alias", service: "mongo", want: "mongodb"},
		{name: "redis tls suffix", service: "redis/tls", want: "redis"},
		{name: "redis ssl suffix", service: "redis/ssl", want: "redis"},
		{name: "mongodb port fallback", port: 27017, want: "mongodb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeServiceName(tt.service, tt.port); got != tt.want {
				t.Fatalf("NormalizeServiceName(%q, %d) = %q, want %q", tt.service, tt.port, got, tt.want)
			}
		})
	}
}

func TestNormalizeServiceNameDoesNotBroadenUnknownTLSAliases(t *testing.T) {
	if got := NormalizeServiceName("ssh/tls", 0); got != "" {
		t.Fatalf("expected ssh/tls without known port to stay unsupported, got %q", got)
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

func (s stubProber) Kind() ProbeKind { return ProbeKindCredential }

func (s stubProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s stubProber) Probe(_ context.Context, _ SecurityCandidate, _ CredentialProbeOptions, _ []Credential) SecurityResult {
	return SecurityResult{Service: s.name}
}
