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

func TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 161, Open: true, Service: "snmp"},
			{Port: 445, Open: true, Service: "cifs"},
			{Port: 587, Open: true, Service: "smtp"},
			{Port: 1433, Open: true, Service: "mssql"},
			{Port: 1521, Open: true, Service: "oracle-tns"},
			{Port: 3389, Open: true, Service: "rdp"},
			{Port: 5672, Open: true, Service: "amqp"},
			{Port: 5900, Open: true, Service: "vnc"},
			{Port: 11211, Open: true, Service: "memcached"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 10 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "snmp" || candidates[2].Service != "smb" || candidates[3].Service != "smtp" || candidates[4].Service != "mssql" || candidates[5].Service != "oracle" || candidates[6].Service != "rdp" || candidates[7].Service != "amqp" || candidates[8].Service != "vnc" || candidates[9].Service != "memcached" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
}

func TestBuildCandidatesDoesNotBroadenOracleBeyondDefaultPort(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 1522, Open: true, Service: "oracle"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 0 {
		t.Fatalf("expected non-1521 oracle service to stay unsupported, got %#v", candidates)
	}
}

func TestBuildCandidatesDoesNotBroadenSNMPBeyondDefaultPort(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 162, Open: true, Service: "snmp"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 0 {
		t.Fatalf("expected non-161 snmp service to stay unsupported, got %#v", candidates)
	}
}

func TestNormalizeServiceNameKeepsOracleBoundToDefaultPort(t *testing.T) {
	if got := NormalizeServiceName("oracle", 1521); got != "oracle" {
		t.Fatalf("expected oracle on 1521, got %q", got)
	}
	if got := NormalizeServiceName("oracle", 1522); got != "" {
		t.Fatalf("expected oracle on 1522 to stay unsupported, got %q", got)
	}
}

func TestNormalizeServiceNameKeepsSNMPBoundToDefaultPort(t *testing.T) {
	if got := NormalizeServiceName("snmp", 161); got != "snmp" {
		t.Fatalf("expected snmp on 161, got %q", got)
	}
	if got := NormalizeServiceName("snmp", 162); got != "" {
		t.Fatalf("expected snmp on 162 to stay unsupported, got %q", got)
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

func TestNormalizeServiceNameSupportsGenericSSLSuffixCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    string
	}{
		{name: "ssh ssl suffix", service: "ssh/ssl", want: "ssh"},
		{name: "mysql ssl suffix", service: "mysql/ssl", want: "mysql"},
		{name: "postgresql ssl suffix", service: "postgresql/ssl", want: "postgresql"},
		{name: "postgres alias ssl suffix", service: "postgres/ssl", want: "postgresql"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeServiceName(tt.service, 0); got != tt.want {
				t.Fatalf("NormalizeServiceName(%q, 0) = %q, want %q", tt.service, got, tt.want)
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
	prober, ok := r.Lookup(SecurityCandidate{Service: "ssh", Port: 22})
	if !ok {
		t.Fatal("expected ssh prober")
	}
	if got := prober.Name(); got != "ssh" {
		t.Fatalf("expected public prober name ssh, got %q", got)
	}
}

func TestBuildCandidatesUsesRegistryLookup(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	r := NewRegistry()
	r.Register(stubProber{name: "ssh"})

	prober, ok := r.Lookup(candidates[0], ProbeKindCredential)
	if !ok {
		t.Fatal("expected lookup to return public prober")
	}
	if got := prober.Name(); got != "ssh" {
		t.Fatalf("expected public prober name ssh, got %q", got)
	}
}

func TestBuildCandidatesWithRegistryIncludesCatalogProtocolWhenProberRegistered(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 445, Open: true, Service: "cifs"},
		},
	}

	r := NewRegistry()
	r.Register(stubProber{name: "smb"})

	candidates := buildCandidatesWithRegistry(res, CredentialProbeOptions{}, r)
	if len(candidates) != 1 {
		t.Fatalf("expected smb candidate once registry supports it, got %#v", candidates)
	}
	if candidates[0].Service != "smb" {
		t.Fatalf("expected canonical smb candidate, got %#v", candidates[0])
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
