package secprobe

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
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

func TestRunUsesBuiltinCredentialsWhenOverridesMissing(t *testing.T) {
	registry := NewRegistry()
	prober := &stubSuccessProber{name: "ssh"}
	registry.Register(prober)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{Timeout: time.Second})

	if result.Meta.Attempted != 1 {
		t.Fatalf("expected attempted candidate, got %+v", result.Meta)
	}
	if prober.credCount == 0 {
		t.Fatal("expected builtin credentials to be loaded")
	}
	if result.Results[0].Username == "" || result.Results[0].Password == "" {
		t.Fatalf("expected result to include credential evidence, got %+v", result.Results[0])
	}
}

func TestApplyDefaultsFillsCredentialProbeOptions(t *testing.T) {
	opts := CredentialProbeOptions{}
	applyDefaults(&opts)

	if opts.Concurrency != 10 {
		t.Fatalf("expected default concurrency 10, got %d", opts.Concurrency)
	}
	if opts.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout 5s, got %s", opts.Timeout)
	}
}

func TestRunRespectsWorkerPoolConcurrency(t *testing.T) {
	registry := NewRegistry()
	prober := &stubCountingProber{name: "ssh", pause: 40 * time.Millisecond}
	registry.Register(prober)

	candidates := make([]SecurityCandidate, 0, 8)
	for i := 0; i < 8; i++ {
		candidates = append(candidates, SecurityCandidate{
			Target:     "demo",
			ResolvedIP: "127.0.0.1",
			Port:       22,
			Service:    "ssh",
		})
	}

	result := RunWithRegistry(context.Background(), registry, candidates, CredentialProbeOptions{
		Concurrency: 2,
		Timeout:     time.Second,
		Credentials: []Credential{{Username: "admin", Password: "admin"}},
	})

	if result.Meta.Attempted != len(candidates) {
		t.Fatalf("expected %d attempts, got %+v", len(candidates), result.Meta)
	}
	if got := atomic.LoadInt32(&prober.maxActive); got > 2 {
		t.Fatalf("expected at most 2 concurrent probes, got %d", got)
	}
	if got := atomic.LoadInt32(&prober.maxActive); got < 2 {
		t.Fatalf("expected worker pool to use more than one worker, got %d", got)
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

type stubSuccessProber struct {
	name      string
	credCount int
}

func (s *stubSuccessProber) Name() string { return s.name }

func (s *stubSuccessProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s *stubSuccessProber) Probe(_ context.Context, candidate SecurityCandidate, _ CredentialProbeOptions, creds []Credential) SecurityResult {
	s.credCount = len(creds)
	result := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}

type stubCountingProber struct {
	name      string
	pause     time.Duration
	active    int32
	maxActive int32
}

func (s *stubCountingProber) Name() string { return s.name }

func (s *stubCountingProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s *stubCountingProber) Probe(_ context.Context, candidate SecurityCandidate, _ CredentialProbeOptions, creds []Credential) SecurityResult {
	current := atomic.AddInt32(&s.active, 1)
	for {
		maxSeen := atomic.LoadInt32(&s.maxActive)
		if current <= maxSeen {
			break
		}
		if atomic.CompareAndSwapInt32(&s.maxActive, maxSeen, current) {
			break
		}
	}
	time.Sleep(s.pause)
	atomic.AddInt32(&s.active, -1)

	result := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}
