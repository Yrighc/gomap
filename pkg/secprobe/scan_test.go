package secprobe

import (
	"context"
	"testing"
	"time"
)

func TestScanRejectsEmptyServices(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Target:  "192.0.2.10",
		Timeout: time.Second,
	})

	if got.Error != "services is required" {
		t.Fatalf("expected exact services validation error, got %+v", got)
	}
	if got.Target != "192.0.2.10" {
		t.Fatalf("expected target echoed back, got %+v", got)
	}
	if got.Meta.Candidates != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty result set on validation failure, got %+v", got)
	}
}

func TestScanRejectsEmptyTarget(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Services: []ScanService{{Service: "ssh"}},
		Timeout:  time.Second,
	})

	if got.Error != "target is required" {
		t.Fatalf("expected exact target validation error, got %+v", got)
	}
	if got.Target != "" {
		t.Fatalf("expected empty target on validation failure, got %+v", got)
	}
	if got.Meta.Candidates != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty result set on validation failure, got %+v", got)
	}
}

func TestScanAppliesDefaultTimeoutAndConcurrency(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, _ []SecurityCandidate, opts CredentialProbeOptions) RunResult {
		if opts.Timeout != 5*time.Second {
			t.Fatalf("expected default timeout, got %+v", opts)
		}
		if opts.Concurrency != 10 {
			t.Fatalf("expected default concurrency, got %+v", opts)
		}
		return RunResult{}
	})
	defer restore()

	Scan(context.Background(), ScanRequest{
		Target:   "demo.local",
		Services: []ScanService{{Port: 22, Service: "ssh"}},
	})
}

func TestScanMapsServicesIntoCandidatesAndBuiltinOptions(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
		if len(candidates) != 2 {
			t.Fatalf("expected 2 candidates, got %d", len(candidates))
		}
		if candidates[0].Target != "demo.local" || candidates[0].ResolvedIP != "192.0.2.15" {
			t.Fatalf("unexpected first candidate: %+v", candidates[0])
		}
		if candidates[0].Service != "ssh" || candidates[1].Service != "redis" {
			t.Fatalf("expected normalized services, got %+v", candidates)
		}
		if candidates[0].Version != "OpenSSH_9.8" || candidates[1].Banner != "redis" {
			t.Fatalf("expected version/banner to flow into candidates, got %+v", candidates)
		}
		if opts.DictDir != "" || len(opts.Credentials) != 0 {
			t.Fatalf("expected builtin dictionary mode, got %+v", opts)
		}
		if !opts.StopOnSuccess || opts.EnableUnauthorized || opts.EnableEnrichment {
			t.Fatalf("unexpected options: %+v", opts)
		}
		if opts.Timeout != 3*time.Second || opts.Concurrency != 4 {
			t.Fatalf("unexpected timeout/concurrency: %+v", opts)
		}
		return RunResult{
			Meta: SecurityMeta{Candidates: 2, Attempted: 2, Succeeded: 1, Failed: 1},
			Results: []SecurityResult{{
				Target:      "demo.local",
				ResolvedIP:  "192.0.2.15",
				Port:        22,
				Service:     "ssh",
				ProbeKind:   ProbeKindCredential,
				FindingType: FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "root",
				Evidence:    "ssh auth succeeded",
			}},
		}
	})
	defer restore()

	got := Scan(context.Background(), ScanRequest{
		Target:        "demo.local",
		ResolvedIP:    "192.0.2.15",
		Timeout:       3 * time.Second,
		Concurrency:   4,
		StopOnSuccess: true,
		Services: []ScanService{
			{Port: 22, Service: "ssh?", Version: "OpenSSH_9.8"},
			{Port: 6379, Service: "redis/ssl", Banner: "redis"},
		},
	})

	if got.Error != "" || got.Meta.Candidates != 2 || len(got.Results) != 1 {
		t.Fatalf("unexpected scan result: %+v", got)
	}
}

func TestScanRejectsOracleOutsideDefaultPort(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Target:  "demo.local",
		Timeout: time.Second,
		Services: []ScanService{
			{Port: 1522, Service: "oracle"},
		},
	})

	if got.Error != "unsupported service \"oracle\" on port 1522" {
		t.Fatalf("expected oracle non-default port rejection, got %+v", got)
	}
}

func TestScanRejectsSNMPOutsideDefaultPort(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Target:  "demo.local",
		Timeout: time.Second,
		Services: []ScanService{
			{Port: 162, Service: "snmp"},
		},
	})

	if got.Error != "unsupported service \"snmp\" on port 162" {
		t.Fatalf("expected snmp non-default port rejection, got %+v", got)
	}
}
