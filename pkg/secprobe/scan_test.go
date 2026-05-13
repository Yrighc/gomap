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
		if opts.Timeout != time.Second {
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
		if len(opts.Credentials) != 0 {
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
			Results: []SecurityResult{
				{
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
				},
				{
					Target:      "demo.local",
					ResolvedIP:  "192.0.2.15",
					Port:        6379,
					Service:     "redis",
					ProbeKind:   ProbeKindCredential,
					FindingType: FindingTypeCredentialValid,
					Success:     false,
					Error:       "authentication failed",
				},
			},
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

	if got.Error != "" || got.Meta.Candidates != 2 || len(got.Results) != 2 {
		t.Fatalf("unexpected scan result: %+v", got)
	}
}

func TestScanFallsBackToTargetWhenResolvedIPMissing(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, _ CredentialProbeOptions) RunResult {
		if len(candidates) != 1 {
			t.Fatalf("expected 1 candidate, got %d", len(candidates))
		}
		if candidates[0].Target != "demo.local" {
			t.Fatalf("unexpected target: %+v", candidates[0])
		}
		if candidates[0].ResolvedIP != "demo.local" {
			t.Fatalf("expected target fallback for empty resolved ip, got %+v", candidates[0])
		}
		return RunResult{}
	})
	defer restore()

	Scan(context.Background(), ScanRequest{
		Target:   "demo.local",
		Services: []ScanService{{Port: 22, Service: "ssh"}},
	})
}

func TestScanRejectsOracleOutsideDefaultPort(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, _ CredentialProbeOptions) RunResult {
		if len(candidates) != 0 {
			t.Fatalf("expected no supported candidates, got %+v", candidates)
		}
		return RunResult{}
	})
	defer restore()

	got := Scan(context.Background(), ScanRequest{
		Target:  "demo.local",
		Timeout: time.Second,
		Services: []ScanService{
			{Port: 1522, Service: "oracle"},
		},
	})

	if got.Error != "" {
		t.Fatalf("expected structured result instead of top-level error, got %+v", got)
	}
	if got.Meta.Candidates != 1 || got.Meta.Skipped != 1 {
		t.Fatalf("expected skipped unsupported service accounting, got %+v", got.Meta)
	}
	if len(got.Results) != 1 {
		t.Fatalf("expected one structured result, got %+v", got)
	}
	if got.Results[0].Error != "unsupported service \"oracle\" on port 1522" {
		t.Fatalf("expected oracle non-default port finding, got %+v", got.Results[0])
	}
}

func TestScanRejectsSNMPOutsideDefaultPort(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, _ CredentialProbeOptions) RunResult {
		if len(candidates) != 0 {
			t.Fatalf("expected no supported candidates, got %+v", candidates)
		}
		return RunResult{}
	})
	defer restore()

	got := Scan(context.Background(), ScanRequest{
		Target:  "demo.local",
		Timeout: time.Second,
		Services: []ScanService{
			{Port: 162, Service: "snmp"},
		},
	})

	if got.Error != "" {
		t.Fatalf("expected structured result instead of top-level error, got %+v", got)
	}
	if got.Meta.Candidates != 1 || got.Meta.Skipped != 1 {
		t.Fatalf("expected skipped unsupported service accounting, got %+v", got.Meta)
	}
	if len(got.Results) != 1 {
		t.Fatalf("expected one structured result, got %+v", got)
	}
	if got.Results[0].Error != "unsupported service \"snmp\" on port 162" {
		t.Fatalf("expected snmp non-default port finding, got %+v", got.Results[0])
	}
}

func TestScanKeepsSupportedAndUnsupportedServicesInOneStructuredResult(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, _ CredentialProbeOptions) RunResult {
		if len(candidates) != 1 {
			t.Fatalf("expected only supported candidates to execute, got %+v", candidates)
		}
		if candidates[0].Service != "ssh" || candidates[0].Port != 22 {
			t.Fatalf("unexpected supported candidate: %+v", candidates[0])
		}
		return RunResult{
			Meta: SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
			Results: []SecurityResult{{
				Target:      "demo.local",
				ResolvedIP:  "192.0.2.30",
				Port:        22,
				Service:     "ssh",
				ProbeKind:   ProbeKindCredential,
				FindingType: FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "toor",
			}},
		}
	})
	defer restore()

	got := Scan(context.Background(), ScanRequest{
		Target:     "demo.local",
		ResolvedIP: "192.0.2.30",
		Services: []ScanService{
			{Port: 22, Service: "ssh"},
			{Port: 9999, Service: "mystery"},
		},
	})

	if got.Error != "" {
		t.Fatalf("expected mixed-service scan to stay successful, got %+v", got)
	}
	if got.Meta.Candidates != 2 || got.Meta.Attempted != 1 || got.Meta.Succeeded != 1 || got.Meta.Skipped != 1 {
		t.Fatalf("unexpected mixed-service meta: %+v", got.Meta)
	}
	if len(got.Results) != 2 {
		t.Fatalf("expected two structured results, got %+v", got)
	}
	if got.Results[0].Service != "ssh" || !got.Results[0].Success {
		t.Fatalf("expected supported service result first, got %+v", got.Results[0])
	}
	if got.Results[1].Service != "mystery" || got.Results[1].Error != "unsupported service \"mystery\" on port 9999" {
		t.Fatalf("expected unsupported service result to be preserved, got %+v", got.Results[1])
	}
}
