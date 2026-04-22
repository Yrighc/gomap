package secprobe

import (
	"context"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestRunWithRegistryAddsRedisEnrichmentWhenEnabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"info_excerpt": "# Server\r\nredis_version:7.4.2"}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	})

	if got.Results[0].Enrichment == nil {
		t.Fatalf("expected enrichment payload, got %+v", got.Results[0])
	}
}

func TestRunWithRegistrySkipsEnrichmentWhenDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
		},
	})

	calls := 0
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		calls++
		result.Enrichment = map[string]any{"info_excerpt": "should not run"}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
	})

	if calls != 0 {
		t.Fatalf("expected enrichment runner to stay idle when disabled, got %d calls", calls)
	}
	if got.Results[0].Enrichment != nil {
		t.Fatalf("expected no enrichment payload when disabled, got %+v", got.Results[0])
	}
}

func TestRunWithRegistrySkipsEnrichmentForFailedResult(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Error:       "dial failed",
		},
	})

	calls := 0
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		calls++
		result.Enrichment = map[string]any{"info_excerpt": "should not run"}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	})

	if calls != 0 {
		t.Fatalf("expected enrichment runner to skip failed result, got %d calls", calls)
	}
	if got.Results[0].Enrichment != nil {
		t.Fatalf("expected failed result to stay unenriched, got %+v", got.Results[0])
	}
}

func TestRunWithRegistryKeepsFindingSemanticsWhenEnrichmentReturnsError(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"error": "enrichment failed"}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	})

	item := got.Results[0]
	if !item.Success {
		t.Fatalf("expected finding success to remain true, got %+v", item)
	}
	if item.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected probe kind to remain unauthorized, got %+v", item)
	}
	if item.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected finding type to remain unauthorized-access, got %+v", item)
	}
	if !reflect.DeepEqual(item.Enrichment, map[string]any{"error": "enrichment failed"}) {
		t.Fatalf("expected non-fatal enrichment error payload, got %+v", item)
	}
}

func TestApplyEnrichmentReturnsCopy(t *testing.T) {
	original := []core.SecurityResult{{
		Service:     "redis",
		ProbeKind:   ProbeKindUnauthorized,
		FindingType: FindingTypeUnauthorizedAccess,
		Success:     true,
	}}

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"info_excerpt": "copied"}
		return result
	})
	defer restore()

	got := applyEnrichment(context.Background(), original, CredentialProbeOptions{
		EnableEnrichment: true,
	})

	if original[0].Enrichment != nil {
		t.Fatalf("expected original slice to remain untouched, got %+v", original[0])
	}
	if !reflect.DeepEqual(got[0].Enrichment, map[string]any{"info_excerpt": "copied"}) {
		t.Fatalf("expected copied slice to contain enrichment, got %+v", got[0])
	}
}

func stubEnrichmentRunner(fn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult) func() {
	old := runEnrichment
	runEnrichment = fn
	return func() { runEnrichment = old }
}
