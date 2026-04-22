package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
)

func TestRedisEnrichUsesTargetWhenResolvedIPMissing(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	result := redisprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      container.Host,
		Port:        container.Port,
		Service:     "redis",
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
		Success:     true,
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	})

	if !result.Success {
		t.Fatalf("expected enrichment to preserve success, got %+v", result)
	}
	if result.ProbeKind != core.ProbeKindUnauthorized {
		t.Fatalf("expected enrichment to preserve probe kind, got %+v", result)
	}
	if result.FindingType != core.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected enrichment to preserve finding type, got %+v", result)
	}
	if result.Enrichment == nil || result.Enrichment["info_excerpt"] == nil {
		t.Fatalf("expected redis enrichment excerpt, got %+v", result)
	}
}

func TestRedisEnrichRecordsErrorNonFatally(t *testing.T) {
	result := redisprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      "127.0.0.1",
		Port:        1,
		Service:     "redis",
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
		Success:     true,
	}, core.CredentialProbeOptions{
		Timeout: 100 * time.Millisecond,
	})

	if !result.Success {
		t.Fatalf("expected enrichment failure to stay non-fatal, got %+v", result)
	}
	if result.ProbeKind != core.ProbeKindUnauthorized {
		t.Fatalf("expected enrichment failure to preserve probe kind, got %+v", result)
	}
	if result.FindingType != core.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected enrichment failure to preserve finding type, got %+v", result)
	}
	if result.Enrichment == nil || result.Enrichment["error"] == nil {
		t.Fatalf("expected redis enrichment error payload, got %+v", result)
	}
}
