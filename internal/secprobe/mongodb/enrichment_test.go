package mongodb_test

import (
	"context"
	"testing"
	"time"

	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestMongoEnrichUsesTargetWhenResolvedIPMissing(t *testing.T) {
	container := testutil.StartMongoDBNoAuth(t)

	result := mongodbprobe.Enrich(context.Background(), secprobe.SecurityResult{
		Target:      container.Host,
		Port:        container.Port,
		Service:     "mongodb",
		ProbeKind:   secprobe.ProbeKindUnauthorized,
		FindingType: secprobe.FindingTypeUnauthorizedAccess,
		Success:     true,
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	})

	if !result.Success {
		t.Fatalf("expected enrichment to preserve success, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected enrichment to preserve probe kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected enrichment to preserve finding type, got %+v", result)
	}
	if result.Enrichment == nil || result.Enrichment["databases"] == nil {
		t.Fatalf("expected mongodb enrichment payload, got %+v", result)
	}
}

func TestMongoEnrichRecordsErrorNonFatally(t *testing.T) {
	result := mongodbprobe.Enrich(context.Background(), secprobe.SecurityResult{
		Target:      "127.0.0.1",
		Port:        1,
		Service:     "mongodb",
		ProbeKind:   secprobe.ProbeKindUnauthorized,
		FindingType: secprobe.FindingTypeUnauthorizedAccess,
		Success:     true,
	}, secprobe.CredentialProbeOptions{
		Timeout: 100 * time.Millisecond,
	})

	if !result.Success {
		t.Fatalf("expected enrichment failure to stay non-fatal, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected enrichment failure to preserve probe kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected enrichment failure to preserve finding type, got %+v", result)
	}
	if result.Enrichment == nil || result.Enrichment["error"] == nil {
		t.Fatalf("expected mongodb enrichment error payload, got %+v", result)
	}
}
