package postgresql_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
)

func TestPostgreSQLEnrichUsesTargetWhenResolvedIPMissing(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	result := postgresqlprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      container.Host,
		Port:        container.Port,
		Service:     "postgresql",
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
		Success:     true,
		Username:    "gomap",
		Password:    "gomap-pass",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	})

	if !result.Success {
		t.Fatalf("expected enrichment to preserve success, got %+v", result)
	}
	if result.ProbeKind != core.ProbeKindCredential {
		t.Fatalf("expected enrichment to preserve probe kind, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected enrichment to preserve finding type, got %+v", result)
	}

	payload, ok := result.Enrichment["payload"].(string)
	if result.Enrichment == nil || !ok {
		t.Fatalf("expected postgresql enrichment payload, got %+v", result)
	}
	if !strings.HasPrefix(payload, "SELECT version();\n\n") {
		t.Fatalf("expected payload to start with query, got %q", payload)
	}
	if !strings.Contains(strings.ToLower(payload), "postgresql") {
		t.Fatalf("expected payload to include version response, got %q", payload)
	}
}

func TestPostgreSQLEnrichRecordsErrorNonFatally(t *testing.T) {
	result := postgresqlprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      "127.0.0.1",
		Port:        1,
		Service:     "postgresql",
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
		Success:     true,
		Username:    "gomap",
		Password:    "gomap-pass",
	}, core.CredentialProbeOptions{
		Timeout: 100 * time.Millisecond,
	})

	if !result.Success {
		t.Fatalf("expected enrichment failure to stay non-fatal, got %+v", result)
	}
	if result.ProbeKind != core.ProbeKindCredential {
		t.Fatalf("expected enrichment failure to preserve probe kind, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected enrichment failure to preserve finding type, got %+v", result)
	}
	if result.Enrichment == nil || result.Enrichment["error"] == nil {
		t.Fatalf("expected postgresql enrichment error payload, got %+v", result)
	}
}
