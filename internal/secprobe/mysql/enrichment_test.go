package mysql_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
)

func TestMySQLEnrichReturnsVersionPayload(t *testing.T) {
	container := testutil.StartMySQL(t, testutil.MySQLConfig{
		Database: "app",
		Username: "app",
		Password: "secret",
	})

	result := mysqlprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      container.Host,
		Port:        container.Port,
		Service:     "mysql",
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
		Success:     true,
		Username:    "app",
		Password:    "secret",
	}, core.CredentialProbeOptions{
		Timeout: 10 * time.Second,
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
	if !ok {
		t.Fatalf("expected mysql enrichment payload string, got %+v", result.Enrichment)
	}
	if !strings.HasPrefix(payload, "SELECT @@version;\n\n") {
		t.Fatalf("expected payload to include query prefix, got %q", payload)
	}
	if strings.TrimPrefix(payload, "SELECT @@version;\n\n") == "" {
		t.Fatalf("expected payload to include query response, got %q", payload)
	}
	if _, exists := result.Enrichment["error"]; exists {
		t.Fatalf("expected no mysql enrichment error on success, got %+v", result.Enrichment)
	}
}

func TestMySQLEnrichRecordsErrorNonFatally(t *testing.T) {
	result := mysqlprobe.Enrich(context.Background(), core.SecurityResult{
		Target:      "127.0.0.1",
		Port:        1,
		Service:     "mysql",
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
		Success:     true,
		Username:    "demo",
		Password:    "wrong",
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
		t.Fatalf("expected mysql enrichment error payload, got %+v", result)
	}
	if _, exists := result.Enrichment["payload"]; exists {
		t.Fatalf("expected no mysql payload on error, got %+v", result.Enrichment)
	}
}
