package postgresql_test

import (
	"context"
	"testing"
	"time"

	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestPostgreSQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := postgresqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
		{Username: "gomap", Password: "gomap-pass"},
	})

	if !result.Success {
		t.Fatalf("expected postgresql success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected postgresql success evidence, got %+v", result)
	}
}

func TestPostgreSQLProberReturnsErrorOnFailure(t *testing.T) {
	container := testutil.StartPostgreSQL(t, testutil.PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := postgresqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected postgresql failure, got %+v", result)
	}
	if result.Error == "" {
		t.Fatalf("expected postgresql failure error, got %+v", result)
	}
}
