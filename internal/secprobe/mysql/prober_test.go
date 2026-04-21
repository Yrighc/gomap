package mysql_test

import (
	"context"
	"testing"
	"time"

	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestMySQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartMySQL(t, testutil.MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := mysqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mysql",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
		{Username: "gomap", Password: "gomap-pass"},
	})

	if !result.Success {
		t.Fatalf("expected mysql success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected mysql success evidence, got %+v", result)
	}
}

func TestMySQLProberReturnsErrorOnFailure(t *testing.T) {
	container := testutil.StartMySQL(t, testutil.MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	prober := mysqlprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mysql",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "gomap", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected mysql failure, got %+v", result)
	}
	if result.Error == "" {
		t.Fatalf("expected mysql failure error, got %+v", result)
	}
}
