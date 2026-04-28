package testutil

import (
	"testing"

	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMySQLContainerRequestWaitsForFinalReadyLog(t *testing.T) {
	req := mysqlContainerRequest(MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	assertFinalReadyLogOccurrence(t, req.WaitingFor, "ready for connections")
}

func TestPostgreSQLContainerRequestWaitsForFinalReadyLog(t *testing.T) {
	req := postgreSQLContainerRequest(PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	assertFinalReadyLogOccurrence(t, req.WaitingFor, "database system is ready to accept connections")
}

func assertFinalReadyLogOccurrence(t *testing.T, strategy wait.Strategy, logLine string) {
	t.Helper()

	multi, ok := strategy.(*wait.MultiStrategy)
	if !ok {
		t.Fatalf("expected MultiStrategy, got %T", strategy)
	}

	for _, item := range multi.Strategies {
		logStrategy, ok := item.(*wait.LogStrategy)
		if !ok || logStrategy.Log != logLine {
			continue
		}
		if logStrategy.Occurrence != 2 {
			t.Fatalf("expected log %q to wait for 2 occurrences, got %d", logLine, logStrategy.Occurrence)
		}
		return
	}

	t.Fatalf("expected log strategy for %q", logLine)
}
