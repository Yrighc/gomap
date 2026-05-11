package testutil

import (
	"testing"

	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegrationEnabledDefaultsToFalse(t *testing.T) {
	t.Setenv("GOMAP_INTEGRATION", "")

	if integrationEnabled() {
		t.Fatal("expected integration tests to stay disabled by default")
	}
}

func TestIntegrationEnabledAcceptsExplicitOptIn(t *testing.T) {
	tests := []string{"1", "true", "TRUE", "yes", "on"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GOMAP_INTEGRATION", value)

			if !integrationEnabled() {
				t.Fatalf("expected %q to enable integration tests", value)
			}
		})
	}
}

func TestMySQLContainerRequestWaitsForFinalReadyLog(t *testing.T) {
	req := mysqlContainerRequest(MySQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	assertLogStrategyPresent(t, req.WaitingFor, "port: 3306")
}

func TestPostgreSQLContainerRequestWaitsForFinalReadyLog(t *testing.T) {
	req := postgreSQLContainerRequest(PostgreSQLConfig{
		Database: "gomap",
		Username: "gomap",
		Password: "gomap-pass",
	})

	assertFinalReadyLogOccurrence(t, req.WaitingFor, "database system is ready to accept connections")
}

func TestNormalizeContainerHost(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "localhost becomes ipv4 loopback", in: "localhost", want: "127.0.0.1"},
		{name: "ipv6 loopback becomes ipv4 loopback", in: "::1", want: "127.0.0.1"},
		{name: "ipv4 loopback stays stable", in: "127.0.0.1", want: "127.0.0.1"},
		{name: "docker gateway stays unchanged", in: "192.168.65.2", want: "192.168.65.2"},
		{name: "remote hostname stays unchanged", in: "docker.internal", want: "docker.internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeContainerHost(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeContainerHost(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func assertLogStrategyPresent(t *testing.T, strategy wait.Strategy, logLine string) {
	t.Helper()

	multi, ok := strategy.(*wait.MultiStrategy)
	if !ok {
		t.Fatalf("expected MultiStrategy, got %T", strategy)
	}

	for _, item := range multi.Strategies {
		logStrategy, ok := item.(*wait.LogStrategy)
		if ok && logStrategy.Log == logLine {
			return
		}
	}

	t.Fatalf("expected log strategy for %q", logLine)
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
