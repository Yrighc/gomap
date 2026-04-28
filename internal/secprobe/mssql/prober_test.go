package mssql

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeMSSQLDB struct {
	pingErr  error
	queryErr error
	version  string
	closed   bool
}

func (db *fakeMSSQLDB) PingContext(context.Context) error {
	return db.pingErr
}

func (db *fakeMSSQLDB) QueryRowContext(context.Context, string, ...any) rowScanner {
	return fakeMSSQLRow{version: db.version, err: db.queryErr}
}

func (db *fakeMSSQLDB) Close() error {
	db.closed = true
	return nil
}

type fakeMSSQLRow struct {
	version string
	err     error
}

func (row fakeMSSQLRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) == 1 {
		if value, ok := dest[0].(*string); ok {
			*value = row.version
		}
	}
	return nil
}

func TestMSSQLProberFindsValidCredential(t *testing.T) {
	originalOpen := openMSSQL
	t.Cleanup(func() {
		openMSSQL = originalOpen
	})

	openMSSQL = func(context.Context, string) (mssqlDB, error) {
		return &fakeMSSQLDB{version: "Microsoft SQL Server 2022"}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1433,
		Service:    "mssql",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "sa", Password: "s3cret"},
	})

	if !result.Success {
		t.Fatalf("expected mssql success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FailureReason != "" {
		t.Fatalf("expected empty failure reason on success, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
}

func TestMSSQLProberTriesTLSDSNBeforeFallbackDisable(t *testing.T) {
	originalOpen := openMSSQL
	t.Cleanup(func() {
		openMSSQL = originalOpen
	})

	var attempts []string
	openMSSQL = func(_ context.Context, dsn string) (mssqlDB, error) {
		attempts = append(attempts, dsn)
		if len(attempts) == 1 {
			return &fakeMSSQLDB{pingErr: errors.New("tls handshake failed")}, nil
		}
		return &fakeMSSQLDB{version: "Microsoft SQL Server 2019"}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1433,
		Service:    "mssql",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "sa", Password: "s3cret"},
	})

	if !result.Success {
		t.Fatalf("expected mssql success after fallback, got %+v", result)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected two DSN attempts, got %d (%v)", len(attempts), attempts)
	}
	assertDSNEncryptMode(t, attempts[0], "true")
	assertDSNEncryptMode(t, attempts[1], "disable")
	if !dsnHasTrustServerCertificate(attempts[0]) {
		t.Fatalf("expected TLS-first DSN to trust server certificate, got %q", attempts[0])
	}
	if dsnHasTrustServerCertificate(attempts[1]) {
		t.Fatalf("expected fallback disable DSN not to set trust server certificate, got %q", attempts[1])
	}
}

func TestBuildDSNAttemptsPrefersTLSFirst(t *testing.T) {
	attempts := buildDSNAttempts(core.SecurityCandidate{
		ResolvedIP: "10.0.0.8",
		Port:       1433,
	}, core.Credential{
		Username: "sa",
		Password: "p@ss",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	})

	if len(attempts) != 2 {
		t.Fatalf("expected two DSN attempts, got %d", len(attempts))
	}
	if got := extractDSNQueryValue(t, attempts[0], "encrypt"); got != "true" {
		t.Fatalf("expected first DSN encrypt=true, got %q", got)
	}
	if got := extractDSNQueryValue(t, attempts[1], "encrypt"); got != "disable" {
		t.Fatalf("expected second DSN encrypt=disable, got %q", got)
	}
	if got := extractDSNQueryValue(t, attempts[0], "TrustServerCertificate"); got != "true" {
		t.Fatalf("expected first DSN TrustServerCertificate=true, got %q", got)
	}
	if got := extractDSNQueryValue(t, attempts[1], "TrustServerCertificate"); got != "" {
		t.Fatalf("expected fallback DSN not to set TrustServerCertificate, got %q", got)
	}
}

func TestMSSQLProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openMSSQL
	t.Cleanup(func() {
		openMSSQL = originalOpen
	})

	openMSSQL = func(context.Context, string) (mssqlDB, error) {
		return &fakeMSSQLDB{
			pingErr: errors.New("Login failed for user 'sa'"),
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1433,
		Service:    "mssql",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "sa", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected mssql failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func assertDSNEncryptMode(t *testing.T, dsn string, want string) {
	t.Helper()
	if got := extractDSNQueryValue(t, dsn, "encrypt"); got != want {
		t.Fatalf("expected DSN encrypt=%q, got %q in %q", want, got, dsn)
	}
}

func dsnHasTrustServerCertificate(dsn string) bool {
	queryValues := parseDSNQuery(dsn)
	return slices.Contains(queryValues["TrustServerCertificate"], "true")
}

func extractDSNQueryValue(t *testing.T, dsn string, key string) string {
	t.Helper()
	values := parseDSNQuery(dsn)
	return values.Get(key)
}

func parseDSNQuery(dsn string) url.Values {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return url.Values{}
	}
	return parsed.Query()
}
