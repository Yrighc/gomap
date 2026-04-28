package mssql

import (
	"context"
	"errors"
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
