package oracle

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeOracleDB struct {
	pingErr error
	closed  bool
}

func (db *fakeOracleDB) PingContext(context.Context) error { return db.pingErr }

func (db *fakeOracleDB) Close() error {
	db.closed = true
	return nil
}

func TestOracleProberFindsValidCredential(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if !result.Success {
		t.Fatalf("expected oracle success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
}

func TestOracleProberTriesKnownServiceNamesInOrder(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	var attempts []string
	openOracle = func(_ context.Context, dsn string) (oracleDB, error) {
		attempts = append(attempts, dsn)
		if len(attempts) < 3 {
			return &fakeOracleDB{pingErr: errors.New("ORA-12514: service not known")}, nil
		}
		return &fakeOracleDB{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if !result.Success {
		t.Fatalf("expected oracle success after service-name fallback, got %+v", result)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected three service-name attempts, got %d (%v)", len(attempts), attempts)
	}
	assertOracleServiceNames(t, attempts, []string{"XEPDB1", "ORCLPDB1", "XE"})
}

func TestOracleProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{pingErr: errors.New("ORA-01017: invalid username/password; logon denied")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected oracle failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestOracleProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestOracleProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}

func assertOracleServiceNames(t *testing.T, attempts []string, want []string) {
	t.Helper()

	got := make([]string, 0, len(attempts))
	for _, dsn := range attempts {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse dsn %q: %v", dsn, err)
		}
		got = append(got, parsed.Path[1:])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("service-name attempts = %v, want %v", got, want)
	}
}
