package oracle

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
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

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     1521,
		Protocol: "oracle",
	}, strategy.Credential{Username: "system", Password: "oracle"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("ORA-01017: invalid username/password; logon denied")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     1521,
		Protocol: "oracle",
	}, strategy.Credential{Username: "system", Password: "wrong"})

	if out.Result.Success {
		t.Fatalf("expected auth failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication code, got %+v", out.Result)
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

func TestOracleProberKeepsServiceFallbackWithinSharedTimeout(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	attempts := 0
	openOracle = func(context.Context, string) (oracleDB, error) {
		attempts++
		if attempts < 3 {
			return blockingOracleDB{}, nil
		}
		return &fakeOracleDB{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{
		Timeout:       120 * time.Millisecond,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if !result.Success {
		t.Fatalf("expected oracle success after timeout-bounded fallback, got %+v", result)
	}
	if attempts != 3 {
		t.Fatalf("expected three oracle attempts within shared timeout, got %d", attempts)
	}
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

func TestOracleProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{pingErr: errors.New("ORA-12514: service not known")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Success {
		t.Fatalf("expected oracle connection failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestOracleProberClassifiesInsufficientConfirmation(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{pingErr: errors.New("oracle returned unexpected state")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Success {
		t.Fatalf("expected oracle insufficient-confirmation failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient-confirmation failure reason, got %+v", result)
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

func TestOracleProberMatchRequiresDefaultPort(t *testing.T) {
	if !New().Match(core.SecurityCandidate{Service: "oracle", Port: 1521}) {
		t.Fatal("expected oracle prober to match default port 1521")
	}
	if New().Match(core.SecurityCandidate{Service: "oracle", Port: 1522}) {
		t.Fatal("expected oracle prober to reject non-1521 ports")
	}
}

func TestBuildOracleDSNAttemptsUsesIPv6SafeHostPort(t *testing.T) {
	attempts := buildOracleDSNAttempts(core.SecurityCandidate{
		ResolvedIP: "2001:db8::1",
		Port:       1521,
	}, core.Credential{
		Username: "system",
		Password: "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second})

	if len(attempts) == 0 {
		t.Fatal("expected oracle dsn attempts")
	}

	parsed, err := url.Parse(attempts[0])
	if err != nil {
		t.Fatalf("parse oracle dsn: %v", err)
	}
	if parsed.Host != "[2001:db8::1]:1521" {
		t.Fatalf("expected IPv6-safe host, got %q", parsed.Host)
	}
}

type blockingOracleDB struct{}

func (blockingOracleDB) PingContext(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (blockingOracleDB) Close() error { return nil }

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
