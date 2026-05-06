package mongodb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type fakeMongoCredentialClient struct {
	listDatabaseNames func(context.Context, any) ([]string, error)
	disconnect        func(context.Context) error
}

func (f fakeMongoCredentialClient) ListDatabaseNames(ctx context.Context, filter any) ([]string, error) {
	if f.listDatabaseNames != nil {
		return f.listDatabaseNames(ctx, filter)
	}
	return nil, nil
}

func (f fakeMongoCredentialClient) Disconnect(ctx context.Context) error {
	if f.disconnect != nil {
		return f.disconnect(ctx)
	}
	return nil
}

func TestMongoDBAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) (registrybridge.Attempt, error) {
		if cred.Username != "alice" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return registrybridge.Attempt{
			Legacy: core.SecurityResult{
				Success:      true,
				Stage:        core.StageConfirmed,
				FindingType:  core.FindingTypeCredentialValid,
				Evidence:     "listDatabaseNames succeeded after authentication",
				Username:     cred.Username,
				Password:     cred.Password,
				Capabilities: []core.Capability{core.CapabilityEnumerable},
			},
		}, nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mongo.local",
		IP:       "127.0.0.1",
		Port:     27017,
		Protocol: "mongodb",
	}, strategy.Credential{
		Username: "alice",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
	}
	if out.Result.Evidence != "listDatabaseNames succeeded after authentication" {
		t.Fatalf("expected deterministic evidence, got %+v", out)
	}
	if !out.Legacy.Success || len(out.Legacy.Capabilities) != 1 || out.Legacy.Capabilities[0] != core.CapabilityEnumerable {
		t.Fatalf("expected enumerable capability preserved through legacy payload, got %+v", out)
	}
}

func TestMongoDBAuthenticatorAuthenticateOnceUsesRealPathAndBoundedDisconnect(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openCalled := false
	disconnectCalled := false
	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		openCalled = true
		if candidate.Target != "mongo.local" || candidate.ResolvedIP != "127.0.0.1" || candidate.Port != 27017 || candidate.Service != "mongodb" {
			t.Fatalf("unexpected candidate: %+v", candidate)
		}
		if cred.Username != "alice" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		if timeout <= 0 {
			t.Fatalf("expected positive timeout, got %v", timeout)
		}

		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return []string{"admin"}, nil
			},
			disconnect: func(ctx context.Context) error {
				disconnectCalled = true
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("expected disconnect context to carry a deadline")
				}
				if time.Until(deadline) <= 0 {
					t.Fatalf("expected disconnect deadline in the future, got %v", deadline)
				}
				return nil
			},
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, strategy.Target{
		Host:     "mongo.local",
		IP:       "127.0.0.1",
		Port:     27017,
		Protocol: "mongodb",
	}, strategy.Credential{
		Username: "alice",
		Password: "secret",
	})

	if !openCalled {
		t.Fatal("expected real authenticateOnce path to open a MongoDB client")
	}
	if !disconnectCalled {
		t.Fatal("expected real authenticateOnce path to disconnect the MongoDB client")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
	}
	if out.Result.Evidence != "listDatabaseNames succeeded after authentication" {
		t.Fatalf("expected deterministic evidence, got %+v", out)
	}
	if !out.Legacy.Success || len(out.Legacy.Capabilities) != 1 || out.Legacy.Capabilities[0] != core.CapabilityEnumerable {
		t.Fatalf("expected enumerable capability preserved through legacy payload, got %+v", out)
	}
}

func TestMongoDBAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error) {
		return registrybridge.Attempt{}, errors.New("Authentication failed")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mongo.local",
		IP:       "127.0.0.1",
		Port:     27017,
		Protocol: "mongodb",
	}, strategy.Credential{
		Username: "alice",
		Password: "wrong",
	})

	if out.Result.Success {
		t.Fatalf("expected authentication failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
	}
	if out.Legacy.Success || len(out.Legacy.Capabilities) != 0 {
		t.Fatalf("expected no legacy success payload on failure, got %+v", out)
	}
}

func TestMongoDBAuthenticatorAuthenticateOnceMapsNoVisibleDatabasesToInsufficientConfirmation(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openMongoCredentialClient = func(context.Context, core.SecurityCandidate, time.Duration, core.Credential) (mongoCredentialClient, error) {
		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return []string{}, nil
			},
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mongo.local",
		IP:       "127.0.0.1",
		Port:     27017,
		Protocol: "mongodb",
	}, strategy.Credential{
		Username: "alice",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected insufficient confirmation failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation error code, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out)
	}
	if out.Result.Error != errMongoNoVisibleDatabases.Error() {
		t.Fatalf("expected no visible databases error, got %+v", out)
	}
	if out.Legacy.Success || len(out.Legacy.Capabilities) != 0 {
		t.Fatalf("expected no legacy success payload on insufficient confirmation, got %+v", out)
	}
}

func TestMongoDBCredentialProberSucceedsAfterAuthenticatedListDatabaseNames(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return []string{"admin"}, nil
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout:       2 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{{
		Username: "alice",
		Password: "secret",
	}})

	if !result.Success {
		t.Fatalf("expected successful credential confirmation, got %+v", result)
	}
	if result.ProbeKind != core.ProbeKindCredential {
		t.Fatalf("expected credential probe kind, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
	if result.Evidence != "listDatabaseNames succeeded after authentication" {
		t.Fatalf("expected deterministic evidence, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.Username != "alice" || result.Password != "secret" {
		t.Fatalf("expected winning credential recorded, got %+v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0] != core.CapabilityEnumerable {
		t.Fatalf("expected enumerable capability, got %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return nil, errors.New("Authentication failed")
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{{
		Username: "alice",
		Password: "wrong",
	}})

	if result.Success {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
	if len(result.Capabilities) != 0 {
		t.Fatalf("expected no capabilities on failed result, got %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		return nil, errors.New("dial tcp 127.0.0.1:27017: connection refused")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{{
		Username: "alice",
		Password: "secret",
	}})

	if result.Success {
		t.Fatalf("expected connection failure, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{{
		Username: "alice",
		Password: "secret",
	}})

	if result.Success {
		t.Fatalf("expected canceled probe, got %+v", result)
	}
	if result.Stage != "" {
		t.Fatalf("expected empty stage before attempting probe, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestMongoDBCredentialProberRequiresVisibleDatabasesForConfirmation(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return []string{}, nil
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{{
		Username: "alice",
		Password: "secret",
	}})

	if result.Success {
		t.Fatalf("expected insufficient confirmation, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient-confirmation failure reason, got %+v", result)
	}
	if len(result.Capabilities) != 0 {
		t.Fatalf("expected no capabilities on insufficient confirmation, got %+v", result)
	}
}

func TestMongoDBCredentialProberReturnsImmediatelyOnTimeoutDuringOpen(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	attempts := 0
	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		attempts++
		if attempts > 1 {
			t.Fatalf("unexpected retry after terminal timeout with credential %+v", cred)
		}
		return nil, context.DeadlineExceeded
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{
		{Username: "alice", Password: "first"},
		{Username: "bob", Password: "second"},
	})

	if attempts != 1 {
		t.Fatalf("expected a single attempt after terminal timeout, got %d", attempts)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}

func TestMongoDBCredentialProberReturnsImmediatelyOnCanceledListDatabaseNames(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() {
		openMongoCredentialClient = originalOpen
	})

	attempts := 0
	openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
		attempts++
		if attempts > 1 {
			t.Fatalf("unexpected retry after terminal cancel with credential %+v", cred)
		}
		return fakeMongoCredentialClient{
			listDatabaseNames: func(context.Context, any) ([]string, error) {
				return nil, context.Canceled
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mongo.local",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{
		Timeout: 2 * time.Second,
	}, []core.Credential{
		{Username: "alice", Password: "first"},
		{Username: "bob", Password: "second"},
	})

	if attempts != 1 {
		t.Fatalf("expected a single attempt after terminal cancel, got %d", attempts)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}
