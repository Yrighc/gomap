package rdp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestRDPProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalNegotiate := negotiateTransport
	originalLogin := loginRDP
	t.Cleanup(func() {
		negotiateTransport = originalNegotiate
		loginRDP = originalLogin
	})

	var modes []transportMode
	negotiateTransport = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) (transportMode, error) {
		return transportModeTLS, nil
	}
	loginRDP = func(_ context.Context, _ core.SecurityCandidate, cred core.Credential, _ core.CredentialProbeOptions, mode transportMode) error {
		modes = append(modes, mode)
		if cred.Password == "correct" {
			return nil
		}
		return errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       3389,
		Service:    "rdp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "alice", Password: "wrong"},
		{Username: "alice", Password: "correct"},
	})

	if !result.Success {
		t.Fatalf("expected rdp success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
	if result.FailureReason != "" {
		t.Fatalf("expected empty failure reason on success, got %+v", result)
	}
	if len(modes) != 2 {
		t.Fatalf("expected two login attempts, got %d", len(modes))
	}
	for _, mode := range modes {
		if mode != transportModeTLS {
			t.Fatalf("expected TLS transport for all attempts, got %v", modes)
		}
	}
}

func TestRDPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalNegotiate := negotiateTransport
	originalLogin := loginRDP
	t.Cleanup(func() {
		negotiateTransport = originalNegotiate
		loginRDP = originalLogin
	})

	negotiateTransport = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) (transportMode, error) {
		return transportModeRDP, nil
	}
	loginRDP = func(context.Context, core.SecurityCandidate, core.Credential, core.CredentialProbeOptions, transportMode) error {
		return errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       3389,
		Service:    "rdp",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "alice", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected rdp failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}
