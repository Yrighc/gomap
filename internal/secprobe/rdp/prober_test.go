package rdp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sergei-bronnikov/grdp/protocol/x224"
	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     3389,
		Protocol: "rdp",
	}, strategy.Credential{Username: "alice", Password: "secret"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("authentication failed")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     3389,
		Protocol: "rdp",
	}, strategy.Credential{Username: "alice", Password: "wrong"})

	if out.Result.Success {
		t.Fatalf("expected auth failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication code, got %+v", out.Result)
	}
}

func TestRDPProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalAttempts := transportAttempts
	originalLogin := loginRDP
	t.Cleanup(func() {
		transportAttempts = originalAttempts
		loginRDP = originalLogin
	})

	var modes []transportAttempt
	transportAttempts = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) ([]transportAttempt, error) {
		return []transportAttempt{{mode: transportModeTLS, protocol: x224.PROTOCOL_SSL}}, nil
	}
	loginRDP = func(_ context.Context, _ core.SecurityCandidate, cred core.Credential, _ core.CredentialProbeOptions, attempt transportAttempt) error {
		modes = append(modes, attempt)
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
	for _, attempt := range modes {
		if attempt.mode != transportModeTLS {
			t.Fatalf("expected TLS transport for all attempts, got %v", modes)
		}
	}
}

func TestRDPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalAttempts := transportAttempts
	originalLogin := loginRDP
	t.Cleanup(func() {
		transportAttempts = originalAttempts
		loginRDP = originalLogin
	})

	transportAttempts = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) ([]transportAttempt, error) {
		return []transportAttempt{{mode: transportModeRDP, protocol: x224.PROTOCOL_RDP}}, nil
	}
	loginRDP = func(context.Context, core.SecurityCandidate, core.Credential, core.CredentialProbeOptions, transportAttempt) error {
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

func TestDefaultTransportAttemptsPreferHybridThenSSLThenRDP(t *testing.T) {
	attempts, err := defaultTransportAttempts(context.Background(), core.SecurityCandidate{
		Service: "rdp",
	}, core.CredentialProbeOptions{})
	if err != nil {
		t.Fatalf("expected no error building attempts, got %v", err)
	}

	if len(attempts) != 3 {
		t.Fatalf("expected three default transport attempts, got %d", len(attempts))
	}
	if attempts[0].mode != transportModeHybrid || attempts[0].protocol != x224.PROTOCOL_HYBRID {
		t.Fatalf("expected HYBRID first, got %+v", attempts)
	}
	if attempts[1].mode != transportModeTLS || attempts[1].protocol != x224.PROTOCOL_SSL {
		t.Fatalf("expected SSL second, got %+v", attempts)
	}
	if attempts[2].mode != transportModeRDP || attempts[2].protocol != x224.PROTOCOL_RDP {
		t.Fatalf("expected RDP third, got %+v", attempts)
	}
}

func TestRDPProberFallsBackAcrossTransportAttempts(t *testing.T) {
	originalAttempts := transportAttempts
	originalLogin := loginRDP
	t.Cleanup(func() {
		transportAttempts = originalAttempts
		loginRDP = originalLogin
	})

	transportAttempts = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) ([]transportAttempt, error) {
		return []transportAttempt{
			{mode: transportModeHybrid, protocol: x224.PROTOCOL_HYBRID},
			{mode: transportModeTLS, protocol: x224.PROTOCOL_SSL},
			{mode: transportModeRDP, protocol: x224.PROTOCOL_RDP},
		}, nil
	}

	var modes []transportMode
	loginRDP = func(_ context.Context, _ core.SecurityCandidate, cred core.Credential, _ core.CredentialProbeOptions, attempt transportAttempt) error {
		modes = append(modes, attempt.mode)
		if attempt.mode == transportModeHybrid {
			return errNegotiationClosed
		}
		if attempt.mode == transportModeTLS && cred.Password == "correct" {
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
		{Username: "alice", Password: "correct"},
	})

	if !result.Success {
		t.Fatalf("expected rdp success after fallback sequence, got %+v", result)
	}
	if len(modes) != 2 || modes[0] != transportModeHybrid || modes[1] != transportModeTLS {
		t.Fatalf("expected hybrid then tls fallback, got %v", modes)
	}
}

func TestLoginOnceReturnsLastRetryableTransportError(t *testing.T) {
	originalAttempts := transportAttempts
	originalLogin := loginRDP
	t.Cleanup(func() {
		transportAttempts = originalAttempts
		loginRDP = originalLogin
	})

	transportAttempts = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) ([]transportAttempt, error) {
		return []transportAttempt{
			{mode: transportModeHybrid, protocol: x224.PROTOCOL_HYBRID},
			{mode: transportModeTLS, protocol: x224.PROTOCOL_SSL},
		}, nil
	}

	var modes []transportMode
	firstErr := errors.New("connection reset by peer")
	lastErr := errors.New("unexpected server response")
	loginRDP = func(_ context.Context, _ core.SecurityCandidate, _ core.Credential, _ core.CredentialProbeOptions, attempt transportAttempt) error {
		modes = append(modes, attempt.mode)
		if attempt.mode == transportModeHybrid {
			return firstErr
		}
		return lastErr
	}

	err := loginOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     3389,
		Protocol: "rdp",
	}, strategy.Credential{Username: "alice", Password: "secret"})

	if err != lastErr {
		t.Fatalf("expected last retryable error %v, got %v", lastErr, err)
	}
	if len(modes) != 2 || modes[0] != transportModeHybrid || modes[1] != transportModeTLS {
		t.Fatalf("expected hybrid then tls fallback, got %v", modes)
	}
}

func TestDefaultLoginRDPReturnsPromptlyWhenNegotiationCloses(t *testing.T) {
	originalOpen := openRDPSession
	t.Cleanup(func() {
		openRDPSession = originalOpen
	})

	openRDPSession = func(context.Context, core.SecurityCandidate, core.Credential, core.CredentialProbeOptions) (rdpSession, error) {
		return &fakeRDPSession{
			connect: func(s *fakeRDPSession) error {
				s.emitClose()
				return nil
			},
		}, nil
	}

	start := time.Now()
	err := defaultLoginRDP(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       3389,
		Service:    "rdp",
	}, core.Credential{
		Username: "alice",
		Password: "secret",
	}, core.CredentialProbeOptions{
		Timeout: 500 * time.Millisecond,
	}, transportAttempt{mode: transportModeHybrid, protocol: x224.PROTOCOL_HYBRID})

	if err == nil {
		t.Fatal("expected negotiation close error")
	}
	if time.Since(start) >= 200*time.Millisecond {
		t.Fatalf("expected prompt return before timeout, got %v", time.Since(start))
	}
	if !strings.Contains(err.Error(), "negotiation closed") {
		t.Fatalf("expected negotiation close error, got %v", err)
	}
	if got := classifyRDPFailure(err); got != core.FailureReasonConnection {
		t.Fatalf("expected connection failure classification, got %q", got)
	}
}

type fakeRDPSession struct {
	onClose func()
	onReady func()
	onError func(error)
	connect func(*fakeRDPSession) error
}

func (s *fakeRDPSession) OnClose(fn func()) { s.onClose = fn }

func (s *fakeRDPSession) OnReady(fn func()) { s.onReady = fn }

func (s *fakeRDPSession) OnError(fn func(error)) { s.onError = fn }

func (s *fakeRDPSession) SetRequestedProtocol(uint32) {}

func (s *fakeRDPSession) Connect() error {
	if s.connect != nil {
		return s.connect(s)
	}
	return nil
}

func (s *fakeRDPSession) Close() error { return nil }

func (s *fakeRDPSession) emitClose() {
	if s.onClose != nil {
		s.onClose()
	}
}
