package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	stdsmtp "net/smtp"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSMTPClient struct {
	name           string
	authExtensions map[string]string
	startTLSErr    error
	authFn         func(stdsmtp.Auth) error
	closeCalls     int
	quitCalls      int
	startTLSCalls  int
}

func (c *fakeSMTPClient) Extension(name string) (bool, string) {
	value, ok := c.authExtensions[name]
	return ok, value
}

func (c *fakeSMTPClient) StartTLS(*tls.Config) error {
	c.startTLSCalls++
	return c.startTLSErr
}

func (c *fakeSMTPClient) Auth(auth stdsmtp.Auth) error {
	if c.authFn != nil {
		return c.authFn(auth)
	}
	return nil
}

func (c *fakeSMTPClient) Close() error {
	c.closeCalls++
	return nil
}

func (c *fakeSMTPClient) Quit() error {
	c.quitCalls++
	return nil
}

func TestSMTPProberFindsValidCredentialWithPlainAuth(t *testing.T) {
	originalDial := dialSMTPClient
	t.Cleanup(func() {
		dialSMTPClient = originalDial
	})

	var attempts []string
	dialSMTPClient = func(context.Context, string, smtpDialPlan, time.Duration) (smtpClient, error) {
		return &fakeSMTPClient{
			authExtensions: map[string]string{"AUTH": "PLAIN LOGIN", "STARTTLS": ""},
			authFn: func(auth stdsmtp.Auth) error {
				attempts = append(attempts, authMechanism(t, auth))
				return nil
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       587,
		Service:    "smtp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "mailer", Password: "secret"},
	})

	if !result.Success {
		t.Fatalf("expected smtp success, got %+v", result)
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
	if !slices.Equal(attempts, []string{"PLAIN"}) {
		t.Fatalf("expected AUTH PLAIN only, got %v", attempts)
	}
}

func TestSMTPProberFallsBackFromPlainToLogin(t *testing.T) {
	originalDial := dialSMTPClient
	t.Cleanup(func() {
		dialSMTPClient = originalDial
	})

	var attempts []string
	var dialedClients []*fakeSMTPClient
	dialSMTPClient = func(context.Context, string, smtpDialPlan, time.Duration) (smtpClient, error) {
		client := &fakeSMTPClient{
			name:           "client",
			authExtensions: map[string]string{"AUTH": "PLAIN LOGIN"},
		}
		client.authFn = func(auth stdsmtp.Auth) error {
			mechanism := authMechanism(t, auth)
			attempts = append(attempts, mechanism+"@"+client.name)
			if mechanism == "PLAIN" {
				return errors.New("535 auth failed and connection closed")
			}
			if client.closeCalls == 0 && client.quitCalls == 0 && len(dialedClients) == 1 {
				t.Fatalf("expected LOGIN fallback to use a fresh connection, got reused client state: %+v", client)
			}
			return nil
		}
		dialedClients = append(dialedClients, client)
		client.name = "client-" + string(rune('0'+len(dialedClients)))
		return client, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       587,
		Service:    "smtp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "mailer", Password: "secret"},
	})

	if !result.Success {
		t.Fatalf("expected smtp success after LOGIN fallback, got %+v", result)
	}
	if len(dialedClients) != 2 {
		t.Fatalf("expected fallback to redial with a fresh client, got %d clients", len(dialedClients))
	}
	if !slices.Equal(attempts, []string{"PLAIN@client-1", "LOGIN@client-2"}) {
		t.Fatalf("expected PLAIN on first client then LOGIN on second client, got %v", attempts)
	}
	if dialedClients[0].closeCalls == 0 && dialedClients[0].quitCalls == 0 {
		t.Fatalf("expected failed AUTH client to be closed, got %+v", dialedClients[0])
	}
}

func TestSMTPProberDoesNotConfirmAuthAdvertisementWithoutAuthenticationSuccess(t *testing.T) {
	originalDial := dialSMTPClient
	t.Cleanup(func() {
		dialSMTPClient = originalDial
	})

	dialSMTPClient = func(context.Context, string, smtpDialPlan, time.Duration) (smtpClient, error) {
		return &fakeSMTPClient{
			authExtensions: map[string]string{"AUTH": "PLAIN LOGIN"},
			authFn: func(stdsmtp.Auth) error {
				return errors.New("535 authentication failed")
			},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       587,
		Service:    "smtp",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "mailer", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected smtp failure, got %+v", result)
	}
	if result.Stage == core.StageConfirmed {
		t.Fatalf("expected auth advertisement alone to avoid confirmed stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestSMTPDialPlanUsesImplicitTLSForPort465(t *testing.T) {
	plan := buildDialPlan(core.SecurityCandidate{
		ResolvedIP: "127.0.0.1",
		Port:       465,
		Service:    "smtp",
	})

	if !plan.implicitTLS {
		t.Fatalf("expected implicit TLS for port 465, got %+v", plan)
	}
	if plan.allowStartTLS {
		t.Fatalf("expected implicit TLS plan to skip STARTTLS upgrade, got %+v", plan)
	}
}

func TestDefaultDialSMTPClientPassesCallerContextToImplicitTLSDialer(t *testing.T) {
	originalDial := dialImplicitTLSContext
	t.Cleanup(func() {
		dialImplicitTLSContext = originalDial
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type markerKey struct{}
	markerCtx := context.WithValue(ctx, markerKey{}, "smtp-ctx")
	sentinel := errors.New("stop after ctx capture")
	var capturedCtx context.Context
	var capturedTimeout time.Duration
	dialImplicitTLSContext = func(ctx context.Context, network, addr string, timeout time.Duration, config *tls.Config) (net.Conn, error) {
		capturedCtx = ctx
		capturedTimeout = timeout
		return nil, sentinel
	}

	timeout := time.Second
	start := time.Now()
	_, err := defaultDialSMTPClient(markerCtx, "127.0.0.1:465", smtpDialPlan{implicitTLS: true}, timeout)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if capturedCtx == nil {
		t.Fatal("expected implicit TLS dialer to receive caller context")
	}
	if capturedCtx == markerCtx {
		t.Fatalf("expected implicit TLS dialer to receive a derived timeout context")
	}
	if got := capturedCtx.Value(markerKey{}); got != "smtp-ctx" {
		t.Fatalf("expected derived context to preserve caller values, got %v", got)
	}
	deadline, ok := capturedCtx.Deadline()
	if !ok {
		t.Fatal("expected implicit TLS dialer context to include timeout deadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > timeout {
		t.Fatalf("expected timeout deadline within %v, got remaining=%v", timeout, remaining)
	}
	if deadline.Before(start) {
		t.Fatalf("expected deadline after call start, got %v before %v", deadline, start)
	}
	if capturedTimeout != timeout {
		t.Fatalf("expected implicit TLS dialer to receive timeout %v, got %v", timeout, capturedTimeout)
	}
}

func TestLoginAuthUsesSequentialStateForEmptyChallenges(t *testing.T) {
	auth := &loginAuth{username: "mailer", password: "secret"}

	proto, initial, err := auth.Start(&stdsmtp.ServerInfo{Name: "127.0.0.1", TLS: true, Auth: []string{"LOGIN"}})
	if err != nil {
		t.Fatalf("start login auth: %v", err)
	}
	if proto != "LOGIN" {
		t.Fatalf("expected LOGIN protocol, got %q", proto)
	}
	if initial != nil {
		t.Fatalf("expected nil initial response, got %q", string(initial))
	}

	first, err := auth.Next(nil, true)
	if err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	second, err := auth.Next(nil, true)
	if err != nil {
		t.Fatalf("second challenge: %v", err)
	}
	third, err := auth.Next(nil, false)
	if err != nil {
		t.Fatalf("final challenge: %v", err)
	}

	if string(first) != "mailer" {
		t.Fatalf("expected first response to send username, got %q", string(first))
	}
	if string(second) != "secret" {
		t.Fatalf("expected second response to send password, got %q", string(second))
	}
	if third != nil {
		t.Fatalf("expected nil terminal response, got %q", string(third))
	}
}

func TestLoginAuthDoesNotRepeatUsernameOnNonStandardChallenge(t *testing.T) {
	auth := &loginAuth{username: "mailer", password: "secret"}

	if _, _, err := auth.Start(&stdsmtp.ServerInfo{Name: "127.0.0.1", TLS: true, Auth: []string{"LOGIN"}}); err != nil {
		t.Fatalf("start login auth: %v", err)
	}

	first, err := auth.Next([]byte("334 VXNlcm5hbWU6"), true)
	if err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	second, err := auth.Next([]byte("334"), true)
	if err != nil {
		t.Fatalf("second challenge: %v", err)
	}

	if string(first) != "mailer" {
		t.Fatalf("expected first response to send username, got %q", string(first))
	}
	if string(second) != "secret" {
		t.Fatalf("expected second response to send password on non-standard challenge, got %q", string(second))
	}
}

func authMechanism(t *testing.T, auth stdsmtp.Auth) string {
	t.Helper()

	proto, _, err := auth.Start(&stdsmtp.ServerInfo{
		Name: "127.0.0.1",
		TLS:  true,
		Auth: []string{"PLAIN", "LOGIN"},
	})
	if err != nil {
		t.Fatalf("inspect auth mechanism: %v", err)
	}
	return proto
}
