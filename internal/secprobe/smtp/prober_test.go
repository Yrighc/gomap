package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	stdsmtp "net/smtp"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSMTPClient struct {
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
	dialSMTPClient = func(context.Context, string, smtpDialPlan, time.Duration) (smtpClient, error) {
		return &fakeSMTPClient{
			authExtensions: map[string]string{"AUTH": "PLAIN LOGIN"},
			authFn: func(auth stdsmtp.Auth) error {
				mechanism := authMechanism(t, auth)
				attempts = append(attempts, mechanism)
				if mechanism == "PLAIN" {
					return errors.New("504 mechanism plain disabled")
				}
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
		t.Fatalf("expected smtp success after LOGIN fallback, got %+v", result)
	}
	if !slices.Equal(attempts, []string{"PLAIN", "LOGIN"}) {
		t.Fatalf("expected PLAIN then LOGIN fallback, got %v", attempts)
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
