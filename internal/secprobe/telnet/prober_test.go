package telnet_test

import (
	"context"
	"errors"
	"testing"
	"time"

	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := telnetprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     23,
		Protocol: "telnet",
	}, strategy.Credential{Username: "admin", Password: "admin"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := telnetprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("authentication failed")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     23,
		Protocol: "telnet",
	}, strategy.Credential{Username: "admin", Password: "wrong"})

	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication code, got %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsCanceledFailure(t *testing.T) {
	auth := telnetprobe.NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return context.Canceled
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     23,
		Protocol: "telnet",
	}, strategy.Credential{Username: "admin", Password: "admin"})

	if out.Result.ErrorCode != result.ErrorCodeCanceled {
		t.Fatalf("expected canceled code, got %+v", out)
	}
}

func TestTelnetProberStopsAfterSuccess(t *testing.T) {
	server := testutil.StartFakeTelnet(t, "admin", "admin")

	prober := telnetprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       server.Port,
		Service:    "telnet",
	}, secprobe.CredentialProbeOptions{
		Timeout:       2 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "later"},
	})

	if !result.Success {
		t.Fatalf("expected telnet success, got %+v", result)
	}
	if got := server.Attempts(); got != 2 {
		t.Fatalf("expected 2 telnet attempts before stopping, got %d", got)
	}
}

func TestTelnetProberContinuesWhenStopOnSuccessDisabled(t *testing.T) {
	server := testutil.StartFakeTelnet(t, "admin", "admin")

	prober := telnetprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       server.Port,
		Service:    "telnet",
	}, secprobe.CredentialProbeOptions{
		Timeout:       2 * time.Second,
		StopOnSuccess: false,
	}, []secprobe.Credential{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "later"},
	})

	if !result.Success {
		t.Fatalf("expected telnet success, got %+v", result)
	}
	if got := server.Attempts(); got != 3 {
		t.Fatalf("expected 3 telnet attempts when stop-on-success is disabled, got %d", got)
	}
}
