package ssh_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
	gssh "golang.org/x/crypto/ssh"
)

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := sshprobe.NewAuthenticator(func(network, addr string, config *gssh.ClientConfig) (*gssh.Client, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if addr != net.JoinHostPort("127.0.0.1", "22") {
			t.Fatalf("addr = %q, want 127.0.0.1:22", addr)
		}
		if config.User != "root" {
			t.Fatalf("user = %q, want root", config.User)
		}
		return nil, nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     22,
		Protocol: "ssh",
	}, strategy.Credential{Username: "root", Password: "password"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOncePropagatesContextDeadlineToDialTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	auth := sshprobe.NewAuthenticator(func(_ string, _ string, config *gssh.ClientConfig) (*gssh.Client, error) {
		if config.Timeout <= 0 {
			t.Fatalf("expected positive ssh timeout, got %v", config.Timeout)
		}
		return nil, nil
	})

	out := auth.AuthenticateOnce(ctx, strategy.Target{
		Host:     "demo",
		IP:       "127.0.0.1",
		Port:     22,
		Protocol: "ssh",
	}, strategy.Credential{Username: "root", Password: "password"})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestSSHProberFindsValidCredential(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "test",
		Password: "test",
		Services: []string{"ssh"},
	})

	prober := sshprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("2222/tcp"),
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "test", Password: "bad"},
		{Username: "test", Password: "test"},
	})

	if !result.Success {
		t.Fatalf("expected ssh success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
}

func TestSSHProberClassifiesAuthenticationFailure(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "test",
		Password: "test",
		Services: []string{"ssh"},
	})

	prober := sshprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("2222/tcp"),
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "test", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected ssh failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestSSHProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := sshprobe.New()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "test", Password: "test"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestSSHProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	prober := sshprobe.New()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "test", Password: "test"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
