package ssh_test

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

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
