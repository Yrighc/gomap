package redis_test

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestRedisProberFindsValidCredential(t *testing.T) {
	container := testutil.StartRedis(t, testutil.RedisConfig{
		Password: "gomap-pass",
	})

	prober := redisprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []secprobe.Credential{
		{Username: "default", Password: "wrong-pass"},
		{Username: "default", Password: "gomap-pass"},
	})

	if !result.Success {
		t.Fatalf("expected redis success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected redis success evidence, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
}

func TestRedisProberReturnsErrorOnFailure(t *testing.T) {
	container := testutil.StartRedis(t, testutil.RedisConfig{
		Password: "gomap-pass",
	})

	prober := redisprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "default", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected redis failure, got %+v", result)
	}
	if result.Error == "" {
		t.Fatalf("expected redis failure error, got %+v", result)
	}
}

func TestRedisProberClassifiesAuthenticationFailure(t *testing.T) {
	container := testutil.StartRedis(t, testutil.RedisConfig{
		Password: "gomap-pass",
	})

	prober := redisprobe.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "default", Password: "wrong-pass"},
	})

	if result.Success {
		t.Fatalf("expected redis failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestRedisProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := redisprobe.New()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "default", Password: "gomap-pass"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestRedisProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	prober := redisprobe.New()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []secprobe.Credential{
		{Username: "default", Password: "gomap-pass"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
