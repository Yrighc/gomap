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

func TestRedisUnauthorizedProberDetectsOpenRedis(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	prober := redisprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if !result.Success {
		t.Fatalf("expected redis unauthorized success, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result)
	}
	if result.Evidence != "INFO returned redis_version without authentication" {
		t.Fatalf("expected deterministic redis evidence, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
}

func TestRedisUnauthorizedProberMarksConfirmedCapabilities(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	prober := redisprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if !result.Success {
		t.Fatalf("expected redis unauthorized success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if len(result.Capabilities) != 2 {
		t.Fatalf("expected redis capabilities, got %+v", result)
	}
	if result.Capabilities[0] != core.CapabilityEnumerable || result.Capabilities[1] != core.CapabilityReadable {
		t.Fatalf("expected enumerable/readable capabilities, got %+v", result)
	}
}

func TestRedisUnauthorizedProberDoesNotMarkAttemptedWhenContextCanceledBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := redisprobe.NewUnauthorized()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any probe attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}
