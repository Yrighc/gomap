package redis_test

import (
	"context"
	"testing"
	"time"

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
