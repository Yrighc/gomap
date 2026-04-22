package redis_test

import (
	"context"
	"testing"
	"time"

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
}
