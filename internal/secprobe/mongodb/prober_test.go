package mongodb_test

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestMongoDBUnauthorizedProberDetectsOpenMongoDB(t *testing.T) {
	container := testutil.StartMongoDBNoAuth(t)

	prober := mongodbprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if !result.Success {
		t.Fatalf("expected mongodb unauthorized success, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result)
	}
	if result.Evidence != "listDatabaseNames succeeded without authentication" {
		t.Fatalf("expected deterministic mongodb evidence, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
}

func TestMongoDBUnauthorizedProberMarksConfirmedEnumerable(t *testing.T) {
	container := testutil.StartMongoDBNoAuth(t)

	prober := mongodbprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}, secprobe.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, nil)

	if !result.Success {
		t.Fatalf("expected mongodb unauthorized success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0] != core.CapabilityEnumerable {
		t.Fatalf("expected enumerable capability, got %+v", result)
	}
}

func TestMongoDBUnauthorizedProberDoesNotMarkAttemptedWhenContextCanceledBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := mongodbprobe.NewUnauthorized()
	result := prober.Probe(ctx, secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
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
