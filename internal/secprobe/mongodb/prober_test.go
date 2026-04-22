package mongodb_test

import (
	"context"
	"testing"
	"time"

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
}
