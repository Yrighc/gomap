package registry

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestPublicProberCredentialAdapterWrapsSingleAttempt(t *testing.T) {
	prober := stubCredentialProber{
		out: core.SecurityResult{
			Success:       true,
			Username:      "admin",
			Password:      "admin",
			FindingType:   core.FindingTypeCredentialValid,
			FailureReason: "",
		},
	}

	adapter := PublicCredentialAdapter{Prober: prober, Timeout: time.Second}
	out := adapter.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 21, Protocol: "ftp",
	}, strategy.Credential{Username: "admin", Password: "admin"})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

type stubCredentialProber struct {
	out core.SecurityResult
}

func (s stubCredentialProber) Name() string { return "stub" }

func (s stubCredentialProber) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (s stubCredentialProber) Match(core.SecurityCandidate) bool { return true }

func (s stubCredentialProber) Probe(context.Context, core.SecurityCandidate, core.CredentialProbeOptions, []core.Credential) core.SecurityResult {
	return s.out
}
