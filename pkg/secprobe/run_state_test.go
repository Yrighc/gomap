package secprobe

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestRunWithRegistryMarksDisabledUnauthorizedAsProbeDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
	})

	result := runWithRegistryInternal(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Stage != core.StageMatched {
		t.Fatalf("expected matched stage for disabled unauthorized candidate, got %+v", got)
	}
	if got.SkipReason != core.SkipReasonProbeDisabled {
		t.Fatalf("expected probe-disabled skip reason, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected internal probe kind to stay unauthorized, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected internal finding type to stay unauthorized-access, got %+v", got)
	}
}

func TestRunWithRegistryInternalMarksUnsupportedProtocol(t *testing.T) {
	result := runWithRegistryInternal(context.Background(), NewRegistry(), []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       80,
		Service:    "http",
	}}, CredentialProbeOptions{})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.SkipReason != core.SkipReasonUnsupportedProtocol {
		t.Fatalf("expected unsupported-protocol skip reason, got %+v", got)
	}
	if got.Stage != "" {
		t.Fatalf("expected unsupported candidate to skip before matching, got %+v", got)
	}
}

func TestRunWithRegistryMarksMissingCredentialsAsNoCredentials(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "customsvc-credential",
		kind:    ProbeKindCredential,
		service: "customsvc",
	})

	result := runWithRegistryInternal(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "customsvc",
	}}, CredentialProbeOptions{
		DictDir: filepath.Join(t.TempDir(), "missing"),
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Stage != core.StageMatched {
		t.Fatalf("expected matched stage before credential load skip, got %+v", got)
	}
	if got.SkipReason != core.SkipReasonNoCredentials {
		t.Fatalf("expected no-credentials skip reason, got %+v", got)
	}
}

func TestRunWithRegistryMarksSuccessfulProbeAsConfirmed(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubSuccessProber{name: "ssh"})

	result := runWithRegistryInternal(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{
		Timeout:     time.Second,
		Credentials: []Credential{{Username: "root", Password: "root"}},
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", got)
	}
	if got.SkipReason != "" {
		t.Fatalf("expected no skip reason for confirmed result, got %+v", got)
	}
	if got.FailureReason != "" {
		t.Fatalf("expected no failure reason for confirmed result, got %+v", got)
	}
}

func TestRunWithRegistryMarksAttemptFailureWithReason(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "ssh-credential",
		kind:    ProbeKindCredential,
		service: "ssh",
		result: SecurityResult{
			Service:     "ssh",
			ProbeKind:   ProbeKindCredential,
			FindingType: FindingTypeCredentialValid,
			Error:       "authentication failed",
		},
	})

	result := runWithRegistryInternal(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{
		Timeout:     time.Second,
		Credentials: []Credential{{Username: "root", Password: "wrong"}},
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage for failed probe, got %+v", got)
	}
	if got.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", got)
	}
	if got.SkipReason != "" {
		t.Fatalf("expected no skip reason on attempted failure, got %+v", got)
	}
}

func TestApplyEnrichmentMarksConfirmedResultAsEnrichedWhenDataAdded(t *testing.T) {
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"info_excerpt": "copied"}
		return result
	})
	defer restore()

	got := applyEnrichment(context.Background(), []core.SecurityResult{{
		Service:       "redis",
		ProbeKind:     ProbeKindUnauthorized,
		FindingType:   FindingTypeUnauthorizedAccess,
		Success:       true,
		Stage:         core.StageConfirmed,
		Capabilities:  []core.Capability{core.CapabilityReadable},
		Risk:          core.RiskHigh,
		FailureReason: core.FailureReasonAuthentication,
	}}, CredentialProbeOptions{
		EnableEnrichment: true,
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Stage != core.StageEnriched {
		t.Fatalf("expected enriched stage after enrichment data added, got %+v", got[0])
	}
	if got[0].Enrichment == nil {
		t.Fatalf("expected enrichment payload, got %+v", got[0])
	}
	if got[0].Capabilities[0] != core.CapabilityReadable {
		t.Fatalf("expected existing core state to survive enrichment, got %+v", got[0])
	}
}

func TestApplyEnrichmentKeepsPriorStageWhenEnrichmentDidNotChange(t *testing.T) {
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Stage = core.StageEnriched
		return result
	})
	defer restore()

	got := applyEnrichment(context.Background(), []core.SecurityResult{{
		Service:     "redis",
		ProbeKind:   ProbeKindUnauthorized,
		FindingType: FindingTypeUnauthorizedAccess,
		Success:     true,
		Stage:       core.StageConfirmed,
		Enrichment:  map[string]any{"info_excerpt": "same"},
	}}, CredentialProbeOptions{
		EnableEnrichment: true,
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Stage != core.StageConfirmed {
		t.Fatalf("expected stage to stay confirmed when enrichment did not change, got %+v", got[0])
	}
	if got[0].Enrichment["info_excerpt"] != "same" {
		t.Fatalf("expected enrichment payload to remain unchanged, got %+v", got[0])
	}
}
