package core

import (
	"encoding/json"
	"testing"
)

func TestSecurityResultKeepsInternalStateOutOfJSON(t *testing.T) {
	result := SecurityResult{
		Target:        "example.com",
		ResolvedIP:    "127.0.0.1",
		Port:          22,
		Service:       "ssh",
		ProbeKind:     ProbeKindCredential,
		FindingType:   FindingTypeCredentialValid,
		Success:       true,
		Username:      "root",
		Password:      "root",
		Evidence:      "SSH authentication succeeded",
		Stage:         StageConfirmed,
		SkipReason:    SkipReasonProbeDisabled,
		FailureReason: FailureReasonAuthentication,
		Capabilities:  []Capability{CapabilityEnumerable, CapabilityReadable},
		Risk:          RiskHigh,
	}

	data, err := result.ToJSON(false)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}

	for _, field := range []string{"Stage", "SkipReason", "FailureReason", "Capabilities", "Risk"} {
		if _, exists := got[field]; exists {
			t.Fatalf("expected %s to stay out of json output: %s", field, string(data))
		}
	}
}

func TestSecurityResultCarriesStructuredStateInMemory(t *testing.T) {
	result := SecurityResult{
		Stage:         StageEnriched,
		SkipReason:    SkipReasonNoCredentials,
		FailureReason: FailureReasonInsufficientConfirmation,
		Capabilities:  []Capability{CapabilityEnumerable, CapabilityReadable},
		Risk:          RiskMedium,
	}

	if result.Stage != StageEnriched {
		t.Fatalf("expected stage %q, got %q", StageEnriched, result.Stage)
	}
	if result.SkipReason != SkipReasonNoCredentials {
		t.Fatalf("expected skip reason %q, got %q", SkipReasonNoCredentials, result.SkipReason)
	}
	if result.FailureReason != FailureReasonInsufficientConfirmation {
		t.Fatalf("expected failure reason %q, got %q", FailureReasonInsufficientConfirmation, result.FailureReason)
	}
	if len(result.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(result.Capabilities))
	}
	if result.Capabilities[0] != CapabilityEnumerable || result.Capabilities[1] != CapabilityReadable {
		t.Fatalf("unexpected capabilities: %#v", result.Capabilities)
	}
	if result.Risk != RiskMedium {
		t.Fatalf("expected risk %q, got %q", RiskMedium, result.Risk)
	}
}
