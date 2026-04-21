package secprobe

import (
	"context"
	"testing"
)

func TestRunSkipsUnsupportedCandidates(t *testing.T) {
	r := NewRegistry()
	result := RunWithRegistry(context.Background(), r, []SecurityCandidate{{Service: "http", Port: 80}}, CredentialProbeOptions{})
	if result.Meta.Candidates != 1 {
		t.Fatalf("expected one candidate, got %+v", result.Meta)
	}
	if result.Meta.Skipped != 1 {
		t.Fatalf("expected one skipped candidate, got %+v", result.Meta)
	}
}
