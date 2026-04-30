package strategy

import (
	"reflect"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestCompilePlanRedisPrefersUnauthorizedThenCredential(t *testing.T) {
	spec := metadata.Spec{
		Name: "redis",
		Capabilities: metadata.Capabilities{
			Credential:   true,
			Unauthorized: true,
			Enrichment:   true,
		},
		PolicyTags: metadata.PolicyTags{
			LockoutRisk: "low",
		},
		Dictionary: metadata.Dictionary{
			DefaultSources:     []string{"redis"},
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
		Results: metadata.ResultProfile{
			CredentialSuccessType:   "credential_valid",
			UnauthorizedSuccessType: "unauthorized_access",
			EvidenceProfile:         "redis_basic",
		},
	}

	plan := Compile(spec, CompileInput{
		Target:             "demo",
		IP:                 "127.0.0.1",
		Port:               6379,
		EnableUnauthorized: true,
		EnableEnrichment:   true,
		StopOnSuccess:      true,
		Timeout:            3 * time.Second,
	})

	if got, want := plan.Capabilities, []Capability{CapabilityUnauthorized, CapabilityCredential}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	if !plan.Execution.StopOnFirstSuccess {
		t.Fatalf("expected stop on first success, got %+v", plan.Execution)
	}
}
