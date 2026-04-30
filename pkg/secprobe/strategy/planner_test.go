package strategy

import (
	"reflect"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestCompileCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec metadata.Capabilities
		in   CompileInput
		want []Capability
	}{
		{
			name: "unauthorized comes before credential when both enabled",
			spec: metadata.Capabilities{Credential: true, Unauthorized: true},
			in:   CompileInput{EnableUnauthorized: true},
			want: []Capability{CapabilityUnauthorized, CapabilityCredential},
		},
		{
			name: "unauthorized stays disabled by runtime gate",
			spec: metadata.Capabilities{Credential: true, Unauthorized: true},
			in:   CompileInput{EnableUnauthorized: false},
			want: []Capability{CapabilityCredential},
		},
		{
			name: "unsupported unauthorized is skipped",
			spec: metadata.Capabilities{Credential: true, Unauthorized: false},
			in:   CompileInput{EnableUnauthorized: true},
			want: []Capability{CapabilityCredential},
		},
		{
			name: "unauthorized only plan omits credential",
			spec: metadata.Capabilities{Credential: false, Unauthorized: true},
			in:   CompileInput{EnableUnauthorized: true},
			want: []Capability{CapabilityUnauthorized},
		},
		{
			name: "no supported capabilities yields empty plan",
			spec: metadata.Capabilities{},
			in:   CompileInput{EnableUnauthorized: true},
			want: []Capability{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := testSpec()
			spec.Capabilities = tt.spec

			plan := Compile(spec, tt.in)
			if !reflect.DeepEqual(plan.Capabilities, tt.want) {
				t.Fatalf("capabilities = %v, want %v", plan.Capabilities, tt.want)
			}
		})
	}
}

func TestCompileEnrichmentPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		specSupports       bool
		runtimeEnabled     bool
		wantEnrichOnSucess bool
	}{
		{
			name:               "enrichment enabled only when runtime and spec both allow it",
			specSupports:       true,
			runtimeEnabled:     true,
			wantEnrichOnSucess: true,
		},
		{
			name:               "runtime disable keeps enrichment off",
			specSupports:       true,
			runtimeEnabled:     false,
			wantEnrichOnSucess: false,
		},
		{
			name:               "unsupported enrichment stays off",
			specSupports:       false,
			runtimeEnabled:     true,
			wantEnrichOnSucess: false,
		},
		{
			name:               "disabled everywhere stays off",
			specSupports:       false,
			runtimeEnabled:     false,
			wantEnrichOnSucess: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := testSpec()
			spec.Capabilities.Enrichment = tt.specSupports

			plan := Compile(spec, CompileInput{EnableEnrichment: tt.runtimeEnabled})
			if plan.Results.EnrichOnSuccess != tt.wantEnrichOnSucess {
				t.Fatalf("EnrichOnSuccess = %v, want %v", plan.Results.EnrichOnSuccess, tt.wantEnrichOnSucess)
			}
		})
	}
}

func TestCompileExecutionPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		lockout    string
		timeout    time.Duration
		wantConc   int
		wantTimout int
	}{
		{name: "high lockout uses single host worker", lockout: "high", timeout: time.Millisecond, wantConc: 1, wantTimout: 1},
		{name: "medium lockout is throttled", lockout: "medium", timeout: 1500 * time.Millisecond, wantConc: 3, wantTimout: 2},
		{name: "low lockout keeps default concurrency", lockout: "low", timeout: 2 * time.Second, wantConc: 10, wantTimout: 2},
		{name: "unknown lockout falls back to default", lockout: "unexpected", timeout: 0, wantConc: 10, wantTimout: 0},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := testSpec()
			spec.PolicyTags.LockoutRisk = tt.lockout

			plan := Compile(spec, CompileInput{Timeout: tt.timeout})
			if plan.Execution.ConcurrencyScope != "per_host" {
				t.Fatalf("ConcurrencyScope = %q, want %q", plan.Execution.ConcurrencyScope, "per_host")
			}
			if plan.Execution.ConcurrencyValue != tt.wantConc {
				t.Fatalf("ConcurrencyValue = %d, want %d", plan.Execution.ConcurrencyValue, tt.wantConc)
			}
			if plan.Execution.TimeoutSeconds != tt.wantTimout {
				t.Fatalf("TimeoutSeconds = %d, want %d", plan.Execution.TimeoutSeconds, tt.wantTimout)
			}
		})
	}
}

func TestCompileCredentialSourceSelection(t *testing.T) {
	t.Parallel()

	inline := []Credential{
		{Username: "root", Password: "root"},
		{Username: "admin", Password: "admin"},
	}
	inlineWithDuplicate := []Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root"},
		{Username: "admin", Password: "admin"},
	}

	tests := []struct {
		name          string
		in            CompileInput
		wantSource    CredentialSource
		wantInline    int
		wantDirectory string
	}{
		{
			name:       "inline credentials override all other sources",
			in:         CompileInput{Credentials: inline, DictDir: "/tmp/dicts"},
			wantSource: CredentialSourceInline,
			wantInline: len(inline),
		},
		{
			name:       "inline credentials count matches runtime dedupe behavior",
			in:         CompileInput{Credentials: inlineWithDuplicate},
			wantSource: CredentialSourceInline,
			wantInline: len(inline),
		},
		{
			name:          "dict dir wins when inline credentials are absent",
			in:            CompileInput{DictDir: "/tmp/dicts"},
			wantSource:    CredentialSourceDirectory,
			wantDirectory: "/tmp/dicts",
		},
		{
			name:          "whitespace dict dir follows runtime non-empty check",
			in:            CompileInput{DictDir: "   "},
			wantSource:    CredentialSourceDirectory,
			wantDirectory: "   ",
		},
		{
			name:       "builtin dictionaries remain the fallback",
			in:         CompileInput{},
			wantSource: CredentialSourceBuiltin,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := testSpec()
			plan := Compile(spec, tt.in)

			if plan.Credentials.Source != tt.wantSource {
				t.Fatalf("Source = %q, want %q", plan.Credentials.Source, tt.wantSource)
			}
			if plan.Credentials.InlineCount != tt.wantInline {
				t.Fatalf("InlineCount = %d, want %d", plan.Credentials.InlineCount, tt.wantInline)
			}
			if plan.Credentials.Directory != tt.wantDirectory {
				t.Fatalf("Directory = %q, want %q", plan.Credentials.Directory, tt.wantDirectory)
			}
			if !reflect.DeepEqual(plan.Credentials.Dictionaries, []string{"redis"}) {
				t.Fatalf("Dictionaries = %v, want %v", plan.Credentials.Dictionaries, []string{"redis"})
			}
		})
	}
}

func testSpec() metadata.Spec {
	return metadata.Spec{
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
}
