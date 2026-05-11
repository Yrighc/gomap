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
		name       string
		in         CompileInput
		wantSource CredentialSource
		wantInline int
	}{
		{
			name:       "inline credentials override all other sources",
			in:         CompileInput{Credentials: inline},
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
			if !reflect.DeepEqual(plan.Credentials.Dictionaries, []string{"redis"}) {
				t.Fatalf("Dictionaries = %v, want %v", plan.Credentials.Dictionaries, []string{"redis"})
			}
		})
	}
}

func TestCompileConsumesSNMPMetadataFields(t *testing.T) {
	t.Parallel()

	spec := metadata.Spec{
		Name: "snmp",
		Capabilities: metadata.Capabilities{
			Credential: true,
		},
		PolicyTags: metadata.PolicyTags{
			LockoutRisk: "low",
			AuthFamily:  "community",
			Transport:   "udp",
		},
		Dictionary: metadata.Dictionary{
			PasswordSource:     "snmp",
			AllowEmptyUsername: true,
			AllowEmptyPassword: false,
			ExpansionProfile:   "static_basic",
		},
		Results: metadata.ResultProfile{
			CredentialSuccessType: "credential_valid",
			EvidenceProfile:       "snmp_basic",
		},
	}

	plan := Compile(spec, CompileInput{
		Target:  "demo",
		IP:      "127.0.0.1",
		Port:    161,
		Timeout: 1500 * time.Millisecond,
	})

	if !reflect.DeepEqual(plan.Capabilities, []Capability{CapabilityCredential}) {
		t.Fatalf("Capabilities = %v, want %v", plan.Capabilities, []Capability{CapabilityCredential})
	}
	if plan.Credentials.Source != CredentialSourceBuiltin {
		t.Fatalf("Source = %q, want %q", plan.Credentials.Source, CredentialSourceBuiltin)
	}
	if !reflect.DeepEqual(plan.Credentials.Dictionaries, []string{"snmp"}) {
		t.Fatalf("Dictionaries = %v, want %v", plan.Credentials.Dictionaries, []string{"snmp"})
	}
	if !plan.Credentials.AllowEmptyUser {
		t.Fatalf("AllowEmptyUser = %v, want true", plan.Credentials.AllowEmptyUser)
	}
	if plan.Credentials.AllowEmptyPass {
		t.Fatalf("AllowEmptyPass = %v, want false", plan.Credentials.AllowEmptyPass)
	}
	if plan.Credentials.ExpansionProfile != "static_basic" {
		t.Fatalf("ExpansionProfile = %q, want %q", plan.Credentials.ExpansionProfile, "static_basic")
	}
	if plan.Execution.ConcurrencyValue != 10 {
		t.Fatalf("ConcurrencyValue = %d, want %d", plan.Execution.ConcurrencyValue, 10)
	}
	if plan.Execution.TimeoutSeconds != 2 {
		t.Fatalf("TimeoutSeconds = %d, want %d", plan.Execution.TimeoutSeconds, 2)
	}
	if plan.Results.CredentialSuccessType != "credential_valid" {
		t.Fatalf("CredentialSuccessType = %q, want %q", plan.Results.CredentialSuccessType, "credential_valid")
	}
	if plan.Results.EvidenceProfile != "snmp_basic" {
		t.Fatalf("EvidenceProfile = %q, want %q", plan.Results.EvidenceProfile, "snmp_basic")
	}
}

func TestCompileConsumesUnauthorizedOnlyMetadataFields(t *testing.T) {
	t.Parallel()

	spec := metadata.Spec{
		Name: "memcached",
		Capabilities: metadata.Capabilities{
			Credential:   false,
			Unauthorized: true,
		},
		PolicyTags: metadata.PolicyTags{
			LockoutRisk: "low",
			AuthFamily:  "none",
			Transport:   "tcp",
		},
		Dictionary: metadata.Dictionary{
			PasswordSource:     "",
			AllowEmptyUsername: false,
			AllowEmptyPassword: false,
			ExpansionProfile:   "none",
		},
		Results: metadata.ResultProfile{
			UnauthorizedSuccessType: "unauthorized_access",
			EvidenceProfile:         "memcached_basic",
		},
	}

	plan := Compile(spec, CompileInput{
		Target:             "demo",
		IP:                 "127.0.0.1",
		Port:               11211,
		EnableUnauthorized: true,
	})

	if !reflect.DeepEqual(plan.Capabilities, []Capability{CapabilityUnauthorized}) {
		t.Fatalf("Capabilities = %v, want %v", plan.Capabilities, []Capability{CapabilityUnauthorized})
	}
	if plan.Credentials.Source != CredentialSourceBuiltin {
		t.Fatalf("Source = %q, want %q", plan.Credentials.Source, CredentialSourceBuiltin)
	}
	if len(plan.Credentials.Dictionaries) != 0 {
		t.Fatalf("Dictionaries = %v, want empty", plan.Credentials.Dictionaries)
	}
	if plan.Credentials.AllowEmptyUser {
		t.Fatalf("AllowEmptyUser = %v, want false", plan.Credentials.AllowEmptyUser)
	}
	if plan.Credentials.AllowEmptyPass {
		t.Fatalf("AllowEmptyPass = %v, want false", plan.Credentials.AllowEmptyPass)
	}
	if plan.Credentials.ExpansionProfile != "none" {
		t.Fatalf("ExpansionProfile = %q, want %q", plan.Credentials.ExpansionProfile, "none")
	}
	if plan.Results.UnauthorizedSuccessType != "unauthorized_access" {
		t.Fatalf("UnauthorizedSuccessType = %q, want %q", plan.Results.UnauthorizedSuccessType, "unauthorized_access")
	}
	if plan.Results.EvidenceProfile != "memcached_basic" {
		t.Fatalf("EvidenceProfile = %q, want %q", plan.Results.EvidenceProfile, "memcached_basic")
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
			PasswordSource:     "redis",
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
