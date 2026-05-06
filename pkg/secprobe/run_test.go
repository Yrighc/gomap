package secprobe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestRunWithRegistryRoutesCandidateToUnauthorizedProber(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}

	want := SecurityResult{
		Target:      "demo",
		ResolvedIP:  "127.0.0.1",
		Port:        6379,
		Service:     "redis",
		ProbeKind:   ProbeKindUnauthorized,
		FindingType: FindingTypeUnauthorizedAccess,
		Success:     true,
		Evidence:    "INFO returned redis_version",
	}
	if got := result.Results[0]; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected unauthorized result %+v, got %+v", want, got)
	}
}

func TestRunWithRegistrySkipsUnauthorizedProbeWhenDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
		},
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Error != "unsupported protocol" {
		t.Fatalf("expected unsupported protocol when unauth disabled, got %+v", got)
	}
	if got.ProbeKind != ProbeKindCredential {
		t.Fatalf("expected public probe kind to keep credential default when unauth disabled, got %+v", got)
	}
	if got.FindingType != FindingTypeCredentialValid {
		t.Fatalf("expected public finding type to keep credential default when unauth disabled, got %+v", got)
	}
}

func TestRunWithRegistryCanceledUnauthorizedCandidateUsesUnauthorizedDefaults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
	})

	result := RunWithRegistry(ctx, registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind for canceled result, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type for canceled result, got %+v", got)
	}
	if got.Error == "" {
		t.Fatalf("expected canceled result to carry context error, got %+v", got)
	}
}

func TestRunWithRegistryFallsBackToUnauthorizedWhenCredentialSetupFails(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-credential",
		kind:    ProbeKindCredential,
		service: "redis",
	})
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		DictDir:            filepath.Join(t.TempDir(), "missing"),
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected unauthorized fallback success, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind after credential setup failure, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type after credential setup failure, got %+v", got)
	}
}

func TestRunWithRegistryPrefersUnauthorizedBeforeCredentialWhenBothSucceed(t *testing.T) {
	registry := NewRegistry()

	credential := &stubKindedProber{
		name:    "redis-credential",
		kind:    ProbeKindCredential,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindCredential,
			FindingType: FindingTypeCredentialValid,
			Success:     true,
			Username:    "default",
			Password:    "default",
		},
	}
	unauthorized := &stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	}
	registry.Register(credential)
	registry.Register(unauthorized)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		Credentials:        []Credential{{Username: "ignored", Password: "ignored"}},
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized result to win when both probes could succeed, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", got)
	}
	if credential.callCount != 0 {
		t.Fatalf("expected credential prober to stay idle after unauthorized success, got %d calls", credential.callCount)
	}
	if unauthorized.callCount != 1 {
		t.Fatalf("expected unauthorized prober to run first exactly once, got %d calls", unauthorized.callCount)
	}
}

func TestRunWithRegistryFallsBackToCredentialAfterUnauthorizedFailure(t *testing.T) {
	registry := NewRegistry()

	unauthorized := &stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Error:       "authentication required",
		},
	}
	credential := &stubKindedProber{
		name:    "redis-credential",
		kind:    ProbeKindCredential,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindCredential,
			FindingType: FindingTypeCredentialValid,
			Success:     true,
			Username:    "admin",
			Password:    "admin",
		},
	}
	registry.Register(credential)
	registry.Register(unauthorized)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		Credentials:        []Credential{{Username: "admin", Password: "admin"}},
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected credential fallback success after unauthorized failure, got %+v", got)
	}
	if got.ProbeKind != ProbeKindCredential {
		t.Fatalf("expected credential result after unauthorized failure, got %+v", got)
	}
	if unauthorized.callCount != 1 || credential.callCount != 1 {
		t.Fatalf("expected unauthorized then credential exactly once, got unauthorized=%d credential=%d", unauthorized.callCount, credential.callCount)
	}
}

func TestRunWithRegistryCountsMissingCredentialsAsFailed(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "customsvc-credential",
		kind:    ProbeKindCredential,
		service: "customsvc",
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "customsvc",
	}}, CredentialProbeOptions{
		DictDir: filepath.Join(t.TempDir(), "missing"),
	})

	if result.Meta.Failed != 1 {
		t.Fatalf("expected missing credentials to count as failed, got %+v", result.Meta)
	}
	if result.Meta.Skipped != 0 {
		t.Fatalf("expected missing credentials not to count as skipped, got %+v", result.Meta)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Error == "" {
		t.Fatalf("expected missing credentials result to keep error detail, got %+v", result.Results[0])
	}
}

func TestRunWithRegistryPreservesPublicProberCredentialBatchContract(t *testing.T) {
	registry := NewRegistry()
	prober := &observingPublicProber{
		name:    "customsvc",
		service: "customsvc",
	}
	registry.Register(prober)

	opts := CredentialProbeOptions{
		Timeout:            3 * time.Second,
		StopOnSuccess:      false,
		EnableUnauthorized: true,
		DictDir:            "/tmp/dicts",
		Credentials: []Credential{
			{Username: "a", Password: "1"},
			{Username: "b", Password: "2"},
		},
	}

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "customsvc",
	}}, opts)

	if len(result.Results) != 1 || !result.Results[0].Success {
		t.Fatalf("expected public prober success, got %+v", result)
	}
	if prober.calls != 1 {
		t.Fatalf("expected public prober to be called once, got %d", prober.calls)
	}
	if prober.lastCredCount != 2 {
		t.Fatalf("expected public prober to receive full credential batch, got %d", prober.lastCredCount)
	}
	wantOpts := opts
	wantOpts.Concurrency = 10
	if !reflect.DeepEqual(prober.lastOpts, wantOpts) {
		t.Fatalf("expected public prober to receive defaulted opts, got %+v want %+v", prober.lastOpts, wantOpts)
	}
}

func TestRunWithRegistryCoreProberContinuesWhenStopOnSuccessDisabled(t *testing.T) {
	registry := NewRegistry()
	prober := &observingCoreProber{name: "coresvc", service: "coresvc"}
	registry.registerCoreProber(prober)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "coresvc",
	}}, CredentialProbeOptions{
		StopOnSuccess: false,
		Credentials: []Credential{
			{Username: "a", Password: "1"},
			{Username: "b", Password: "2"},
		},
	})

	if len(result.Results) != 1 || !result.Results[0].Success {
		t.Fatalf("expected core-backed success, got %+v", result)
	}
	if prober.calls != 2 {
		t.Fatalf("expected core-backed loop to continue after success, got %d calls", prober.calls)
	}
	if result.Results[0].Username != "b" || result.Results[0].Password != "2" {
		t.Fatalf("expected last success to surface when stop is disabled, got %+v", result.Results[0])
	}
}

func TestRunWithRegistryPrefersAtomicCredentialPluginOverLegacyCoreProber(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicCredential("ssh", stubAtomicAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    "root",
			Password:    "password",
			FindingType: result.FindingTypeCredentialValid,
			Evidence:    "atomic ssh auth",
		}}
	}))
	coreProber := &observingCoreProber{name: "ssh", service: "ssh"}
	registry.registerCoreProber(coreProber)

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{
		StopOnSuccess: true,
		Credentials:   []Credential{{Username: "root", Password: "password"}},
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic credential success, got %+v", out)
	}
	if out.Results[0].Evidence != "atomic ssh auth" {
		t.Fatalf("expected atomic evidence, got %+v", out.Results[0])
	}
	if coreProber.calls != 0 {
		t.Fatalf("expected legacy core prober to stay idle, got %d calls", coreProber.calls)
	}
}

func TestRunWithRegistryUsesAtomicCredentialPathForBuiltinFTP(t *testing.T) {
	registry := NewRegistry()

	var calls int32
	registry.RegisterAtomicCredential("ftp", stubAtomicAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		atomic.AddInt32(&calls, 1)
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    "admin",
			Password:    "admin",
			FindingType: result.FindingTypeCredentialValid,
			Evidence:    "FTP authentication succeeded",
		}}
	}))
	coreProber := &observingCoreProber{name: "ftp", service: "ftp"}
	registry.registerCoreProber(coreProber)

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target: "demo", ResolvedIP: "127.0.0.1", Port: 21, Service: "ftp",
	}}, CredentialProbeOptions{
		Credentials:   []Credential{{Username: "admin", Password: "admin"}},
		StopOnSuccess: true,
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic success, got %+v", out)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly one atomic attempt, got %d", calls)
	}
	if coreProber.calls != 0 {
		t.Fatalf("expected legacy core prober to stay idle, got %d calls", coreProber.calls)
	}
}

func TestRunWithRegistryPrefersAtomicUnauthorizedPluginOverLegacyCoreProber(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicUnauthorized("redis", stubAtomicUnauthorizedChecker(func(context.Context, strategy.Target) registrybridge.Attempt {
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			FindingType: result.FindingTypeUnauthorizedAccess,
			Evidence:    "atomic redis unauth",
		}}
	}))
	coreProber := &observingCoreUnauthorizedProber{name: "redis-unauthorized", service: "redis"}
	registry.registerCoreProber(coreProber)

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic unauthorized success, got %+v", out)
	}
	if out.Results[0].Evidence != "atomic redis unauth" {
		t.Fatalf("expected atomic evidence, got %+v", out.Results[0])
	}
	if coreProber.calls != 0 {
		t.Fatalf("expected legacy unauthorized core prober to stay idle, got %d calls", coreProber.calls)
	}
}

func TestRunWithRegistrySupportsAtomicOnlyCredentialPlugin(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicCredential("atomicsvc", stubAtomicAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    "root",
			Password:    "password",
			FindingType: result.FindingTypeCredentialValid,
			Evidence:    "atomic only auth",
		}}
	}))

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "atomicsvc",
	}}, CredentialProbeOptions{
		StopOnSuccess: true,
		Credentials:   []Credential{{Username: "root", Password: "password"}},
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic-only success, got %+v", out)
	}
	if out.Results[0].Evidence != "atomic only auth" {
		t.Fatalf("expected atomic-only evidence, got %+v", out.Results[0])
	}
}

func TestRunWithRegistryPassesTimeoutToAtomicCredentialPlugin(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicCredential("atomicsvc", stubAtomicAuthenticator(func(ctx context.Context, _ strategy.Target, _ strategy.Credential) registrybridge.Attempt {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("expected atomic credential plugin to receive deadline")
		}
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			FindingType: result.FindingTypeCredentialValid,
			Evidence:    "deadline observed",
		}}
	}))

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       1234,
		Service:    "atomicsvc",
	}}, CredentialProbeOptions{
		Timeout:       time.Second,
		StopOnSuccess: true,
		Credentials:   []Credential{{Username: "root", Password: "password"}},
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic timeout-aware success, got %+v", out)
	}
}

func TestRunUsesDefaultRegistryForRedisUnauthorized(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}}, CredentialProbeOptions{
		DictDir:            filepath.Join(t.TempDir(), "missing"),
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected redis unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected redis unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected redis unauthorized finding type via default registry, got %+v", got)
	}
}

func TestRunUsesDefaultRegistryForMongoDBUnauthorized(t *testing.T) {
	container := testutil.StartMongoDBNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected mongodb unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected mongodb unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected mongodb unauthorized finding type via default registry, got %+v", got)
	}
}

func TestRunUsesDefaultRegistryForMongoDBCredentialAfterUnauthorizedFailure(t *testing.T) {
	container := testutil.StartMongoDBWithAuth(t, testutil.MongoDBConfig{
		Username: "admin",
		Password: "admin",
	})

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected mongodb credential success via default registry fallback, got %+v", got)
	}
	if got.ProbeKind != ProbeKindCredential {
		t.Fatalf("expected mongodb credential probe kind via default registry fallback, got %+v", got)
	}
	if got.FindingType != FindingTypeCredentialValid {
		t.Fatalf("expected mongodb credential finding type via default registry fallback, got %+v", got)
	}
	if got.Username == "" || got.Password == "" {
		t.Fatalf("expected mongodb credential result to include username/password, got %+v", got)
	}
}

func TestRunUsesDefaultRegistryForMemcachedUnauthorized(t *testing.T) {
	container := testutil.StartMemcachedNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "memcached",
	}}, CredentialProbeOptions{
		DictDir:            filepath.Join(t.TempDir(), "missing"),
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected memcached unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected memcached unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected memcached unauthorized finding type via default registry, got %+v", got)
	}
}

func TestRunUsesDefaultRegistryForZookeeperUnauthorized(t *testing.T) {
	container := testutil.StartZookeeperNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "zookeeper",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected zookeeper unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected zookeeper unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected zookeeper unauthorized finding type via default registry, got %+v", got)
	}
}

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

func TestRunUsesBuiltinCredentialsWhenOverridesMissing(t *testing.T) {
	registry := NewRegistry()
	prober := &stubSuccessProber{name: "ssh"}
	registry.Register(prober)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{Timeout: time.Second})

	if result.Meta.Attempted != 1 {
		t.Fatalf("expected attempted candidate, got %+v", result.Meta)
	}
	if prober.credCount == 0 {
		t.Fatal("expected builtin credentials to be loaded")
	}
	if result.Results[0].Username == "" || result.Results[0].Password == "" {
		t.Fatalf("expected result to include credential evidence, got %+v", result.Results[0])
	}
}

func TestRunWithRegistryInternalKeepsCoreOnlyStateAfterEnrichment(t *testing.T) {
	registry := NewRegistry()
	registry.registerCoreProber(coreStateProber{
		name:    "ssh-core",
		service: "ssh",
		result: core.SecurityResult{
			Service:       "ssh",
			ProbeKind:     ProbeKindCredential,
			FindingType:   FindingTypeCredentialValid,
			Success:       true,
			Stage:         core.StageConfirmed,
			FailureReason: core.FailureReasonAuthentication,
			Capabilities:  []core.Capability{core.CapabilityReadable},
			Risk:          core.RiskHigh,
		},
	})

	restore := stubCoreEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Stage = core.StageEnriched
		result.Enrichment = map[string]any{"source": "stub"}
		return result
	})
	defer restore()

	result := runWithRegistryInternal(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{
		EnableEnrichment: true,
		Credentials:      []Credential{{Username: "root", Password: "root"}},
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 internal result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if got.Stage != core.StageEnriched {
		t.Fatalf("expected stage to survive enrichment, got %+v", got)
	}
	if got.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected failure reason to be preserved, got %+v", got)
	}
	if !reflect.DeepEqual(got.Capabilities, []core.Capability{core.CapabilityReadable}) {
		t.Fatalf("expected capabilities to be preserved, got %+v", got)
	}
	if got.Risk != core.RiskHigh {
		t.Fatalf("expected risk to be preserved, got %+v", got)
	}
}

func TestRunWithRegistryZeroCandidatesKeepsNilResults(t *testing.T) {
	result := RunWithRegistry(context.Background(), NewRegistry(), nil, CredentialProbeOptions{})
	if result.Results != nil {
		t.Fatalf("expected nil results for zero candidates, got %#v", result.Results)
	}

	data, err := result.ToJSON(false)
	if err != nil {
		t.Fatalf("marshal zero-candidate result: %v", err)
	}

	var decoded struct {
		Results []SecurityResult `json:"Results"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal zero-candidate json: %v", err)
	}
	if decoded.Results != nil {
		t.Fatalf("expected JSON null results to decode as nil slice, got %#v", decoded.Results)
	}
	if string(data) != `{"Meta":{"Candidates":0,"Attempted":0,"Succeeded":0,"Failed":0,"Skipped":0},"Results":null}` {
		t.Fatalf("unexpected zero-candidate JSON: %s", string(data))
	}
}

func TestApplyDefaultsFillsCredentialProbeOptions(t *testing.T) {
	opts := CredentialProbeOptions{}
	applyDefaults(&opts)

	if opts.Concurrency != 10 {
		t.Fatalf("expected default concurrency 10, got %d", opts.Concurrency)
	}
	if opts.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout 5s, got %s", opts.Timeout)
	}
}

func TestRunUsesDictDirBeforeBuiltinCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh.txt"), []byte("custom : secret\n"), 0o600); err != nil {
		t.Fatalf("write dict file: %v", err)
	}

	registry := NewRegistry()
	prober := &stubSuccessProber{name: "ssh"}
	registry.Register(prober)

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{
		Timeout: time.Second,
		DictDir: dir,
	})

	if !result.Results[0].Success {
		t.Fatalf("expected dict-dir credentials to succeed, got %+v", result.Results[0])
	}
	if result.Results[0].Username != "custom" || result.Results[0].Password != "secret" {
		t.Fatalf("expected dict-dir credentials, got %+v", result.Results[0])
	}
}

func TestRunAccountsCanceledCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	candidates := []SecurityCandidate{
		{Target: "a", ResolvedIP: "127.0.0.1", Port: 22, Service: "ssh"},
		{Target: "b", ResolvedIP: "127.0.0.1", Port: 23, Service: "telnet"},
	}
	result := RunWithRegistry(ctx, NewRegistry(), candidates, CredentialProbeOptions{})

	if result.Meta.Candidates != len(candidates) {
		t.Fatalf("expected %d candidates, got %+v", len(candidates), result.Meta)
	}
	if len(result.Results) != len(candidates) {
		t.Fatalf("expected %d results, got %d", len(candidates), len(result.Results))
	}
	if result.Meta.Failed != len(candidates) {
		t.Fatalf("expected %d failed canceled candidates, got %+v", len(candidates), result.Meta)
	}
	for i, item := range result.Results {
		if item.Target != candidates[i].Target || item.Error == "" {
			t.Fatalf("expected canceled result for candidate %d, got %+v", i, item)
		}
	}
}

func TestRunRespectsWorkerPoolConcurrency(t *testing.T) {
	registry := NewRegistry()
	prober := &stubCountingProber{name: "ssh", pause: 40 * time.Millisecond}
	registry.Register(prober)

	candidates := make([]SecurityCandidate, 0, 8)
	for i := 0; i < 8; i++ {
		candidates = append(candidates, SecurityCandidate{
			Target:     "demo",
			ResolvedIP: "127.0.0.1",
			Port:       22,
			Service:    "ssh",
		})
	}

	result := RunWithRegistry(context.Background(), registry, candidates, CredentialProbeOptions{
		Concurrency: 2,
		Timeout:     time.Second,
		Credentials: []Credential{{Username: "admin", Password: "admin"}},
	})

	if result.Meta.Attempted != len(candidates) {
		t.Fatalf("expected %d attempts, got %+v", len(candidates), result.Meta)
	}
	if got := atomic.LoadInt32(&prober.maxActive); got > 2 {
		t.Fatalf("expected at most 2 concurrent probes, got %d", got)
	}
	if got := atomic.LoadInt32(&prober.maxActive); got < 2 {
		t.Fatalf("expected worker pool to use more than one worker, got %d", got)
	}
}

func TestDefaultRegistryRegistersAtomicCredentialCapabilities(t *testing.T) {
	r := DefaultRegistry()
	for _, candidate := range []SecurityCandidate{
		{Service: "ssh", Port: 22},
		{Service: "ftp", Port: 21},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "redis", Port: 6379},
		{Service: "telnet", Port: 23},
	} {
		if !r.hasCapability(candidate, ProbeKindCredential) {
			t.Fatalf("expected credential capability for service %q", candidate.Service)
		}
		if _, ok := r.lookupAtomicCredential(candidate); !ok {
			t.Fatalf("expected atomic credential plugin for service %q", candidate.Service)
		}
		if _, ok := r.Lookup(candidate, ProbeKindCredential); ok {
			t.Fatalf("expected credential lookup miss for service %q", candidate.Service)
		}
	}
}

type stubKindedProber struct {
	name      string
	kind      ProbeKind
	service   string
	result    SecurityResult
	callCount int
}

func (s *stubKindedProber) Name() string { return s.name }

func (s *stubKindedProber) Kind() ProbeKind { return s.kind }

func (s *stubKindedProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.service
}

func (s *stubKindedProber) Probe(context.Context, SecurityCandidate, CredentialProbeOptions, []Credential) SecurityResult {
	s.callCount++
	return s.result
}

type stubSuccessProber struct {
	name      string
	credCount int
}

func (s *stubSuccessProber) Name() string { return s.name }

func (s *stubSuccessProber) Kind() ProbeKind { return ProbeKindCredential }

func (s *stubSuccessProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s *stubSuccessProber) Probe(_ context.Context, candidate SecurityCandidate, _ CredentialProbeOptions, creds []Credential) SecurityResult {
	s.credCount = len(creds)
	result := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}

type observingPublicProber struct {
	name          string
	service       string
	calls         int
	lastCredCount int
	lastOpts      CredentialProbeOptions
}

func (p *observingPublicProber) Name() string { return p.name }

func (p *observingPublicProber) Kind() ProbeKind { return ProbeKindCredential }

func (p *observingPublicProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == p.service
}

func (p *observingPublicProber) Probe(_ context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult {
	p.calls++
	p.lastCredCount = len(creds)
	p.lastOpts = opts

	result := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   ProbeKindCredential,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}

type observingCoreProber struct {
	name    string
	service string
	calls   int
}

func (p *observingCoreProber) Name() string { return p.name }

func (p *observingCoreProber) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (p *observingCoreProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == p.service
}

func (p *observingCoreProber) Probe(_ context.Context, candidate core.SecurityCandidate, _ core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	p.calls++
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}

type observingCoreUnauthorizedProber struct {
	name    string
	service string
	calls   int
}

func (p *observingCoreUnauthorizedProber) Name() string { return p.name }

func (p *observingCoreUnauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (p *observingCoreUnauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == p.service
}

func (p *observingCoreUnauthorizedProber) Probe(_ context.Context, candidate core.SecurityCandidate, _ core.CredentialProbeOptions, _ []core.Credential) core.SecurityResult {
	p.calls++
	return core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
		Success:     true,
		Evidence:    "legacy redis unauth",
	}
}

type stubAtomicAuthenticator func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt

func (f stubAtomicAuthenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	return f(ctx, target, cred)
}

type stubAtomicUnauthorizedChecker func(context.Context, strategy.Target) registrybridge.Attempt

func (f stubAtomicUnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
	return f(ctx, target)
}

type stubCountingProber struct {
	name      string
	pause     time.Duration
	active    int32
	maxActive int32
}

func (s *stubCountingProber) Name() string { return s.name }

func (s *stubCountingProber) Kind() ProbeKind { return ProbeKindCredential }

func (s *stubCountingProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}

func (s *stubCountingProber) Probe(_ context.Context, candidate SecurityCandidate, _ CredentialProbeOptions, creds []Credential) SecurityResult {
	current := atomic.AddInt32(&s.active, 1)
	for {
		maxSeen := atomic.LoadInt32(&s.maxActive)
		if current <= maxSeen {
			break
		}
		if atomic.CompareAndSwapInt32(&s.maxActive, maxSeen, current) {
			break
		}
	}
	time.Sleep(s.pause)
	atomic.AddInt32(&s.active, -1)

	result := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
	}
	if len(creds) > 0 {
		result.Username = creds[0].Username
		result.Password = creds[0].Password
	}
	return result
}

type coreStateProber struct {
	name    string
	service string
	result  core.SecurityResult
}

func (s coreStateProber) Name() string { return s.name }

func (s coreStateProber) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (s coreStateProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == s.service
}

func (s coreStateProber) Probe(context.Context, core.SecurityCandidate, core.CredentialProbeOptions, []core.Credential) core.SecurityResult {
	return s.result
}

func stubCoreEnrichmentRunner(fn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult) func() {
	old := runEnrichment
	runEnrichment = fn
	return func() { runEnrichment = old }
}
