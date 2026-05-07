# secprobe Engine Phase 5 Legacy Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the remaining built-in dependence on the legacy execution path, make provider lookup metadata-driven and engine-first, and leave the old public-prober surface only as an explicit compatibility layer instead of the default builtin runtime.

**Architecture:** By the start of this phase, built-in credential protocols are atomic and `memcached` unauthorized is template-backed. Phase 5 tightens the runtime contract so candidate support, capability discovery, and provider selection are driven by metadata plus registered providers, not by implicit `core.Prober` presence. The compatibility path for externally registered public probers is isolated and renamed so “legacy” no longer sits on the hot path for built-in protocols.

**Tech Stack:** Go, `pkg/secprobe/registry.go`, `pkg/secprobe/run.go`, `pkg/secprobe/candidates.go`, `pkg/secprobe/default_registry.go`, `pkg/secprobe/registry/*`, `pkg/secprobe/result`, and Go `testing`.

---

## Scope Decomposition

In scope:

- move built-in capability checks off implicit `lookupCore(...)` fallback
- centralize runtime provider selection order
- isolate public-prober compatibility adapters behind explicit naming
- remove dead built-in fallback branches in `run.go`
- update documentation and tests to match the cleaned execution model

Out of scope:

- removing `Registry.Register(...)` from the public API
- removing code-backed unauthorized logic for `zookeeper`
- changing the external JSON result contract
- introducing new protocol functionality

---

## File Map

### Runtime/provider routing

- Modify: `pkg/secprobe/registry.go`
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/candidates.go`
- Modify: `pkg/secprobe/default_registry.go`

### Compatibility adapter isolation

- Delete: `pkg/secprobe/registry/legacy_adapter.go`
- Create: `pkg/secprobe/registry/public_prober_adapter.go`
- Create: `pkg/secprobe/registry/public_prober_adapter_test.go`

### Regression coverage

- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/run_state_test.go`
- Modify: `README.md`

---

## Task 1: Lock the Provider-First Cleanup Contract with Failing Tests

**Files:**
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Add a failing candidate-selection test proving built-ins should not require core probers**

Extend `pkg/secprobe/candidates_test.go`:

```go
func TestBuildCandidatesWithRegistryIncludesBuiltinAtomicProtocolWithoutCoreFallback(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target: "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 21, Open: true, Service: "ftp"},
		},
	}

	r := NewRegistry()
	r.RegisterAtomicCredential("ftp", stubAtomicCandidateAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		return registrybridge.Attempt{Result: result.Attempt{Success: true, FindingType: result.FindingTypeCredentialValid}}
	}))

	candidates := buildCandidatesWithRegistry(res, CredentialProbeOptions{}, r)
	if len(candidates) != 1 || candidates[0].Service != "ftp" {
		t.Fatalf("expected ftp candidate through provider-first support detection, got %#v", candidates)
	}
}
```

- [ ] **Step 2: Add a failing runtime test that built-in execution no longer enters the legacy branch**

Extend `pkg/secprobe/run_test.go`:

```go
func TestRunWithRegistryBuiltinAtomicProtocolSkipsLegacyCompatibilityBranch(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicCredential("ftp", stubAtomicAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    "admin",
			Password:    "admin",
			FindingType: result.FindingTypeCredentialValid,
		}}
	}))

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target: "demo", ResolvedIP: "127.0.0.1", Port: 21, Service: "ftp",
	}}, CredentialProbeOptions{
		Credentials: []Credential{{Username: "admin", Password: "admin"}},
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected builtin atomic success, got %+v", out)
	}
}
```

- [ ] **Step 3: Add a default-registry assertion that only remaining built-in code-backed unauthorized protocols use core registration**

Extend `pkg/secprobe/default_registry_test.go`:

```go
func TestDefaultRegistryLeavesOnlyZookeeperOnBuiltinCoreUnauthorizedPath(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "ftp", Port: 21}); !ok {
		t.Fatal("expected ftp atomic credential plugin")
	}
	if _, ok := r.lookupAtomicUnauthorized(SecurityCandidate{Service: "memcached", Port: 11211}); !ok {
		t.Fatal("expected memcached atomic unauthorized checker")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "zookeeper", Port: 2181}, ProbeKindUnauthorized); !ok {
		t.Fatal("expected zookeeper compatibility prober to remain")
	}
}
```

- [ ] **Step 4: Run the focused failing baseline**

Run:

```bash
go test ./pkg/secprobe -run 'TestBuildCandidatesWithRegistryIncludesBuiltinAtomicProtocolWithoutCoreFallback|TestRunWithRegistryBuiltinAtomicProtocolSkipsLegacyCompatibilityBranch|TestDefaultRegistryLeavesOnlyZookeeperOnBuiltinCoreUnauthorizedPath' -v
```

Expected: FAIL until provider-first lookup is made explicit and the built-in routing no longer depends on the old branch structure.

- [ ] **Step 5: Commit the failing cleanup baseline**

```bash
git add pkg/secprobe/candidates_test.go pkg/secprobe/default_registry_test.go pkg/secprobe/run_test.go
git commit -m "test(secprobe): 锁定 phase5 provider-first 清理基线"
```

---

## Task 2: Make Capability Discovery and Runtime Routing Provider-First

**Files:**
- Modify: `pkg/secprobe/registry.go`
- Modify: `pkg/secprobe/candidates.go`
- Modify: `pkg/secprobe/run.go`

- [ ] **Step 1: Introduce explicit provider lookup helpers in `Registry`**

Update `pkg/secprobe/registry.go` with helpers that separate built-in provider lookup from compatibility lookup:

```go
func (r *Registry) hasBuiltinProvider(candidate SecurityCandidate, kind ProbeKind) bool {
	switch kind {
	case ProbeKindCredential:
		_, ok := r.lookupAtomicCredential(candidate)
		return ok
	case ProbeKindUnauthorized:
		_, ok := r.lookupAtomicUnauthorized(candidate)
		return ok
	default:
		return false
	}
}

func (r *Registry) hasCompatibilityProber(candidate SecurityCandidate, kind ProbeKind) bool {
	_, ok := r.lookupCore(candidate, kind)
	return ok
}
```

Then rewrite `hasCapability(...)` to check builtin providers first and only fall back to compatibility probers when needed.

- [ ] **Step 2: Remove the implicit “legacy public prober” branch from the built-in run path**

Refactor `pkg/secprobe/run.go` so `probeCandidate(...)` uses provider lookup in this order:

1. atomic unauthorized / template-backed unauthorized
2. atomic credential
3. compatibility public-prober adapter only if no builtin provider exists

The simplified shape should be:

```go
func probeCandidate(ctx context.Context, registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) (core.SecurityResult, probeStatus) {
	hasCredential := registry.hasCapability(candidate, ProbeKindCredential)
	hasUnauthorized := registry.hasCapability(candidate, ProbeKindUnauthorized)

	plan, ok := compilePlanForCandidate(candidate, opts, hasCredential, hasUnauthorized)
	if !ok {
		result := defaultResultForCandidate(registry, candidate, opts)
		return markSkipped(result, core.SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
	}

	runInput := engine.Input{
		Authenticator:       credentialExecutor(registry, candidate, opts.Timeout),
		UnauthorizedChecker: unauthorizedExecutor(registry, candidate, opts.Timeout),
	}
	// existing credential loader and engine.Run(...) flow stays intact
}
```

Notice the executor helpers no longer accept a builtin core prober argument.

- [ ] **Step 3: Keep candidate selection aligned with the new provider-first contract**

Update `pkg/secprobe/candidates.go` only if needed so `registrySupportsCandidate(...)` relies on the new `hasCapability(...)` semantics and does not assume core registration means builtin support.

- [ ] **Step 4: Run the focused provider-first regression suite**

Run:

```bash
go test ./pkg/secprobe -run 'TestBuildCandidatesWithRegistryIncludesBuiltinAtomicProtocolWithoutCoreFallback|TestRunWithRegistryBuiltinAtomicProtocolSkipsLegacyCompatibilityBranch|TestDefaultRegistryLeavesOnlyZookeeperOnBuiltinCoreUnauthorizedPath' -v
```

Expected: PASS with builtin routing resolved through providers before compatibility adapters.

- [ ] **Step 5: Commit the provider-first routing refactor**

```bash
git add pkg/secprobe/registry.go pkg/secprobe/candidates.go pkg/secprobe/run.go
git commit -m "refactor(secprobe): 切换为 provider-first 的运行时路由"
```

---

## Task 3: Isolate Compatibility Adapters and Remove the “Legacy” Hot-Path Naming

**Files:**
- Delete: `pkg/secprobe/registry/legacy_adapter.go`
- Create: `pkg/secprobe/registry/public_prober_adapter.go`
- Create: `pkg/secprobe/registry/public_prober_adapter_test.go`
- Modify: `pkg/secprobe/run.go`

- [ ] **Step 1: Add failing compatibility tests for externally registered public probers**

Create `pkg/secprobe/registry/public_prober_adapter_test.go`:

```go
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
```

- [ ] **Step 2: Replace `legacy_adapter.go` with explicitly named compatibility adapters**

Create `pkg/secprobe/registry/public_prober_adapter.go` by moving the current logic under new names:

```go
type PublicCredentialAdapter struct {
	Prober  core.Prober
	Timeout time.Duration
}

func (a PublicCredentialAdapter) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) Attempt {
	return probePublicOnce(ctx, a.Prober, target, a.Timeout, core.ProbeKindCredential, []core.Credential{{
		Username: cred.Username,
		Password: cred.Password,
	}})
}
```

Mirror the same change for `PublicUnauthorizedAdapter`.

- [ ] **Step 3: Point `run.go` at the renamed compatibility adapters**

Update the compatibility fallback inside executor selection:

```go
return registrybridge.PublicCredentialAdapter{
	Prober:  prober,
	Timeout: timeout,
}
```

and:

```go
return registrybridge.PublicUnauthorizedAdapter{
	Prober:  prober,
	Timeout: timeout,
}
```

- [ ] **Step 4: Run the adapter-focused regression suite**

Run:

```bash
go test ./pkg/secprobe/registry ./pkg/secprobe -run 'TestPublicProberCredentialAdapterWrapsSingleAttempt|TestRunWithRegistry' -v
```

Expected: PASS with compatibility preserved and “legacy” removed from the builtin mental model.

- [ ] **Step 5: Commit the compatibility isolation**

```bash
git add pkg/secprobe/registry/public_prober_adapter.go pkg/secprobe/registry/public_prober_adapter_test.go pkg/secprobe/run.go
git rm pkg/secprobe/registry/legacy_adapter.go
git commit -m "refactor(secprobe): 隔离公共 prober 兼容适配层"
```

---

## Task 4: Remove Dead Built-in Fallbacks and Document the Final Architecture Boundary

**Files:**
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/run_state_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `README.md`

- [ ] **Step 1: Remove dead helper branches that only existed for built-in legacy fallback**

Delete any now-unused helpers in `pkg/secprobe/run.go`, including the old builtin-only branch selectors such as `usesLegacyPublicProber(...)`, once the provider-first and compatibility adapter split is complete.

- [ ] **Step 2: Tighten regression tests around the final builtin/compatibility split**

Update `pkg/secprobe/run_state_test.go` and `pkg/secprobe/default_registry_test.go` so the assertions clearly distinguish:

- built-in protocols use provider-first execution
- external `Registry.Register(...)` probers still work through compatibility adapters
- `zookeeper` remains the only builtin code-backed unauthorized compatibility case at the end of phase 5

- [ ] **Step 3: Document the final cleaned runtime shape**

Add to `README.md`:

```md
### secprobe engine phase 5

- Built-in protocols are resolved through metadata + provider registration, not implicit legacy core-prober presence
- Public `Registry.Register(...)` compatibility remains available through explicit public-prober adapters
- The builtin hot path is now planner -> engine -> provider, with compatibility isolated off the default execution path
```

- [ ] **Step 4: Run the full secprobe regression suite**

Run:

```bash
go test ./pkg/secprobe ./pkg/secprobe/registry ./internal/secprobe/... -v
```

Expected: PASS with no builtin regression and with compatibility adapters still covering externally registered public probers.

- [ ] **Step 5: Commit the final cleanup**

```bash
git add pkg/secprobe/default_registry.go pkg/secprobe/run_state_test.go pkg/secprobe/default_registry_test.go README.md
git commit -m "refactor(secprobe): 完成 phase5 内置执行路径清理"
```

---

## Self-Review Checklist

### Spec coverage

- Built-in execution is metadata-driven and provider-first.
- Engine remains the central control point.
- Compatibility for external public probers is preserved but isolated.
- No new execution logic leaks back into YAML.

### Placeholder scan

- Every cleanup task lists the exact files and the specific runtime contract it changes.
- All delete/rename operations are explicit.
- Each phase-end verification step names a concrete `go test` command.

### Type consistency

- Provider types remain `CredentialAuthenticator` and `UnauthorizedChecker`.
- Compatibility adapters are renamed `PublicCredentialAdapter` and `PublicUnauthorizedAdapter`.
- Public secprobe API remains stable while builtin routing becomes cleaner.
