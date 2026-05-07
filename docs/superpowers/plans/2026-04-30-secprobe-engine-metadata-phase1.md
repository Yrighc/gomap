# secprobe Engine/Metadata Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce the first working slice of the new `secprobe` architecture: YAML protocol metadata, `Spec -> Plan` strategy compilation, a centralized engine loop, and reference atomic plugins for Redis and SSH while keeping the current public `Run` API working.

**Architecture:** This phase adds `metadata`, `strategy`, `engine`, and `result` packages under `pkg/secprobe`, but preserves the current CLI and SDK surface by routing `Run`/`RunWithRegistry` through a compatibility bridge. Protocol YAML stays strictly declarative, the planner compiles `Spec` plus runtime options into a `Plan`, and the engine owns capability order, credential looping, and stop-on-success. Redis and SSH become the first atomic plugins; legacy protocol probers continue to work through adapters until later migration phases.

**Tech Stack:** Go, embedded app assets, YAML parsing (`gopkg.in/yaml.v3` or existing repo-approved equivalent), Go `testing`, existing `pkg/secprobe` and `internal/secprobe` packages.

---

## File Structure

### New files in this phase

- `app/secprobe/protocols/redis.yaml`
- `app/secprobe/protocols/ssh.yaml`
- `pkg/secprobe/metadata/spec.go`
- `pkg/secprobe/metadata/loader.go`
- `pkg/secprobe/metadata/loader_test.go`
- `pkg/secprobe/result/codes.go`
- `pkg/secprobe/result/types.go`
- `pkg/secprobe/strategy/plan.go`
- `pkg/secprobe/strategy/planner.go`
- `pkg/secprobe/strategy/planner_test.go`
- `pkg/secprobe/engine/runner.go`
- `pkg/secprobe/engine/runner_test.go`
- `pkg/secprobe/registry/atomic.go`
- `pkg/secprobe/registry/legacy_adapter.go`
- `internal/secprobe/ssh/auth_once.go`
- `internal/secprobe/redis/auth_once.go`
- `internal/secprobe/redis/unauthorized_once.go`

### Existing files to modify in this phase

- `app/app.go` or the current embedded asset entrypoint for `app/secprobe/protocols/*.yaml`
- `pkg/secprobe/protocol_catalog.go`
- `pkg/secprobe/default_registry.go`
- `pkg/secprobe/run.go`
- `pkg/secprobe/types.go`
- `internal/secprobe/core/types.go`
- `internal/secprobe/core/registry.go`
- `internal/secprobe/ssh/prober_test.go`
- `internal/secprobe/redis/prober_test.go`
- `pkg/secprobe/run_test.go`
- `pkg/secprobe/default_registry_test.go`
- `README.md`

### Follow-up work intentionally left out of this phase

- Full migration of every protocol to atomic plugins
- Template executor for simple unauthorized checks
- Public export of every internal execution field
- Removal of all legacy adapter code

This plan produces a working, testable slice without blocking on full protocol migration.

---

### Task 1: Add YAML Protocol Metadata and Loader

**Files:**
- Create: `app/secprobe/protocols/redis.yaml`
- Create: `app/secprobe/protocols/ssh.yaml`
- Create: `pkg/secprobe/metadata/spec.go`
- Create: `pkg/secprobe/metadata/loader.go`
- Create: `pkg/secprobe/metadata/loader_test.go`
- Modify: `app/app.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Test: `pkg/secprobe/metadata/loader_test.go`
- Test: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Write the failing metadata loader tests**

```go
package metadata

import "testing"

func TestLoadSpecsIncludesRedisAndSSHAliases(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	redis, ok := specs["redis"]
	if !ok {
		t.Fatalf("expected redis spec, got keys %v", maps.Keys(specs))
	}
	if redis.PolicyTags.LockoutRisk != "low" {
		t.Fatalf("expected redis lockout risk low, got %+v", redis.PolicyTags)
	}

	ssh, ok := specs["ssh"]
	if !ok {
		t.Fatalf("expected ssh spec, got keys %v", maps.Keys(specs))
	}
	if len(ssh.Ports) != 1 || ssh.Ports[0] != 22 {
		t.Fatalf("expected ssh port 22, got %+v", ssh.Ports)
	}
}
```

```go
package secprobe

import "testing"

func TestLookupProtocolSpecPrefersYAMLMetadata(t *testing.T) {
	spec, ok := LookupProtocolSpec("redis/tls", 6379)
	if !ok {
		t.Fatal("expected redis/tls alias to resolve")
	}
	if spec.Name != "redis" {
		t.Fatalf("expected redis spec, got %+v", spec)
	}
	if !spec.SupportsEnrichment {
		t.Fatalf("expected redis enrichment support, got %+v", spec)
	}
}
```

- [ ] **Step 2: Run the loader tests and verify they fail**

Run: `go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesRedisAndSSHAliases|TestLookupProtocolSpecPrefersYAMLMetadata' -v`

Expected: FAIL with errors like `package metadata: no Go files` or `undefined: LoadBuiltin`.

- [ ] **Step 3: Create the first protocol YAML files**

`app/secprobe/protocols/redis.yaml`

```yaml
name: redis
aliases:
  - redis/ssl
  - redis/tls
ports:
  - 6379
capabilities:
  credential: true
  unauthorized: true
  enrichment: true
policy_tags:
  lockout_risk: low
  auth_family: password
  transport: tcp
dictionary:
  default_sources:
    - redis
  allow_empty_username: true
  allow_empty_password: true
  expansion_profile: static_basic
results:
  credential_success_type: credential_valid
  unauthorized_success_type: unauthorized_access
  evidence_profile: redis_basic
```

`app/secprobe/protocols/ssh.yaml`

```yaml
name: ssh
ports:
  - 22
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: high
  auth_family: password
  transport: tcp
dictionary:
  default_sources:
    - ssh
  allow_empty_username: false
  allow_empty_password: true
  expansion_profile: user_password_basic
results:
  credential_success_type: credential_valid
  evidence_profile: ssh_basic
```

- [ ] **Step 4: Implement spec types and the built-in loader**

`pkg/secprobe/metadata/spec.go`

```go
package metadata

type Spec struct {
	Name         string        `yaml:"name"`
	Aliases      []string      `yaml:"aliases"`
	Ports        []int         `yaml:"ports"`
	Capabilities Capabilities  `yaml:"capabilities"`
	PolicyTags   PolicyTags    `yaml:"policy_tags"`
	Dictionary   Dictionary    `yaml:"dictionary"`
	Results      ResultProfile `yaml:"results"`
}

type Capabilities struct {
	Credential   bool `yaml:"credential"`
	Unauthorized bool `yaml:"unauthorized"`
	Enrichment   bool `yaml:"enrichment"`
}

type PolicyTags struct {
	LockoutRisk string `yaml:"lockout_risk"`
	AuthFamily  string `yaml:"auth_family"`
	Transport   string `yaml:"transport"`
}

type Dictionary struct {
	DefaultSources     []string `yaml:"default_sources"`
	AllowEmptyUsername bool     `yaml:"allow_empty_username"`
	AllowEmptyPassword bool     `yaml:"allow_empty_password"`
	ExpansionProfile   string   `yaml:"expansion_profile"`
}

type ResultProfile struct {
	CredentialSuccessType   string `yaml:"credential_success_type"`
	UnauthorizedSuccessType string `yaml:"unauthorized_success_type"`
	EvidenceProfile         string `yaml:"evidence_profile"`
}
```

`pkg/secprobe/metadata/loader.go`

```go
package metadata

import (
	"fmt"
	"path/filepath"
	"strings"

	appassets "github.com/yrighc/gomap/app"
	"gopkg.in/yaml.v3"
)

func LoadBuiltin() (map[string]Spec, error) {
	files, err := appassets.SecprobeProtocolFiles()
	if err != nil {
		return nil, err
	}

	specs := make(map[string]Spec, len(files))
	for _, file := range files {
		raw, err := appassets.SecprobeProtocol(filepath.Base(file))
		if err != nil {
			return nil, err
		}
		var spec Spec
		if err := yaml.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		spec.Name = strings.ToLower(strings.TrimSpace(spec.Name))
		specs[spec.Name] = spec
	}
	return specs, nil
}
```

- [ ] **Step 5: Embed the protocol YAMLs and teach `LookupProtocolSpec` to consult them first**

Add these asset helpers to the app asset package:

```go
func SecprobeProtocolFiles() ([]string, error) { /* return embedded protocol YAML names */ }
func SecprobeProtocol(name string) ([]byte, error) { /* read embedded protocol YAML */ }
```

Update `pkg/secprobe/protocol_catalog.go` to:

```go
var builtinSpecs = sync.OnceValues(func() (map[string]metadata.Spec, error) {
	return metadata.LoadBuiltin()
})

func LookupProtocolSpec(service string, port int) (ProtocolSpec, bool) {
	token := normalizeProtocolToken(service)

	specs, err := builtinSpecs()
	if err == nil && token != "" {
		for _, spec := range specs {
			if spec.Name == token || slices.Contains(spec.Aliases, token) {
				return fromMetadataSpec(spec), true
			}
		}
	}

	return lookupLegacyProtocolSpec(service, port)
}
```

- [ ] **Step 6: Run the metadata and protocol catalog tests**

Run: `go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadSpecsIncludesRedisAndSSHAliases|TestLookupProtocolSpec' -v`

Expected: PASS with lines containing `--- PASS: TestLoadSpecsIncludesRedisAndSSHAliases` and `--- PASS: TestLookupProtocolSpecPrefersYAMLMetadata`.

- [ ] **Step 7: Commit the metadata slice**

```bash
git add app/secprobe/protocols/redis.yaml app/secprobe/protocols/ssh.yaml app/app.go pkg/secprobe/metadata pkg/secprobe/protocol_catalog.go pkg/secprobe/metadata/loader_test.go pkg/secprobe/protocol_catalog_test.go
git commit -m "feat: add secprobe protocol metadata loader"
```

---

### Task 2: Introduce Result Codes and `Spec -> Plan` Strategy Compilation

**Files:**
- Create: `pkg/secprobe/result/codes.go`
- Create: `pkg/secprobe/result/types.go`
- Create: `pkg/secprobe/strategy/plan.go`
- Create: `pkg/secprobe/strategy/planner.go`
- Create: `pkg/secprobe/strategy/planner_test.go`
- Modify: `internal/secprobe/core/types.go`
- Modify: `pkg/secprobe/assets.go`
- Modify: `pkg/secprobe/types.go`
- Test: `pkg/secprobe/strategy/planner_test.go`
- Test: `pkg/secprobe/assets_test.go`

- [ ] **Step 1: Write the failing planner tests**

```go
package strategy

import (
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestCompilePlanRedisPrefersUnauthorizedThenCredential(t *testing.T) {
	spec := metadata.Spec{
		Name: "redis",
		Capabilities: metadata.Capabilities{Credential: true, Unauthorized: true, Enrichment: true},
		PolicyTags: metadata.PolicyTags{LockoutRisk: "low"},
		Dictionary: metadata.Dictionary{DefaultSources: []string{"redis"}, AllowEmptyUsername: true, AllowEmptyPassword: true, ExpansionProfile: "static_basic"},
		Results: metadata.ResultProfile{CredentialSuccessType: "credential_valid", UnauthorizedSuccessType: "unauthorized_access", EvidenceProfile: "redis_basic"},
	}

	plan := Compile(spec, CompileInput{
		Target: "demo",
		IP: "127.0.0.1",
		Port: 6379,
		EnableUnauthorized: true,
		EnableEnrichment: true,
		StopOnSuccess: true,
		Timeout: 3 * time.Second,
	})

	if got, want := plan.Capabilities, []Capability{CapabilityUnauthorized, CapabilityCredential}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %v, want %v", got, want)
	}
	if !plan.Execution.StopOnFirstSuccess {
		t.Fatalf("expected stop on first success, got %+v", plan.Execution)
	}
}
```

- [ ] **Step 2: Run the planner tests and verify they fail**

Run: `go test ./pkg/secprobe/strategy -run TestCompilePlanRedisPrefersUnauthorizedThenCredential -v`

Expected: FAIL with `undefined: Compile` and `undefined: CapabilityUnauthorized`.

- [ ] **Step 3: Add the standard result/error code types**

`pkg/secprobe/result/codes.go`

```go
package result

type ErrorCode string

const (
	ErrorCodeAuthentication           ErrorCode = "authentication"
	ErrorCodeConnection               ErrorCode = "connection"
	ErrorCodeTimeout                  ErrorCode = "timeout"
	ErrorCodeCanceled                 ErrorCode = "canceled"
	ErrorCodeInsufficientConfirmation ErrorCode = "insufficient_confirmation"
)

type FindingType string

const (
	FindingTypeCredentialValid    FindingType = "credential_valid"
	FindingTypeUnauthorizedAccess FindingType = "unauthorized_access"
)
```

`pkg/secprobe/result/types.go`

```go
package result

type Attempt struct {
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Error       string
	ErrorCode   ErrorCode
	FindingType FindingType
}
```

- [ ] **Step 4: Add Plan and planner types**

`pkg/secprobe/strategy/plan.go`

```go
package strategy

type Capability string

const (
	CapabilityCredential   Capability = "credential"
	CapabilityUnauthorized Capability = "unauthorized"
	CapabilityEnrichment   Capability = "enrichment"
)

type Plan struct {
	Target       Target
	Capabilities []Capability
	Credentials  CredentialSet
	Execution    ExecutionPolicy
	Results      ResultPolicy
}

type Target struct {
	Host     string
	IP       string
	Port     int
	Protocol string
}

type CredentialSet struct {
	Source           string
	Dictionaries     []string
	ExpansionProfile string
	AllowEmptyUser   bool
	AllowEmptyPass   bool
}

type ExecutionPolicy struct {
	StopOnFirstSuccess bool
	ConcurrencyScope   string
	ConcurrencyValue   int
	TimeoutSeconds     int
}

type ResultPolicy struct {
	CredentialSuccessType   string
	UnauthorizedSuccessType string
	EnrichOnSuccess         bool
	EvidenceProfile         string
}
```

`pkg/secprobe/strategy/planner.go`

```go
package strategy

import "github.com/yrighc/gomap/pkg/secprobe/metadata"

type CompileInput struct {
	Target             string
	IP                 string
	Port               int
	EnableUnauthorized bool
	EnableEnrichment   bool
	StopOnSuccess      bool
	Timeout            time.Duration
}

func Compile(spec metadata.Spec, in CompileInput) Plan {
	caps := make([]Capability, 0, 3)
	if in.EnableUnauthorized && spec.Capabilities.Unauthorized {
		caps = append(caps, CapabilityUnauthorized)
	}
	if spec.Capabilities.Credential {
		caps = append(caps, CapabilityCredential)
	}
	return Plan{
		Target: Target{Host: in.Target, IP: in.IP, Port: in.Port, Protocol: spec.Name},
		Capabilities: caps,
		Credentials: CredentialSet{
			Source: "builtin",
			Dictionaries: append([]string(nil), spec.Dictionary.DefaultSources...),
			ExpansionProfile: spec.Dictionary.ExpansionProfile,
			AllowEmptyUser: spec.Dictionary.AllowEmptyUsername,
			AllowEmptyPass: spec.Dictionary.AllowEmptyPassword,
		},
		Execution: ExecutionPolicy{
			StopOnFirstSuccess: in.StopOnSuccess,
			ConcurrencyScope: "per_host",
			ConcurrencyValue: defaultConcurrency(spec.PolicyTags.LockoutRisk),
			TimeoutSeconds: int(in.Timeout.Seconds()),
		},
		Results: ResultPolicy{
			CredentialSuccessType: spec.Results.CredentialSuccessType,
			UnauthorizedSuccessType: spec.Results.UnauthorizedSuccessType,
			EnrichOnSuccess: in.EnableEnrichment && spec.Capabilities.Enrichment,
			EvidenceProfile: spec.Results.EvidenceProfile,
		},
	}
}
```

- [ ] **Step 5: Align internal result types with the new error codes**

Update `internal/secprobe/core/types.go` so `FailureReason` aliases the new result code set:

```go
type FailureReason = result.ErrorCode

const (
	FailureReasonConnection               = result.ErrorCodeConnection
	FailureReasonAuthentication           = result.ErrorCodeAuthentication
	FailureReasonTimeout                  = result.ErrorCodeTimeout
	FailureReasonCanceled                 = result.ErrorCodeCanceled
	FailureReasonInsufficientConfirmation = result.ErrorCodeInsufficientConfirmation
)
```

- [ ] **Step 6: Run the planner and assets tests**

Run: `go test ./pkg/secprobe/strategy ./pkg/secprobe -run 'TestCompilePlanRedisPrefersUnauthorizedThenCredential|TestBuiltinCredentials' -v`

Expected: PASS with `--- PASS: TestCompilePlanRedisPrefersUnauthorizedThenCredential`.

- [ ] **Step 7: Commit the planning layer**

```bash
git add pkg/secprobe/result pkg/secprobe/strategy internal/secprobe/core/types.go pkg/secprobe/assets.go pkg/secprobe/types.go pkg/secprobe/strategy/planner_test.go pkg/secprobe/assets_test.go
git commit -m "feat: add secprobe plan and result types"
```

---

### Task 3: Add the Central Engine and Legacy Adapter Bridge

**Files:**
- Create: `pkg/secprobe/engine/runner.go`
- Create: `pkg/secprobe/engine/runner_test.go`
- Create: `pkg/secprobe/registry/atomic.go`
- Create: `pkg/secprobe/registry/legacy_adapter.go`
- Modify: `internal/secprobe/core/registry.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/run_test.go`
- Test: `pkg/secprobe/engine/runner_test.go`
- Test: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing engine tests**

```go
package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestRunnerStopsCredentialLoopOnFirstSuccess(t *testing.T) {
	var attempts atomic.Int32
	plugin := stubAuthenticator(func(context.Context, strategy.Target, Credential) result.Attempt {
		n := attempts.Add(1)
		if n == 2 {
			return result.Attempt{Success: true, FindingType: result.FindingTypeCredentialValid}
		}
		return result.Attempt{Error: "bad password", ErrorCode: result.ErrorCodeAuthentication}
	})

	plan := strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Credentials: strategy.CredentialSet{Source: "inline"},
		Execution: strategy.ExecutionPolicy{StopOnFirstSuccess: true},
	}

	out := Run(context.Background(), plan, Input{
		Credentials: []Credential{{Username: "a", Password: "1"}, {Username: "a", Password: "2"}, {Username: "a", Password: "3"}},
		Authenticator: plugin,
	})

	if !out.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}
```

- [ ] **Step 2: Run the engine tests and verify they fail**

Run: `go test ./pkg/secprobe/engine -run TestRunnerStopsCredentialLoopOnFirstSuccess -v`

Expected: FAIL with `undefined: Run`.

- [ ] **Step 3: Define the atomic interfaces and legacy adapter**

`pkg/secprobe/registry/atomic.go`

```go
package registry

type CredentialAuthenticator interface {
	AuthenticateOnce(ctx context.Context, target strategy.Target, cred secprobe.Credential) result.Attempt
}

type UnauthorizedChecker interface {
	CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) result.Attempt
}

type Enricher interface {
	EnrichOnce(ctx context.Context, attempt result.Attempt) result.Attempt
}
```

`pkg/secprobe/registry/legacy_adapter.go`

```go
package registry

type LegacyCredentialAdapter struct {
	Prober core.Prober
}

func (a LegacyCredentialAdapter) AuthenticateOnce(ctx context.Context, target strategy.Target, cred secprobe.Credential) result.Attempt {
	out := a.Prober.Probe(ctx, core.SecurityCandidate{
		Target: target.Host,
		ResolvedIP: target.IP,
		Port: target.Port,
		Service: target.Protocol,
	}, core.CredentialProbeOptions{
		StopOnSuccess: true,
		Timeout: time.Second * time.Duration(targetTimeout(target)),
	}, []core.Credential{{Username: cred.Username, Password: cred.Password}})

	return result.Attempt{
		Success: out.Success,
		Username: out.Username,
		Password: out.Password,
		Evidence: out.Evidence,
		Error: out.Error,
		ErrorCode: result.ErrorCode(out.FailureReason),
		FindingType: result.FindingType(out.FindingType),
	}
}
```

- [ ] **Step 4: Implement the engine runner**

`pkg/secprobe/engine/runner.go`

```go
package engine

func Run(ctx context.Context, plan strategy.Plan, in Input) Output {
	out := Output{}

	for _, capability := range plan.Capabilities {
		switch capability {
		case strategy.CapabilityUnauthorized:
			if in.UnauthorizedChecker == nil {
				continue
			}
			attempt := in.UnauthorizedChecker.CheckUnauthorizedOnce(ctx, plan.Target)
			if attempt.Success {
				return Output{Success: true, Attempt: attempt}
			}
			out.Attempt = attempt
		case strategy.CapabilityCredential:
			if in.Authenticator == nil {
				continue
			}
			for _, cred := range in.Credentials {
				attempt := in.Authenticator.AuthenticateOnce(ctx, plan.Target, cred)
				if attempt.Success {
					return Output{Success: true, Attempt: attempt}
				}
				out.Attempt = attempt
				if isTerminal(attempt.ErrorCode) {
					return out
				}
			}
		}
	}

	return out
}
```

- [ ] **Step 5: Route the public `Run` path through the planner and engine**

Update `pkg/secprobe/run.go` to:

```go
func runWithRegistryInternal(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) core.RunResult {
	applyDefaults(&opts)
	// existing candidate loop stays
	// per candidate:
	spec, ok := metadata.Lookup(candidate.Service, candidate.Port)
	if !ok { /* keep skip behavior */ }
	plan := strategy.Compile(spec, strategy.CompileInput{ /* map opts + candidate */ })
	adapter := registry.atomicFor(candidate)
	engineOut := engine.Run(probeCtx, plan, adapter.InputFor(candidate, opts))
	// map engine output back into core.SecurityResult
}
```

- [ ] **Step 6: Run the engine and run-path tests**

Run: `go test ./pkg/secprobe/engine ./pkg/secprobe -run 'TestRunnerStopsCredentialLoopOnFirstSuccess|TestRunWithRegistry' -v`

Expected: PASS with `--- PASS: TestRunnerStopsCredentialLoopOnFirstSuccess` and existing `RunWithRegistry` tests still green.

- [ ] **Step 7: Commit the engine bridge**

```bash
git add pkg/secprobe/engine pkg/secprobe/registry pkg/secprobe/default_registry.go pkg/secprobe/run.go pkg/secprobe/run_test.go internal/secprobe/core/registry.go
git commit -m "feat: add secprobe engine and legacy adapters"
```

---

### Task 4: Migrate Redis and SSH to Atomic Plugins

**Files:**
- Create: `internal/secprobe/redis/auth_once.go`
- Create: `internal/secprobe/redis/unauthorized_once.go`
- Create: `internal/secprobe/ssh/auth_once.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `internal/secprobe/redis/prober_test.go`
- Modify: `internal/secprobe/ssh/prober_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Test: `internal/secprobe/redis/prober_test.go`
- Test: `internal/secprobe/ssh/prober_test.go`
- Test: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write failing tests for the new atomic plugins**

```go
package ssh

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(fakeDialSuccess)
	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo",
		IP: "127.0.0.1",
		Port: 22,
		Protocol: "ssh",
	}, core.Credential{Username: "root", Password: "password"})

	if !out.Success || out.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}
```

```go
package redis

func TestUnauthorizedCheckerDetectsOpenRedis(t *testing.T) {
	checker := NewUnauthorizedChecker(fakePingNoAuth)
	out := checker.CheckUnauthorizedOnce(context.Background(), strategy.Target{
		Host: "demo",
		IP: "127.0.0.1",
		Port: 6379,
		Protocol: "redis",
	})

	if !out.Success || out.FindingType != result.FindingTypeUnauthorizedAccess {
		t.Fatalf("unexpected attempt %+v", out)
	}
}
```

- [ ] **Step 2: Run the protocol tests and verify they fail**

Run: `go test ./internal/secprobe/ssh ./internal/secprobe/redis -run 'TestAuthenticatorAuthenticateOnceReturnsCredentialValid|TestUnauthorizedCheckerDetectsOpenRedis' -v`

Expected: FAIL with `undefined: NewAuthenticator` or `undefined: NewUnauthorizedChecker`.

- [ ] **Step 3: Add the new SSH and Redis atomic implementations**

`internal/secprobe/ssh/auth_once.go`

```go
package ssh

type Authenticator struct {
	dial func(network, addr string, config *gssh.ClientConfig) (*gssh.Client, error)
}

func NewAuthenticator(dial func(string, string, *gssh.ClientConfig) (*gssh.Client, error)) Authenticator {
	if dial == nil {
		dial = gssh.Dial
	}
	return Authenticator{dial: dial}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred core.Credential) result.Attempt {
	config := &gssh.ClientConfig{
		User: cred.Username,
		Auth: []gssh.AuthMethod{gssh.Password(cred.Password)},
		HostKeyCallback: gssh.InsecureIgnoreHostKey(),
	}
	client, err := a.dial("tcp", net.JoinHostPort(target.IP, strconv.Itoa(target.Port)), config)
	if err != nil {
		return result.Attempt{Error: err.Error(), ErrorCode: classifySSHError(err), FindingType: result.FindingTypeCredentialValid}
	}
	_ = client.Close()
	return result.Attempt{Success: true, Username: cred.Username, Password: cred.Password, Evidence: "SSH authentication succeeded", FindingType: result.FindingTypeCredentialValid}
}
```

`internal/secprobe/redis/unauthorized_once.go`

```go
package redis

type UnauthorizedChecker struct {
	ping func(context.Context, strategy.Target) error
}

func NewUnauthorizedChecker(ping func(context.Context, strategy.Target) error) UnauthorizedChecker {
	if ping == nil {
		ping = pingWithoutAuth
	}
	return UnauthorizedChecker{ping: ping}
}

func (c UnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) result.Attempt {
	if err := c.ping(ctx, target); err != nil {
		return result.Attempt{Error: err.Error(), ErrorCode: classifyRedisCredentialFailure(err), FindingType: result.FindingTypeUnauthorizedAccess}
	}
	return result.Attempt{Success: true, Evidence: "INFO returned redis_version", FindingType: result.FindingTypeUnauthorizedAccess}
}
```

- [ ] **Step 4: Register the new atomic plugins before the legacy adapters**

Update `pkg/secprobe/default_registry.go`:

```go
func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.RegisterAtomicCredential("ssh", sshprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("redis", redisprobe.NewAuthenticator(nil))
	r.RegisterAtomicUnauthorized("redis", redisprobe.NewUnauthorizedChecker(nil))

	// keep legacy registrations for protocols not yet migrated
	r.registerCoreProber(ftpprobe.New())
	// ...
}
```

- [ ] **Step 5: Run the protocol and registry tests**

Run: `go test ./internal/secprobe/ssh ./internal/secprobe/redis ./pkg/secprobe -run 'TestAuthenticatorAuthenticateOnceReturnsCredentialValid|TestUnauthorizedCheckerDetectsOpenRedis|TestDefaultRegistry' -v`

Expected: PASS with the new atomic plugin tests and existing registry tests still green.

- [ ] **Step 6: Commit the first atomic plugins**

```bash
git add internal/secprobe/ssh/auth_once.go internal/secprobe/redis/auth_once.go internal/secprobe/redis/unauthorized_once.go internal/secprobe/ssh/prober_test.go internal/secprobe/redis/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat: migrate ssh and redis to atomic secprobe plugins"
```

---

### Task 5: Public API Compatibility, Docs, and Regression Coverage

**Files:**
- Modify: `pkg/secprobe/types.go`
- Modify: `pkg/secprobe/run_state_test.go`
- Modify: `pkg/secprobe/scan.go`
- Modify: `README.md`
- Test: `pkg/secprobe/run_state_test.go`
- Test: `pkg/secprobe/scan_test.go`

- [ ] **Step 1: Write a regression test that public `RunResult` stays compatible**

```go
package secprobe

func TestRunResultJSONOmitsInternalExecutionFieldsAfterEngineRefactor(t *testing.T) {
	result := RunResult{
		Meta: SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
		Results: []SecurityResult{{
			Target: "demo",
			Service: "redis",
			ProbeKind: ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success: true,
			Evidence: "INFO returned redis_version",
		}},
	}

	data, err := result.ToJSON(true)
	if err != nil {
		t.Fatalf("ToJSON error = %v", err)
	}
	text := string(data)
	for _, hidden := range []string{"Stage", "SkipReason", "FailureReason", "Capabilities", "Risk"} {
		if strings.Contains(text, hidden) {
			t.Fatalf("unexpected internal field %q in JSON: %s", hidden, text)
		}
	}
}
```

- [ ] **Step 2: Run the compatibility tests and verify the current baseline**

Run: `go test ./pkg/secprobe -run 'TestRunResultJSONOmitsInternalExecutionFieldsAfterEngineRefactor|TestScan' -v`

Expected: PASS on current JSON behavior; if it fails after earlier tasks, fix the export bridge before continuing.

- [ ] **Step 3: Keep the public exports stable while wiring the new engine internals**

Update `pkg/secprobe/types.go` and `pkg/secprobe/scan.go` so the engine path still exports:

```go
type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	ProbeKind   ProbeKind
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Enrichment  map[string]any
	Error       string
}
```

Keep the internal-to-public bridge logic in `exportSecurityResult` intact, but map the new result codes into the existing `Error` field rather than adding breaking JSON fields in this phase.

- [ ] **Step 4: Document the phase-1 architecture in the README**

Add a short section to `README.md` under the `weak` architecture notes:

```md
### secprobe engine phase 1

- Protocol metadata begins moving from hard-coded catalog entries into `app/secprobe/protocols/*.yaml`
- `Run` now compiles protocol specs into a `Plan` before execution
- Redis and SSH use atomic plugins under the centralized engine path
- Legacy protocol probers remain supported through adapters during migration
```

- [ ] **Step 5: Run the targeted regression suite**

Run: `go test ./pkg/secprobe ./internal/secprobe/ssh ./internal/secprobe/redis -v`

Expected: PASS with `ok   github.com/yrighc/gomap/pkg/secprobe`, `ok   github.com/yrighc/gomap/internal/secprobe/ssh`, and `ok   github.com/yrighc/gomap/internal/secprobe/redis`.

- [ ] **Step 6: Commit the compatibility pass**

```bash
git add pkg/secprobe/types.go pkg/secprobe/run_state_test.go pkg/secprobe/scan.go pkg/secprobe/scan_test.go README.md
git commit -m "docs: document secprobe engine phase 1 compatibility"
```

---

## Self-Review Checklist

### Spec coverage

- YAML strictly declarative: covered by Task 1 metadata schema and Task 2 planner boundary.
- Strategy uniquely compiles `Spec -> Plan`: covered by Task 2.
- Engine owns execution control: covered by Task 3.
- Plugins become atomic units: covered by Task 4.
- Public API stays stable during the first slice: covered by Task 5.

### Placeholder scan

- No `TODO` or `TBD` markers appear in the steps.
- Every code-writing step includes concrete file names and code blocks.
- Every verification step includes an exact `go test` command and expected result.

### Type consistency

- Metadata type names: `Spec`, `Capabilities`, `PolicyTags`, `Dictionary`, `ResultProfile`.
- Strategy type names: `Plan`, `CompileInput`, `CapabilityCredential`, `CapabilityUnauthorized`.
- Result type names: `ErrorCodeAuthentication`, `FindingTypeCredentialValid`, `FindingTypeUnauthorizedAccess`.
- Engine input/output naming is consistent with the planner and plugin contracts.

---

## Follow-up Plans

After this phase lands, write follow-up plans for:

1. Migrating the remaining credential protocols (`ftp`, `mysql`, `postgresql`, `mssql`, `oracle`, `smtp`, `telnet`, `rdp`, `vnc`, `smb`, `snmp`, `amqp`)
2. Adding the simple unauthorized template executor
3. Removing the legacy adapter path once protocol migration is complete

