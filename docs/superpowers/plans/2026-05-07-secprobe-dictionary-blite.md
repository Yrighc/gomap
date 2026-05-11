# secprobe Dictionary B-lite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a minimal, explicit, and extensible credential candidate subsystem for `secprobe` that upgrades dictionary handling from static txt loading to profile-driven candidate generation with scan tiers.

**Architecture:** Add a focused `pkg/secprobe/credentials` layer between protocol metadata and the existing engine. This layer resolves protocol dictionary profile, loads credentials from `inline / dict_dir / builtin`, applies small deterministic expansions, filters by explicit scan tier (`fast/default/full`), and returns an ordered credential list that the existing engine consumes unchanged.

**Tech Stack:** Go 1.24, existing `pkg/secprobe` metadata/strategy/engine stack, embedded app assets, Go testing package

---

## File Structure

### New files

- `pkg/secprobe/credentials/types.go`
  - Internal enums and small structs for scan tier and source entries
- `pkg/secprobe/credentials/profile.go`
  - Runtime `CredentialProfile` and metadata-to-profile conversion
- `pkg/secprobe/credentials/sources.go`
  - Source loading for `inline / dict_dir / builtin`
- `pkg/secprobe/credentials/expand.go`
  - Small deterministic credential expansion rules
- `pkg/secprobe/credentials/tiers.go`
  - Tier filtering and runtime/profile tier intersection
- `pkg/secprobe/credentials/generator.go`
  - Main generation entrypoint returning ordered credentials
- `pkg/secprobe/credentials/profile_test.go`
  - Profile parsing tests
- `pkg/secprobe/credentials/expand_test.go`
  - Expansion tests
- `pkg/secprobe/credentials/generator_test.go`
  - Generator behavior tests

### Modified files

- `pkg/secprobe/metadata/spec.go`
  - Add `default_tiers` to dictionary metadata
- `pkg/secprobe/metadata/loader.go`
  - Keep normalization consistent for new metadata field
- `pkg/secprobe/strategy/plan.go`
  - Add scan profile/tier concept to runtime plan if needed for traceability
- `pkg/secprobe/strategy/planner.go`
  - Thread scan profile into plan construction
- `pkg/secprobe/run.go`
  - Replace direct dictionary loading path with credentials generator
- `pkg/secprobe/assets.go`
  - Extract builtin source reading helpers so generator can consume builtin layered inputs cleanly
- `pkg/secprobe/assets_test.go`
  - Adjust builtin credential tests if helper split changes behavior
- `pkg/secprobe/run_test.go`
  - Add integration coverage for scan tier behavior and preserved compatibility
- `pkg/secprobe/strategy/planner_test.go`
  - Add tests for scan profile propagation if plan shape changes
- `app/secprobe/protocols/*.yaml`
  - Add `default_tiers` to selected credential-capable protocols

### Files intentionally not changed

- `pkg/secprobe/engine/runner.go`
  - Engine loop stays unchanged
- `internal/secprobe/*/auth_once.go`
  - Providers stay atomic and unaware of dictionary logic
- `pkg/secprobe/template/*`
  - Unauthorized template executor is out of scope

## Task 1: Add Metadata Tier Support

**Files:**
- Modify: `pkg/secprobe/metadata/spec.go`
- Modify: `pkg/secprobe/metadata/loader.go`
- Modify: `app/secprobe/protocols/ssh.yaml`
- Modify: `app/secprobe/protocols/mysql.yaml`
- Modify: `app/secprobe/protocols/redis.yaml`
- Modify: `app/secprobe/protocols/telnet.yaml`
- Test: `pkg/secprobe/credentials/profile_test.go`

- [ ] **Step 1: Write the failing profile parsing test**

```go
package credentials

import (
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestProfileFromMetadataIncludesDefaultTiers(t *testing.T) {
	profile := ProfileFromMetadata("ssh", metadata.Dictionary{
		DefaultSources:     []string{"ssh"},
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "static_basic",
		DefaultTiers:       []string{"top", "common"},
	})

	if len(profile.DefaultTiers) != 2 {
		t.Fatalf("DefaultTiers len = %d, want 2", len(profile.DefaultTiers))
	}
	if profile.DefaultTiers[0] != TierTop || profile.DefaultTiers[1] != TierCommon {
		t.Fatalf("DefaultTiers = %v, want [top common]", profile.DefaultTiers)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe/credentials -run TestProfileFromMetadataIncludesDefaultTiers -count=1`
Expected: FAIL with missing package/file/type errors

- [ ] **Step 3: Add metadata schema support**

```go
type Dictionary struct {
	DefaultSources     []string `yaml:"default_sources"`
	AllowEmptyUsername bool     `yaml:"allow_empty_username"`
	AllowEmptyPassword bool     `yaml:"allow_empty_password"`
	ExpansionProfile   string   `yaml:"expansion_profile"`
	DefaultTiers       []string `yaml:"default_tiers"`
}
```

And normalize tiers in `pkg/secprobe/metadata/loader.go`:

```go
func normalizeSpec(spec Spec) Spec {
	spec.Name = strings.ToLower(strings.TrimSpace(spec.Name))
	spec.Aliases = normalizeStrings(spec.Aliases)
	spec.Dictionary.DefaultSources = normalizeStrings(spec.Dictionary.DefaultSources)
	spec.Dictionary.DefaultTiers = normalizeStrings(spec.Dictionary.DefaultTiers)
	spec.Templates.Unauthorized = strings.ToLower(strings.TrimSpace(spec.Templates.Unauthorized))
	return spec
}
```

- [ ] **Step 4: Add initial protocol metadata entries**

Add to selected protocol YAMLs:

```yaml
dictionary:
  default_sources:
    - ssh
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
  default_tiers:
    - top
    - common
```

For `redis`, start conservative:

```yaml
dictionary:
  default_sources:
    - redis
  allow_empty_username: false
  allow_empty_password: true
  expansion_profile: static_basic
  default_tiers:
    - top
    - common
```

- [ ] **Step 5: Run focused tests**

Run: `go test ./pkg/secprobe/metadata ./pkg/secprobe/credentials -count=1`
Expected: profile test may still fail until `ProfileFromMetadata` exists; metadata tests should compile or fail only on missing credentials package implementation

- [ ] **Step 6: Commit**

```bash
git add pkg/secprobe/metadata/spec.go pkg/secprobe/metadata/loader.go app/secprobe/protocols/ssh.yaml app/secprobe/protocols/mysql.yaml app/secprobe/protocols/redis.yaml app/secprobe/protocols/telnet.yaml pkg/secprobe/credentials/profile_test.go
git commit -m "feat(secprobe): 增加字典层级元数据声明"
```

## Task 2: Introduce Credential Profile and Scan Tier Types

**Files:**
- Create: `pkg/secprobe/credentials/types.go`
- Create: `pkg/secprobe/credentials/profile.go`
- Test: `pkg/secprobe/credentials/profile_test.go`

- [ ] **Step 1: Write the failing tier normalization test**

```go
func TestProfileFromMetadataFallsBackToDefaultTiers(t *testing.T) {
	profile := ProfileFromMetadata("mysql", metadata.Dictionary{
		DefaultSources:   []string{"mysql"},
		ExpansionProfile: "static_basic",
	})

	if len(profile.DefaultTiers) != 2 {
		t.Fatalf("DefaultTiers len = %d, want 2", len(profile.DefaultTiers))
	}
	if profile.DefaultTiers[0] != TierTop || profile.DefaultTiers[1] != TierCommon {
		t.Fatalf("DefaultTiers = %v, want [top common]", profile.DefaultTiers)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe/credentials -run TestProfileFromMetadataFallsBackToDefaultTiers -count=1`
Expected: FAIL with undefined `ProfileFromMetadata` / `TierTop`

- [ ] **Step 3: Create minimal profile implementation**

`pkg/secprobe/credentials/types.go`

```go
package credentials

type Tier string

const (
	TierTop      Tier = "top"
	TierCommon   Tier = "common"
	TierExtended Tier = "extended"
)

type ScanProfile string

const (
	ScanProfileFast    ScanProfile = "fast"
	ScanProfileDefault ScanProfile = "default"
	ScanProfileFull    ScanProfile = "full"
)
```

`pkg/secprobe/credentials/profile.go`

```go
package credentials

import "github.com/yrighc/gomap/pkg/secprobe/metadata"

type CredentialProfile struct {
	Protocol         string
	DefaultSources   []string
	ExpansionProfile string
	AllowEmptyUser   bool
	AllowEmptyPass   bool
	DefaultTiers     []Tier
}

func ProfileFromMetadata(protocol string, dict metadata.Dictionary) CredentialProfile {
	return CredentialProfile{
		Protocol:         protocol,
		DefaultSources:   append([]string(nil), dict.DefaultSources...),
		ExpansionProfile: dict.ExpansionProfile,
		AllowEmptyUser:   dict.AllowEmptyUsername,
		AllowEmptyPass:   dict.AllowEmptyPassword,
		DefaultTiers:     normalizeTiers(dict.DefaultTiers),
	}
}

func normalizeTiers(in []string) []Tier {
	if len(in) == 0 {
		return []Tier{TierTop, TierCommon}
	}

	out := make([]Tier, 0, len(in))
	seen := make(map[Tier]struct{}, len(in))
	for _, item := range in {
		tier := Tier(item)
		switch tier {
		case TierTop, TierCommon, TierExtended:
		default:
			continue
		}
		if _, ok := seen[tier]; ok {
			continue
		}
		seen[tier] = struct{}{}
		out = append(out, tier)
	}
	if len(out) == 0 {
		return []Tier{TierTop, TierCommon}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/secprobe/credentials -run 'TestProfileFromMetadata' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/credentials/types.go pkg/secprobe/credentials/profile.go pkg/secprobe/credentials/profile_test.go
git commit -m "feat(secprobe): 增加字典 profile 与扫描档位类型"
```

## Task 3: Build Basic Expansion Rules

**Files:**
- Create: `pkg/secprobe/credentials/expand.go`
- Test: `pkg/secprobe/credentials/expand_test.go`

- [ ] **Step 1: Write the failing expansion tests**

```go
package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestExpandStaticBasicAddsUsernameDerivedPasswords(t *testing.T) {
	in := []strategy.Credential{{Username: "admin", Password: "root"}}
	got := expandCredentials("static_basic", false, false, in)

	want := []strategy.Credential{
		{Username: "admin", Password: "root"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "admin123"},
		{Username: "admin", Password: "admin@123"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandCredentials() = %#v, want %#v", got, want)
	}
}

func TestExpandStaticBasicRespectsEmptyFlags(t *testing.T) {
	in := []strategy.Credential{{Username: "redis", Password: "redis"}}
	got := expandCredentials("static_basic", true, true, in)

	wantLast := []strategy.Credential{
		{Username: "", Password: "redis"},
		{Username: "redis", Password: ""},
	}
	if !reflect.DeepEqual(got[len(got)-2:], wantLast) {
		t.Fatalf("tail = %#v, want %#v", got[len(got)-2:], wantLast)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe/credentials -run 'TestExpandStaticBasic' -count=1`
Expected: FAIL with undefined `expandCredentials`

- [ ] **Step 3: Implement minimal expansion helper**

```go
package credentials

import "github.com/yrighc/gomap/pkg/secprobe/strategy"

func expandCredentials(profile string, allowEmptyUser, allowEmptyPass bool, in []strategy.Credential) []strategy.Credential {
	if profile != "static_basic" {
		return dedupe(in)
	}

	out := make([]strategy.Credential, 0, len(in)*4)
	out = append(out, in...)
	for _, cred := range in {
		if cred.Username != "" {
			out = append(out,
				strategy.Credential{Username: cred.Username, Password: cred.Username},
				strategy.Credential{Username: cred.Username, Password: cred.Username + "123"},
				strategy.Credential{Username: cred.Username, Password: cred.Username + "@123"},
			)
			if allowEmptyUser {
				out = append(out, strategy.Credential{Username: "", Password: cred.Password})
			}
			if allowEmptyPass {
				out = append(out, strategy.Credential{Username: cred.Username, Password: ""})
			}
		}
	}
	return dedupe(out)
}

func dedupe(in []strategy.Credential) []strategy.Credential {
	seen := make(map[string]struct{}, len(in))
	out := make([]strategy.Credential, 0, len(in))
	for _, cred := range in {
		key := cred.Username + "\x00" + cred.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cred)
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/secprobe/credentials -run 'TestExpandStaticBasic' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/credentials/expand.go pkg/secprobe/credentials/expand_test.go
git commit -m "feat(secprobe): 增加基础凭证变异规则"
```

## Task 4: Add Tier Resolution and Scan Profile Selection

**Files:**
- Create: `pkg/secprobe/credentials/tiers.go`
- Test: `pkg/secprobe/credentials/generator_test.go`

- [ ] **Step 1: Write the failing tier intersection tests**

```go
package credentials

import (
	"reflect"
	"testing"
)

func TestAllowedTiersForFast(t *testing.T) {
	got := allowedTiers(ScanProfileFast, []Tier{TierTop, TierCommon, TierExtended})
	want := []Tier{TierTop}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedTiers(fast) = %v, want %v", got, want)
	}
}

func TestAllowedTiersForFullDoesNotInventUndeclaredTiers(t *testing.T) {
	got := allowedTiers(ScanProfileFull, []Tier{TierTop})
	want := []Tier{TierTop}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowedTiers(full) = %v, want %v", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe/credentials -run 'TestAllowedTiers' -count=1`
Expected: FAIL with undefined `allowedTiers`

- [ ] **Step 3: Implement tier filtering**

```go
package credentials

func allowedTiers(profile ScanProfile, declared []Tier) []Tier {
	limit := map[Tier]struct{}{}
	switch profile {
	case ScanProfileFast:
		limit[TierTop] = struct{}{}
	case ScanProfileFull:
		limit[TierTop] = struct{}{}
		limit[TierCommon] = struct{}{}
		limit[TierExtended] = struct{}{}
	default:
		limit[TierTop] = struct{}{}
		limit[TierCommon] = struct{}{}
	}

	out := make([]Tier, 0, len(declared))
	for _, tier := range declared {
		if _, ok := limit[tier]; ok {
			out = append(out, tier)
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/secprobe/credentials -run 'TestAllowedTiers' -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/credentials/tiers.go pkg/secprobe/credentials/generator_test.go
git commit -m "feat(secprobe): 增加扫描档位与字典层级过滤"
```

## Task 5: Build Source Loading and Generator Entry

**Files:**
- Create: `pkg/secprobe/credentials/sources.go`
- Create: `pkg/secprobe/credentials/generator.go`
- Modify: `pkg/secprobe/assets.go`
- Test: `pkg/secprobe/credentials/generator_test.go`

- [ ] **Step 1: Write the failing generator precedence tests**

```go
package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestGenerateUsesInlineBeforeBuiltin(t *testing.T) {
	profile := CredentialProfile{
		Protocol:         "ssh",
		DefaultSources:   []string{"ssh"},
		ExpansionProfile: "",
		DefaultTiers:     []Tier{TierTop, TierCommon},
	}

	got, err := Generate(GenerateInput{
		Profile:     profile,
		ScanProfile: ScanProfileDefault,
		Inline: []strategy.Credential{
			{Username: "inline", Password: "inline"},
		},
		BuiltinLoader: func(string, Tier) ([]strategy.Credential, error) {
			return []strategy.Credential{{Username: "builtin", Password: "builtin"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{{Username: "inline", Password: "inline"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() = %#v, want %#v", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe/credentials -run TestGenerateUsesInlineBeforeBuiltin -count=1`
Expected: FAIL with undefined `Generate`

- [ ] **Step 3: Expose builtin tier-aware loader helper**

Add to `pkg/secprobe/assets.go`:

```go
func BuiltinCredentialsForTier(protocol string, tier string) ([]Credential, error) {
	name := strings.ToLower(strings.TrimSpace(protocol))
	if tier != "" {
		if data, err := appassets.SecprobeDict(filepath.Join(tier, name+".txt")); err == nil {
			return parseCredentialLines(string(data))
		}
	}
	return BuiltinCredentials(protocol)
}
```

If the current app assets API cannot read nested tier paths yet, keep the helper shape but make it gracefully fall back to current flat files for phase 1 compatibility.

- [ ] **Step 4: Implement minimal generator**

`pkg/secprobe/credentials/generator.go`

```go
package credentials

import "github.com/yrighc/gomap/pkg/secprobe/strategy"

type GenerateInput struct {
	Profile       CredentialProfile
	ScanProfile   ScanProfile
	Inline        []strategy.Credential
	DictDir       string
	DirLoader     func(string, string, Tier) ([]strategy.Credential, error)
	BuiltinLoader func(string, Tier) ([]strategy.Credential, error)
}

func Generate(in GenerateInput) ([]strategy.Credential, error) {
	if len(in.Inline) > 0 {
		return expandCredentials(in.Profile.ExpansionProfile, in.Profile.AllowEmptyUser, in.Profile.AllowEmptyPass, in.Inline), nil
	}

	tiers := allowedTiers(in.ScanProfile, in.Profile.DefaultTiers)
	if in.DictDir != "" && in.DirLoader != nil {
		creds, err := loadFromDir(in.DirLoader, in.Profile.DefaultSources, in.DictDir, tiers)
		if err == nil && len(creds) > 0 {
			return expandCredentials(in.Profile.ExpansionProfile, in.Profile.AllowEmptyUser, in.Profile.AllowEmptyPass, creds), nil
		}
	}

	creds, err := loadBuiltin(in.BuiltinLoader, in.Profile.Protocol, tiers)
	if err != nil {
		return nil, err
	}
	return expandCredentials(in.Profile.ExpansionProfile, in.Profile.AllowEmptyUser, in.Profile.AllowEmptyPass, creds), nil
}
```

- [ ] **Step 5: Run focused generator tests**

Run: `go test ./pkg/secprobe/credentials -run 'TestGenerateUsesInlineBeforeBuiltin|TestAllowedTiers' -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/secprobe/assets.go pkg/secprobe/credentials/sources.go pkg/secprobe/credentials/generator.go pkg/secprobe/credentials/generator_test.go
git commit -m "feat(secprobe): 增加凭证候选生成入口"
```

## Task 6: Integrate Generator into secprobe Run Path

**Files:**
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/strategy/plan.go`
- Modify: `pkg/secprobe/strategy/planner.go`
- Test: `pkg/secprobe/run_test.go`
- Test: `pkg/secprobe/strategy/planner_test.go`

- [ ] **Step 1: Write the failing integration test for default scan profile**

```go
func TestRunUsesGeneratedExpandedCredentials(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterAtomicCredential("ssh", stubAtomicAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) registrybridge.Attempt {
		if cred.Username == "admin" && cred.Password == "admin123" {
			return registrybridge.Attempt{Result: result.Attempt{
				Success:     true,
				Username:    cred.Username,
				Password:    cred.Password,
				FindingType: result.FindingTypeCredentialValid,
			}}
		}
		return registrybridge.Attempt{Result: result.Attempt{
			Username:  cred.Username,
			Password:  cred.Password,
			ErrorCode: result.ErrorCodeAuthentication,
		}}
	}))

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:  "127.0.0.1",
		Service: "ssh",
		Port:    22,
	}}, CredentialProbeOptions{
		Credentials: []Credential{{Username: "admin", Password: "root"}},
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("RunWithRegistry() = %#v, want success via generated credential", out.Results)
	}
	if out.Results[0].Password != "admin123" {
		t.Fatalf("Password = %q, want %q", out.Results[0].Password, "admin123")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe -run TestRunUsesGeneratedExpandedCredentials -count=1`
Expected: FAIL because inline credentials currently bypass expansion logic

- [ ] **Step 3: Thread scan profile through plan and run path**

Add to `pkg/secprobe/strategy/plan.go`:

```go
type CredentialSet struct {
	Source           CredentialSource
	InlineCount      int
	Directory        string
	Dictionaries     []string
	ExpansionProfile string
	AllowEmptyUser   bool
	AllowEmptyPass   bool
	ScanProfile      string
}
```

In `pkg/secprobe/strategy/planner.go`, set default profile:

```go
set := CredentialSet{
	Source:           CredentialSourceBuiltin,
	Dictionaries:     append([]string(nil), spec.Dictionary.DefaultSources...),
	ExpansionProfile: spec.Dictionary.ExpansionProfile,
	AllowEmptyUser:   spec.Dictionary.AllowEmptyUsername,
	AllowEmptyPass:   spec.Dictionary.AllowEmptyPassword,
	ScanProfile:      string(credentials.ScanProfileDefault),
}
```

If a public option field is needed later, keep this first pass default-only and do not widen public API yet.

- [ ] **Step 4: Replace `credentialsForCandidate` internals with generator call**

Shape target in `pkg/secprobe/run.go`:

```go
func credentialsForCandidate(protocol string, opts CredentialProbeOptions) ([]Credential, error) {
	spec, ok := LookupProtocolSpec(protocol, 0)
	if !ok {
		return CredentialsFor(protocol, opts)
	}

	profile := credentials.ProfileFromMetadata(spec.Name, metadata.Dictionary{
		DefaultSources:     append([]string(nil), spec.DictNames...),
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "",
	})
	return credentials.GenerateAsLegacy(credentials.GenerateInput{
		Profile:     profile,
		ScanProfile: credentials.ScanProfileDefault,
		Inline:      strategyCredentials(opts.Credentials),
		DictDir:     opts.DictDir,
		DirLoader:   credentials.LoadDirSource,
		BuiltinLoader: func(protocol string, tier credentials.Tier) ([]strategy.Credential, error) {
			return credentials.ToStrategy(BuiltinCredentialsForTier(protocol, string(tier)))
		},
	})
}
```

During implementation, prefer real metadata spec over back-converting from legacy `ProtocolSpec` where available.

- [ ] **Step 5: Run integration and planner tests**

Run: `go test ./pkg/secprobe ./pkg/secprobe/strategy -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/secprobe/run.go pkg/secprobe/strategy/plan.go pkg/secprobe/strategy/planner.go pkg/secprobe/run_test.go pkg/secprobe/strategy/planner_test.go
git commit -m "feat(secprobe): 接入字典候选生成链路"
```

## Task 7: Add Tiered Behavior Coverage and Compatibility Regression

**Files:**
- Modify: `pkg/secprobe/credentials/generator_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/assets_test.go`

- [ ] **Step 1: Add failing tests for scan tier semantics**

```go
func TestGenerateFastOnlyUsesTopTier(t *testing.T) {
	profile := CredentialProfile{
		Protocol:       "ssh",
		DefaultSources: []string{"ssh"},
		DefaultTiers:   []Tier{TierTop, TierCommon, TierExtended},
	}

	got, err := Generate(GenerateInput{
		Profile:     profile,
		ScanProfile: ScanProfileFast,
		BuiltinLoader: func(_ string, tier Tier) ([]strategy.Credential, error) {
			return []strategy.Credential{{Username: string(tier), Password: string(tier)}}, nil
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	want := []strategy.Credential{{Username: "top", Password: "top"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() = %#v, want %#v", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe/credentials -run TestGenerateFastOnlyUsesTopTier -count=1`
Expected: FAIL until builtin tier iteration is implemented

- [ ] **Step 3: Implement tier-aware loading order and compatibility tests**

Ensure generator walks tiers in order:

```go
for _, tier := range tiers {
	creds, err := loader(protocol, tier)
	if err != nil || len(creds) == 0 {
		continue
	}
	out = append(out, creds...)
}
```

Add regression tests that confirm:

- inline credentials still win
- dict_dir still overrides builtin
- builtin fallback still works when no higher source is present
- `no-credentials` still surfaces on missing directory and builtin miss

- [ ] **Step 4: Run full targeted test suite**

Run: `go test ./pkg/secprobe ./pkg/secprobe/credentials ./pkg/secprobe/strategy -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/credentials/generator_test.go pkg/secprobe/run_test.go pkg/secprobe/assets_test.go
git commit -m "test(secprobe): 补齐扫描档位与兼容回归覆盖"
```

## Task 8: Document the New Dictionary Behavior

**Files:**
- Modify: `docs/secprobe-protocol-extension-guide.md`
- Modify: `docs/secprobe-third-party-migration-guide.md`
- Modify: `README.md`

- [ ] **Step 1: Write doc updates describing scan profile semantics**

Add concise documentation for:

- `fast / default / full`
- explicit scan depth instead of hidden truncation
- provider behavior unchanged
- third-party integration remains API-compatible

Use this README wording block:

```markdown
- 弱口令字典扫描深度采用显式档位语义，而不是隐藏式尝试截断。
- `fast` 仅运行 `top` 层，`default` 运行 `top + common`，`full` 运行 `top + common + extended`。
- 该变更不会修改 `Run` / `RunWithRegistry` / atomic provider 的集成接口，但会影响默认候选顺序与默认扫描深度。
```

- [ ] **Step 2: Run a formatting check**

Run: `git diff --check -- README.md docs/secprobe-protocol-extension-guide.md docs/secprobe-third-party-migration-guide.md`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add README.md docs/secprobe-protocol-extension-guide.md docs/secprobe-third-party-migration-guide.md
git commit -m "docs(secprobe): 补充字典子系统扫描档位说明"
```

## Task 9: Final Verification

**Files:**
- Test only

- [ ] **Step 1: Run package-level verification**

Run: `go test ./pkg/secprobe ./pkg/secprobe/credentials ./pkg/secprobe/strategy -count=1`
Expected: PASS

- [ ] **Step 2: Run broader secprobe verification**

Run: `go test ./internal/secprobe/... ./pkg/secprobe/... -count=1`
Expected: PASS

- [ ] **Step 3: Run full repository verification if prior commands pass**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 4: Commit verification-only adjustments if needed**

```bash
git add .
git commit -m "test(secprobe): 完成字典子系统 B-lite 最终验证"
```

## Self-Review

### Spec coverage

- Scan tier semantics: covered in Tasks 1, 4, 5, 7, 8
- Metadata-driven dictionary profile: covered in Tasks 1, 2, 6
- Basic deterministic expansion: covered in Task 3
- No hidden budget truncation: covered in Tasks 4, 8
- Engine/provider compatibility: covered in Tasks 6, 7, 9

No spec sections are intentionally omitted.

### Placeholder scan

- No `TODO` / `TBD`
- No "implement later"
- Code steps include concrete snippets
- Commands include expected outcomes

### Type consistency

- `TierTop/TierCommon/TierExtended` used consistently
- `ScanProfileFast/Default/Full` used consistently
- `CredentialProfile` is the runtime metadata projection throughout the plan

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-07-secprobe-dictionary-blite.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
