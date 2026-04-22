# secprobe v1.3 单目标稳定性增强 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `secprobe` 增加内部结构化结果状态、单目标执行链稳定性语义，以及 Redis/MongoDB unauthorized 与 SSH/Redis credential 的确认逻辑加固，同时保持 CLI 对外行为和理解成本基本不变。

**Architecture:** 继续保持 `pkg/secprobe` 统一入口，先在 `internal/secprobe/core` 增强内部状态模型，再在 `pkg/secprobe/run.go` 补齐阶段推进、跳过/失败分类和 enrichment 收口，最后对少量高价值协议做定点确认与错误分类增强。新增字段先服务于 Go 内部逻辑和测试断言，通过 `json:"-"` 保持 JSON/CLI 输出兼容。

**Tech Stack:** Go 1.24、标准库 `testing`、现有 `testcontainers` 集成测试、`go test`

---

## File Structure

- Modify: `internal/secprobe/core/types.go`
  - 增加内部结构化状态枚举与 `SecurityResult` 扩展字段
- Modify: `pkg/secprobe/types.go`
  - 对外重导出新增状态类型和常量，维持 `pkg/secprobe` 统一入口
- Create: `internal/secprobe/core/types_test.go`
  - 验证新增字段在内存中可用、在 JSON 中默认隐藏
- Modify: `pkg/secprobe/run.go`
  - 增加阶段推进、skip/failure 分类、目标级熔断边界和 enrichment 收口
- Create: `pkg/secprobe/run_state_test.go`
  - 为执行链新增状态语义测试，避免继续依赖 `Error` 文本猜逻辑
- Modify: `internal/secprobe/redis/unauthorized_prober.go`
  - 收紧 unauthorized 确认逻辑并补最小能力表达
- Modify: `internal/secprobe/mongodb/prober.go`
  - 收紧 unauthorized 确认逻辑并补最小能力表达
- Modify: `internal/secprobe/ssh/prober.go`
  - 增加认证失败/超时/取消分类，提升 credential 确认稳定性
- Modify: `internal/secprobe/redis/prober.go`
  - 增加认证失败/超时分类，提升 credential 结果准确性
- Modify: `internal/secprobe/redis/unauthorized_prober_test.go`
- Modify: `internal/secprobe/mongodb/prober_test.go`
- Modify: `internal/secprobe/ssh/prober_test.go`
- Modify: `internal/secprobe/redis/prober_test.go`
  - 覆盖高价值协议的成功、认证失败、确认成功语义
- Modify: `cmd/main_test.go`
  - 确认 CLI JSON 不暴露内部状态字段
- Modify: `README.md`
  - 补一段 `v1.3` 行为说明，强调确认逻辑增强且 CLI 参数未膨胀
- Modify: `examples/library/main.go`
  - 给 `runWeakExample` 增加注释，说明内部状态增强不会改变现有 `ToJSON` 形状

### Task 1: 结果模型与导出边界

**Files:**
- Modify: `internal/secprobe/core/types.go`
- Modify: `pkg/secprobe/types.go`
- Create: `internal/secprobe/core/types_test.go`

- [ ] **Step 1: 写结果模型的失败测试**

```go
package core

import (
	"bytes"
	"testing"
)

func TestSecurityResultKeepsInternalStateOutOfJSON(t *testing.T) {
	raw, err := (&SecurityResult{
		Target:        "demo",
		Stage:         StageConfirmed,
		SkipReason:    SkipReasonUnsupportedProtocol,
		FailureReason: FailureReasonAuthentication,
		Capabilities:  []Capability{CapabilityEnumerable, CapabilityReadable},
		Risk:          RiskMedium,
	}).ToJSON(false)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	for _, field := range []string{`"Stage"`, `"SkipReason"`, `"FailureReason"`, `"Capabilities"`, `"Risk"`} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatalf("expected %s to stay out of JSON, got %s", field, string(raw))
		}
	}
}

func TestSecurityResultCarriesStructuredStateInMemory(t *testing.T) {
	result := SecurityResult{
		Stage:         StageAttempted,
		FailureReason: FailureReasonAuthentication,
		Capabilities:  []Capability{CapabilityReadable},
	}

	if result.Stage != StageAttempted {
		t.Fatalf("expected attempted stage, got %q", result.Stage)
	}
	if result.FailureReason != FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %q", result.FailureReason)
	}
	if len(result.Capabilities) != 1 || result.Capabilities[0] != CapabilityReadable {
		t.Fatalf("expected readable capability, got %+v", result.Capabilities)
	}
}
```

- [ ] **Step 2: 运行测试确认当前失败**

Run: `go test -count=1 ./internal/secprobe/core -run 'TestSecurityResult'`

Expected: FAIL，提示 `StageConfirmed`、`SkipReasonUnsupportedProtocol`、`CapabilityReadable` 等新符号未定义，或者 `SecurityResult` 缺少对应字段。

- [ ] **Step 3: 在核心类型里增加内部状态枚举和隐藏字段**

```go
package core

type ResultStage string

const (
	StageMatched   ResultStage = "matched"
	StageAttempted ResultStage = "attempted"
	StageConfirmed ResultStage = "confirmed"
	StageEnriched  ResultStage = "enriched"
)

type SkipReason string

const (
	SkipReasonUnsupportedProtocol SkipReason = "unsupported-protocol"
	SkipReasonProbeDisabled       SkipReason = "probe-disabled"
	SkipReasonNoCredentials       SkipReason = "no-credentials"
)

type FailureReason string

const (
	FailureReasonConnection             FailureReason = "connection"
	FailureReasonAuthentication         FailureReason = "authentication"
	FailureReasonTimeout                FailureReason = "timeout"
	FailureReasonCanceled               FailureReason = "canceled"
	FailureReasonInsufficientConfirmation FailureReason = "insufficient-confirmation"
)

type Capability string

const (
	CapabilityEnumerable Capability = "enumerable"
	CapabilityReadable   Capability = "readable"
)

type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

type SecurityResult struct {
	Target        string
	ResolvedIP    string
	Port          int
	Service       string
	ProbeKind     ProbeKind
	FindingType   string
	Success       bool
	Username      string
	Password      string
	Evidence      string
	Enrichment    map[string]any
	Error         string
	Stage         ResultStage   `json:"-"`
	SkipReason    SkipReason    `json:"-"`
	FailureReason FailureReason `json:"-"`
	Capabilities  []Capability  `json:"-"`
	Risk          RiskLevel     `json:"-"`
}
```

- [ ] **Step 4: 在对外入口重导出新类型和常量**

```go
package secprobe

import "github.com/yrighc/gomap/internal/secprobe/core"

type ResultStage = core.ResultStage
type SkipReason = core.SkipReason
type FailureReason = core.FailureReason
type Capability = core.Capability
type RiskLevel = core.RiskLevel

const (
	StageMatched   = core.StageMatched
	StageAttempted = core.StageAttempted
	StageConfirmed = core.StageConfirmed
	StageEnriched  = core.StageEnriched
)

const (
	SkipReasonUnsupportedProtocol = core.SkipReasonUnsupportedProtocol
	SkipReasonProbeDisabled       = core.SkipReasonProbeDisabled
	SkipReasonNoCredentials       = core.SkipReasonNoCredentials
)

const (
	FailureReasonConnection               = core.FailureReasonConnection
	FailureReasonAuthentication           = core.FailureReasonAuthentication
	FailureReasonTimeout                  = core.FailureReasonTimeout
	FailureReasonCanceled                 = core.FailureReasonCanceled
	FailureReasonInsufficientConfirmation = core.FailureReasonInsufficientConfirmation
)

const (
	CapabilityEnumerable = core.CapabilityEnumerable
	CapabilityReadable   = core.CapabilityReadable
)

const (
	RiskLow    = core.RiskLow
	RiskMedium = core.RiskMedium
	RiskHigh   = core.RiskHigh
)
```

- [ ] **Step 5: 运行核心测试确认通过**

Run: `go test -count=1 ./internal/secprobe/core ./pkg/secprobe -run 'TestSecurityResult'`

Expected: PASS，`internal/secprobe/core` 中新增测试通过，`pkg/secprobe` 编译通过且能访问重导出常量。

- [ ] **Step 6: 提交结果模型任务**

```bash
git add internal/secprobe/core/types.go internal/secprobe/core/types_test.go pkg/secprobe/types.go
git commit -m "feat(secprobe): 增强 v1.3 结果状态模型"
```

### Task 2: 执行链阶段推进与结果归类

**Files:**
- Modify: `pkg/secprobe/run.go`
- Create: `pkg/secprobe/run_state_test.go`
- Modify: `pkg/secprobe/enrichment_test.go`

- [ ] **Step 1: 写执行链状态语义的失败测试**

```go
package secprobe

import (
	"context"
	"testing"
)

func TestRunWithRegistryMarksDisabledUnauthorizedAsSkipped(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{})

	got := result.Results[0]
	if got.SkipReason != SkipReasonProbeDisabled {
		t.Fatalf("expected probe-disabled skip reason, got %+v", got)
	}
	if got.Stage != "" {
		t.Fatalf("expected no execution stage for disabled unauth probe, got %+v", got)
	}
}

func TestRunWithRegistryMarksConfirmedAndEnrichedResult(t *testing.T) {
	original := runEnrichment
	defer func() { runEnrichment = original }()

	runEnrichment = func(_ context.Context, result SecurityResult, _ CredentialProbeOptions) SecurityResult {
		result.Enrichment = map[string]any{"mode": "test"}
		result.Stage = StageEnriched
		return result
	}

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
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	})

	got := result.Results[0]
	if got.Stage != StageEnriched {
		t.Fatalf("expected enriched stage, got %+v", got)
	}
	if got.SkipReason != "" || got.FailureReason != "" {
		t.Fatalf("expected clean success result, got %+v", got)
	}
}
```

- [ ] **Step 2: 运行执行链测试确认当前失败**

Run: `go test -count=1 ./pkg/secprobe -run 'TestRunWithRegistryMarks'`

Expected: FAIL，提示 `SkipReasonProbeDisabled`、`StageEnriched` 断言不成立，或者现有执行链没有写入阶段与归类信息。

- [ ] **Step 3: 在 `run.go` 中补状态推进和归类助手**

```go
func markMatched(result SecurityResult) SecurityResult {
	result.Stage = StageMatched
	return result
}

func markSkipped(result SecurityResult, reason SkipReason, errText string) SecurityResult {
	result.SkipReason = reason
	result.Error = errText
	return result
}

func markAttemptFailure(result SecurityResult, reason FailureReason, err error) SecurityResult {
	result.Stage = StageAttempted
	result.FailureReason = reason
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func markConfirmed(result SecurityResult) SecurityResult {
	result.Stage = StageConfirmed
	result.SkipReason = ""
	result.FailureReason = ""
	result.Error = ""
	return result
}
```

在 `probeCandidate` 中按以下顺序接入：

```go
for _, kind := range probeKindsForCandidate(opts) {
	prober, ok := registry.Lookup(candidate, kind)
	if !ok {
		if kind == ProbeKindUnauthorized && !opts.EnableUnauthorized {
			base = markSkipped(base, SkipReasonProbeDisabled, "unauthorized probe disabled")
		}
		continue
	}

	base = markMatched(base)
	// credential 读字典失败时写 SkipReasonNoCredentials
	// probe 调用前把返回结果默认推进到 attempted
	// 成功时统一走 markConfirmed
}

if attempted {
	return base, probeAttemptFailed
}
return markSkipped(base, SkipReasonUnsupportedProtocol, "unsupported protocol"), probeSkipped
```

- [ ] **Step 4: 在 enrichment 收口阶段补 `StageEnriched`**

```go
func applyEnrichment(ctx context.Context, results []SecurityResult, opts CredentialProbeOptions) []SecurityResult {
	if !opts.EnableEnrichment {
		return results
	}

	enriched := make([]SecurityResult, len(results))
	for i, result := range results {
		if !result.Success {
			enriched[i] = result
			continue
		}

		next := runEnrichment(ctx, result, opts)
		if len(next.Enrichment) > 0 {
			next.Stage = StageEnriched
		}
		enriched[i] = next
	}
	return enriched
}
```

- [ ] **Step 5: 运行执行链与 enrichment 测试**

Run: `go test -count=1 ./pkg/secprobe -run 'TestRunWithRegistry|TestApplyEnrichment'`

Expected: PASS，新增状态测试通过，原有 unauthorized / enrichment 测试不回归。

- [ ] **Step 6: 提交执行链任务**

```bash
git add pkg/secprobe/run.go pkg/secprobe/run_state_test.go pkg/secprobe/enrichment_test.go
git commit -m "feat(secprobe): 增强 v1.3 执行链状态归类"
```

### Task 3: 高价值协议定点加固

**Files:**
- Modify: `internal/secprobe/redis/unauthorized_prober.go`
- Modify: `internal/secprobe/redis/unauthorized_prober_test.go`
- Modify: `internal/secprobe/mongodb/prober.go`
- Modify: `internal/secprobe/mongodb/prober_test.go`
- Modify: `internal/secprobe/ssh/prober.go`
- Modify: `internal/secprobe/ssh/prober_test.go`
- Modify: `internal/secprobe/redis/prober.go`
- Modify: `internal/secprobe/redis/prober_test.go`

- [ ] **Step 1: 写协议级失败测试，先锁定 v1.3 要求的确认语义**

```go
func TestRedisUnauthorizedProberMarksConfirmedCapabilities(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	result := redisprobe.NewUnauthorized().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Stage != secprobe.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if len(result.Capabilities) == 0 || result.Capabilities[0] != secprobe.CapabilityEnumerable {
		t.Fatalf("expected enumerable capability, got %+v", result.Capabilities)
	}
}

func TestSSHProberClassifiesAuthenticationFailure(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "test",
		Password: "test",
		Services: []string{"ssh"},
	})

	result := sshprobe.New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("2222/tcp"),
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, []secprobe.Credential{
		{Username: "test", Password: "wrong"},
	})

	if result.FailureReason != secprobe.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
	if result.Stage != secprobe.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
}
```

- [ ] **Step 2: 运行目标协议测试确认当前失败**

Run: `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb ./internal/secprobe/ssh -run 'TestRedisUnauthorizedProberMarksConfirmedCapabilities|TestSSHProberClassifiesAuthenticationFailure|TestMySQL^$'`

Expected: FAIL，现有协议返回值尚未填充 `Stage`、`Capabilities` 或 `FailureReasonAuthentication`。

- [ ] **Step 3: 收紧 Redis / MongoDB unauthorized 的确认与能力表达**

```go
// internal/secprobe/redis/unauthorized_prober.go
result.Stage = core.StageAttempted

pingCtx, pingCancel := context.WithTimeout(ctx, opts.Timeout)
if err := client.Ping(pingCtx).Err(); err != nil {
	pingCancel()
	result.FailureReason = core.FailureReasonConnection
	result.Error = err.Error()
	return result
}
pingCancel()

infoCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
info, err := client.Info(infoCtx, "server").Result()
cancel()
if err != nil {
	result.FailureReason = classifyRedisUnauthorizedError(err)
	result.Error = err.Error()
	return result
}
if !strings.Contains(info, "redis_version:") {
	result.FailureReason = core.FailureReasonInsufficientConfirmation
	result.Error = "unable to confirm redis unauth from INFO server"
	return result
}

result.Success = true
result.Stage = core.StageConfirmed
result.Capabilities = []core.Capability{core.CapabilityEnumerable, core.CapabilityReadable}
result.Evidence = "INFO server returned redis_version without authentication"
```

```go
// internal/secprobe/mongodb/prober.go
result.Stage = core.StageAttempted

listCtx, listCancel := context.WithTimeout(ctx, opts.Timeout)
dbs, err := client.ListDatabaseNames(listCtx, map[string]any{})
listCancel()
if err != nil {
	result.FailureReason = classifyMongoUnauthorizedError(err)
	result.Error = err.Error()
	return result
}
if len(dbs) == 0 {
	result.FailureReason = core.FailureReasonInsufficientConfirmation
	result.Error = "listDatabaseNames returned no visible databases"
	return result
}

result.Success = true
result.Stage = core.StageConfirmed
result.Capabilities = []core.Capability{core.CapabilityEnumerable}
result.Evidence = "listDatabaseNames succeeded without authentication"
```

- [ ] **Step 4: 加固 SSH / Redis credential 的失败分类**

```go
// internal/secprobe/ssh/prober.go
result.Stage = core.StageAttempted

if err == nil {
	successResult.Stage = core.StageConfirmed
	successResult.FailureReason = ""
}

if errors.Is(err, context.Canceled) {
	result.FailureReason = core.FailureReasonCanceled
	return result
}
if errors.Is(err, context.DeadlineExceeded) {
	result.FailureReason = core.FailureReasonTimeout
	return result
}
if isSSHAuthenticationError(err) {
	result.FailureReason = core.FailureReasonAuthentication
} else {
	result.FailureReason = core.FailureReasonConnection
}
```

```go
// internal/secprobe/redis/prober.go
result.Stage = core.StageAttempted

if err == nil {
	successResult.Stage = core.StageConfirmed
	successResult.FailureReason = ""
}

if errors.Is(err, context.Canceled) {
	result.FailureReason = core.FailureReasonCanceled
} else if errors.Is(err, context.DeadlineExceeded) {
	result.FailureReason = core.FailureReasonTimeout
} else if strings.Contains(err.Error(), "WRONGPASS") || strings.Contains(err.Error(), "invalid username-password pair") {
	result.FailureReason = core.FailureReasonAuthentication
} else {
	result.FailureReason = core.FailureReasonConnection
}
```

- [ ] **Step 5: 运行协议测试确认通过**

Run: `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb ./internal/secprobe/ssh -v`

Expected: PASS，unauthorized 成功用例进入 `StageConfirmed`，SSH/Redis 错误口令用例进入 `FailureReasonAuthentication`。

- [ ] **Step 6: 提交协议加固任务**

```bash
git add internal/secprobe/redis/unauthorized_prober.go internal/secprobe/redis/unauthorized_prober_test.go internal/secprobe/mongodb/prober.go internal/secprobe/mongodb/prober_test.go internal/secprobe/ssh/prober.go internal/secprobe/ssh/prober_test.go internal/secprobe/redis/prober.go internal/secprobe/redis/prober_test.go
git commit -m "feat(secprobe): 加固 v1.3 高价值协议确认逻辑"
```

### Task 4: 文档、CLI 兼容与全量验证

**Files:**
- Modify: `cmd/main_test.go`
- Modify: `README.md`
- Modify: `examples/library/main.go`

- [ ] **Step 1: 写 CLI 兼容测试，锁定内部状态字段不出现在 JSON 中**

```go
func TestPortWithWeakOutputOmitsInternalStateFields(t *testing.T) {
	security := &secprobe.RunResult{
		Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
		Results: []secprobe.SecurityResult{{
			Target:        "demo",
			Service:       "redis",
			ProbeKind:     secprobe.ProbeKindUnauthorized,
			FindingType:   secprobe.FindingTypeUnauthorizedAccess,
			Success:       true,
			Stage:         secprobe.StageEnriched,
			FailureReason: secprobe.FailureReasonAuthentication,
			Capabilities:  []secprobe.Capability{secprobe.CapabilityEnumerable},
		}},
	}

	raw, err := security.ToJSON(false)
	if err != nil {
		t.Fatalf("marshal security result: %v", err)
	}
	for _, field := range []string{`"Stage"`, `"FailureReason"`, `"Capabilities"`} {
		if bytes.Contains(raw, []byte(field)) {
			t.Fatalf("expected %s to stay internal, got %s", field, string(raw))
		}
	}
}
```

- [ ] **Step 2: 运行 CLI 兼容测试确认当前通过或失败都可解释**

Run: `go test -count=1 ./cmd -run 'TestPortWithWeakOutputOmitsInternalStateFields|TestPortWithWeakWrapsAssetAndSecurityResults'`

Expected: PASS。`Task 1` 已经通过 `json:"-"` 隐藏内部状态字段，这里应作为回归保护测试稳定通过。

- [ ] **Step 3: 更新 README 和示例，说明 v1.3 行为边界**

```md
### v1.3 行为说明

- `secprobe` 内部结果模型已增强，但 CLI 输出结构保持兼容
- `weak` / `port -weak` 不新增复杂控制参数
- 成功 finding 仍以现有 `Success / Evidence / Error / Enrichment` 作为主要对外字段
```

```go
// runWeakExample 继续打印 ToJSON(true) 的兼容结果；
// v1.3 新增的 Stage / FailureReason / Capabilities 仅用于内部执行和测试，不直接暴露到 JSON。
func runWeakExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: "21,22,3306,5432,6379",
		Protocol: assetprobe.ProtocolTCP,
	})
	if err != nil {
		return err
	}

	security := secprobe.Run(
		context.Background(),
		secprobe.BuildCandidates(result, secprobe.CredentialProbeOptions{
			EnableUnauthorized: true,
			EnableEnrichment:   true,
		}),
		secprobe.CredentialProbeOptions{
			EnableUnauthorized: true,
			EnableEnrichment:   true,
		},
	)
	out, _ := security.ToJSON(true)

	fmt.Println("== Weak Example ==")
	fmt.Println(string(out))
	return nil
}
```

- [ ] **Step 4: 运行本阶段回归测试**

Run: `go test -count=1 ./cmd ./pkg/secprobe ./internal/secprobe/...`

Expected: PASS，CLI、公共执行链和协议测试全部通过。

- [ ] **Step 5: 运行全仓验证**

Run: `go test ./...`

Expected: PASS，全仓回归通过，没有因为内部字段增强破坏现有 JSON 或库接口。

- [ ] **Step 6: 提交文档与回归任务**

```bash
git add cmd/main_test.go README.md examples/library/main.go
git commit -m "docs(secprobe): 完善 v1.3 兼容性说明"
```

## Self-Review

### Spec coverage

- `Stage / SkipReason / FailureReason / Capabilities / Risk`：由 Task 1 实现
- 单目标执行链阶段推进、目标级熔断边界、有限重试收口：由 Task 2 实现
- Redis / MongoDB unauthorized 与 SSH / Redis credential 定点加固：由 Task 3 实现
- CLI 保持易用、输出兼容、文档收口：由 Task 4 实现

### Placeholder scan

- 计划中没有 `TODO`、`TBD`、`后续补` 之类占位词
- 高价值 credential 协议已在计划中明确为 `ssh` 和 `redis`
- 所有测试命令、提交命令和目标文件都已给出具体路径

### Type consistency

- 统一使用 `ResultStage` / `StageMatched` / `StageAttempted` / `StageConfirmed` / `StageEnriched`
- 统一使用 `SkipReasonUnsupportedProtocol` / `SkipReasonProbeDisabled` / `SkipReasonNoCredentials`
- 统一使用 `FailureReasonConnection` / `FailureReasonAuthentication` / `FailureReasonTimeout` / `FailureReasonCanceled` / `FailureReasonInsufficientConfirmation`
- 统一使用 `CapabilityEnumerable` / `CapabilityReadable`
