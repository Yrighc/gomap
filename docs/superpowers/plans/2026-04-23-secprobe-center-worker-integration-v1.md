# secprobe Center Worker Integration v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `center -> zvas worker -> GoMap` 打通 host 级 `secprobe` 弱口令探测链路，固定采用 `1 host + N services` 下发模型，并同时保留任务摘要、原始 findings、统一漏洞事实。

**Architecture:** 先在 GoMap `pkg/secprobe` 内补稳定请求式入口 `Scan(ctx, ScanRequest) ScanResult`，让上层只依赖 host/services 语义而不暴露内部 `SecurityCandidate` / `CredentialProbeOptions`。再在 `zvas` 内新增独立 `secprobe` route、共享 `center payload` 契约、worker engine 与 center 播种/落库逻辑，最终让 `center` 从结构化端口结果自动播种 `secprobe` unit，`worker` 本地调用 GoMap SDK 并把摘要、raw findings、`UnitVulnerability` 一并回传。

**Tech Stack:** Go 1.24、标准库 `testing`、GoMap `pkg/secprobe`、zvas `taskroute/center/worker`、PostgreSQL repo tests

---

## File Structure

- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_types.go`
  - 定义稳定的 `ScanRequest`、`ScanService`、`ScanResult`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan.go`
  - 实现 `Scan(ctx, req)`、默认值、候选映射和低层 `Run(...)` 对接
- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_test.go`
  - 覆盖请求校验、候选映射、builtin 字典模式
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/platform/contracts/scan_unit.go`
  - 增加 `SecprobeServicePayload`，作为 center -> worker 的共享 payload 契约
- Modify: `/Users/yrighc/work/hzyz/project/zvas/pkg/taskroute/task_route.go`
  - 增加 `secprobe` 路由常量、配置和 helper
- Modify: `/Users/yrighc/work/hzyz/project/zvas/pkg/taskroute/task_route_test.go`
  - 覆盖 secprobe route 解析与 site-route 隔离
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/usecase/scan_task_usecase.go`
  - 增加内置模板 `TaskTemplateSecprobe`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/usecase/scan_task_usecase_test.go`
  - 覆盖新模板的默认 stage plan
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/modules.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/secprobe_task.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/listener_test.go`
  - 覆盖 unit 规范化与 listener/process topic 对齐
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/modules.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/request.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/secprobe.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/process_test.go`
  - 覆盖 payload 解析、默认值、部分结果成功语义
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/mapper/result.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/mapper/result_test.go`
  - 覆盖摘要、raw findings、`UnitVulnerability` 映射
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/catalog.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/catalog_test.go`
  - 注册 secprobe engine / listener
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed_runtime.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed_runtime_test.go`
  - 从结构化端口结果按 host 聚合出 secprobe queued unit
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_port_structured.go`
  - 复用结构化端口结果并补 secprobe 服务筛选/聚合辅助逻辑
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_repo_postgres.go`
  - 增加 secprobe lease 时长
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_result_summary.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_result_summary_test.go`
  - 覆盖 secprobe 任务摘要
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/scan_task_record_detail_repo.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/scan_task_record_detail_repo_test.go`
  - 让 secprobe record detail 也能读取统一漏洞事实
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_vulnerability.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_vulnerability_test.go`
  - 确认 secprobe 不走 `task_unit_weak_scan_finding`，而是走 `task_unit_vulnerability`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_repo_postgres_result_test.go`
  - 覆盖 secprobe running lease 续租

### Task 1: Add the Stable GoMap `secprobe.Scan` Surface

**Files:**
- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_types.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan.go`
- Create: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_test.go`

- [ ] **Step 1: Write the failing API test**

```go
package secprobe

import (
	"context"
	"testing"
	"time"
)

func TestScanRejectsEmptyServices(t *testing.T) {
	got := Scan(context.Background(), ScanRequest{
		Target:  "192.0.2.10",
		Timeout: time.Second,
	})

	if got.Error == "" {
		t.Fatalf("expected validation error, got %+v", got)
	}
	if got.Target != "192.0.2.10" {
		t.Fatalf("expected target echoed back, got %+v", got)
	}
	if got.Meta.Candidates != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty result set on validation failure, got %+v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `(cd /Users/yrighc/work/hzyz/project/GoMap && go test -count=1 ./pkg/secprobe -run TestScanRejectsEmptyServices)`

Expected: FAIL with `undefined: ScanRequest` and `undefined: Scan`

- [ ] **Step 3: Add request/response types and the minimal entrypoint**

```go
package secprobe

import "time"

type ScanRequest struct {
	Target             string
	ResolvedIP         string
	Services           []ScanService
	Timeout            time.Duration
	Concurrency        int
	StopOnSuccess      bool
	EnableEnrichment   bool
	EnableUnauthorized bool
}

type ScanService struct {
	Port    int
	Service string
	Version string
	Banner  string
}

type ScanResult struct {
	Target     string
	ResolvedIP string
	Meta       SecurityMeta
	Results    []SecurityResult
	Error      string
}
```

```go
package secprobe

import (
	"context"
	"strings"
)

func Scan(_ context.Context, req ScanRequest) ScanResult {
	if strings.TrimSpace(req.Target) == "" {
		return ScanResult{Error: "target is required"}
	}
	if len(req.Services) == 0 {
		return ScanResult{
			Target:     req.Target,
			ResolvedIP: req.ResolvedIP,
			Error:      "services is required",
		}
	}
	return ScanResult{
		Target:     req.Target,
		ResolvedIP: req.ResolvedIP,
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `(cd /Users/yrighc/work/hzyz/project/GoMap && go test -count=1 ./pkg/secprobe -run TestScanRejectsEmptyServices)`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/GoMap add pkg/secprobe/scan_types.go pkg/secprobe/scan.go pkg/secprobe/scan_test.go
git -C /Users/yrighc/work/hzyz/project/GoMap commit -m "feat(secprobe): add stable scan request api"
```

### Task 2: Implement GoMap `Scan` Mapping and Builtin-Dictionary Execution

**Files:**
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan.go`
- Modify: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_test.go`

- [ ] **Step 1: Write the failing mapping test**

```go
func TestScanMapsServicesIntoCandidatesAndBuiltinOptions(t *testing.T) {
	restore := stubScanRunner(func(_ context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
		if len(candidates) != 2 {
			t.Fatalf("expected 2 candidates, got %d", len(candidates))
		}
		if candidates[0].Target != "demo.local" || candidates[0].ResolvedIP != "192.0.2.15" {
			t.Fatalf("unexpected first candidate: %+v", candidates[0])
		}
		if candidates[0].Service != "ssh" || candidates[1].Service != "redis" {
			t.Fatalf("expected normalized services, got %+v", candidates)
		}
		if candidates[0].Version != "OpenSSH_9.8" || candidates[1].Banner != "redis" {
			t.Fatalf("expected version/banner to flow into candidates, got %+v", candidates)
		}
		if opts.DictDir != "" || len(opts.Credentials) != 0 {
			t.Fatalf("expected builtin dictionary mode, got %+v", opts)
		}
		if !opts.StopOnSuccess || opts.EnableUnauthorized || opts.EnableEnrichment {
			t.Fatalf("unexpected options: %+v", opts)
		}
		if opts.Timeout != 3*time.Second || opts.Concurrency != 4 {
			t.Fatalf("unexpected timeout/concurrency: %+v", opts)
		}
		return RunResult{
			Meta: SecurityMeta{Candidates: 2, Attempted: 2, Succeeded: 1, Failed: 1},
			Results: []SecurityResult{{
				Target:      "demo.local",
				ResolvedIP:  "192.0.2.15",
				Port:        22,
				Service:     "ssh",
				ProbeKind:   ProbeKindCredential,
				FindingType: FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "root",
				Evidence:    "ssh auth succeeded",
			}},
		}
	})
	defer restore()

	got := Scan(context.Background(), ScanRequest{
		Target:        "demo.local",
		ResolvedIP:    "192.0.2.15",
		Timeout:       3 * time.Second,
		Concurrency:   4,
		StopOnSuccess: true,
		Services: []ScanService{
			{Port: 22, Service: "ssh?", Version: "OpenSSH_9.8"},
			{Port: 6379, Service: "redis/ssl", Banner: "redis"},
		},
	})

	if got.Error != "" || got.Meta.Candidates != 2 || len(got.Results) != 1 {
		t.Fatalf("unexpected scan result: %+v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `(cd /Users/yrighc/work/hzyz/project/GoMap && go test -count=1 ./pkg/secprobe -run TestScanMapsServicesIntoCandidatesAndBuiltinOptions)`

Expected: FAIL because `stubScanRunner` and the candidate/options mapping do not exist yet

- [ ] **Step 3: Implement mapping, defaults, and runner injection**

```go
package secprobe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

var scanRun = func(ctx context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	return Run(ctx, candidates, opts)
}

func Scan(ctx context.Context, req ScanRequest) ScanResult {
	if strings.TrimSpace(req.Target) == "" {
		return ScanResult{Error: "target is required"}
	}
	candidates, err := buildScanCandidates(req)
	if err != nil {
		return ScanResult{
			Target:     req.Target,
			ResolvedIP: req.ResolvedIP,
			Error:      err.Error(),
		}
	}
	opts := CredentialProbeOptions{
		Concurrency:        req.Concurrency,
		Timeout:            req.Timeout,
		StopOnSuccess:      req.StopOnSuccess,
		EnableEnrichment:   req.EnableEnrichment,
		EnableUnauthorized: req.EnableUnauthorized,
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	run := scanRun(ctx, candidates, opts)
	return ScanResult{
		Target:     req.Target,
		ResolvedIP: req.ResolvedIP,
		Meta:       run.Meta,
		Results:    run.Results,
	}
}

func buildScanCandidates(req ScanRequest) ([]SecurityCandidate, error) {
	if len(req.Services) == 0 {
		return nil, fmt.Errorf("services is required")
	}
	out := make([]SecurityCandidate, 0, len(req.Services))
	for _, item := range req.Services {
		if item.Port <= 0 {
			return nil, fmt.Errorf("invalid service port %d", item.Port)
		}
		service := NormalizeServiceName(item.Service, item.Port)
		if service == "" {
			return nil, fmt.Errorf("unsupported service %q on port %d", item.Service, item.Port)
		}
		out = append(out, SecurityCandidate{
			Target:     req.Target,
			ResolvedIP: req.ResolvedIP,
			Port:       item.Port,
			Service:    service,
			Version:    item.Version,
			Banner:     item.Banner,
		})
	}
	return out, nil
}

func stubScanRunner(fn func(context.Context, []SecurityCandidate, CredentialProbeOptions) RunResult) func() {
	previous := scanRun
	scanRun = fn
	return func() { scanRun = previous }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `(cd /Users/yrighc/work/hzyz/project/GoMap && go test -count=1 ./pkg/secprobe -run 'TestScan(RejectsEmptyServices|MapsServicesIntoCandidatesAndBuiltinOptions)')`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/GoMap add pkg/secprobe/scan.go pkg/secprobe/scan_test.go
git -C /Users/yrighc/work/hzyz/project/GoMap commit -m "feat(secprobe): implement scan candidate mapping"
```

### Task 3: Add the Shared secprobe Payload Contract, Route, and Task Template

**Files:**
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/platform/contracts/scan_unit.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/pkg/taskroute/task_route.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/pkg/taskroute/task_route_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/usecase/scan_task_usecase.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/usecase/scan_task_usecase_test.go`

- [ ] **Step 1: Write the failing route/template tests**

```go
func TestResolveTaskRouteForSecprobe(t *testing.T) {
	item, ok := ResolveTaskRoute(TaskTypeSecprobe, StageSecprobe)
	if !ok {
		t.Fatal("expected secprobe route")
	}
	if item.RouteCode != RouteCodeSecprobeHost || item.DefaultTopic != TopicScanSecprobeHost {
		t.Fatalf("unexpected secprobe route: %+v", item)
	}
	if IsSiteRoute(TaskTypeSecprobe, StageSecprobe) {
		t.Fatal("expected secprobe to stay out of site-route helpers")
	}
}
```

```go
func TestLookupTaskTemplateSecprobeIncludesPortScanAndSecprobe(t *testing.T) {
	template, ok := lookupTaskTemplate(TaskTemplateSecprobe)
	if !ok {
		t.Fatal("expected secprobe template")
	}
	expected := []string{taskroute.StageScopeFilter, taskroute.StagePortScan, taskroute.StageSecprobe}
	if !reflect.DeepEqual(template.DefaultStages, expected) {
		t.Fatalf("unexpected stages: %+v", template.DefaultStages)
	}
	if template.DefaultParams["stop_on_success"] != "true" {
		t.Fatalf("unexpected default params: %+v", template.DefaultParams)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./pkg/taskroute ./internal/center/usecase -run 'Test(ResolveTaskRouteForSecprobe|LookupTaskTemplateSecprobeIncludesPortScanAndSecprobe)')`

Expected: FAIL because secprobe route/template constants do not exist yet

- [ ] **Step 3: Add the shared payload type, route config, and template**

```go
package contracts

type SecprobeServicePayload struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}
```

```go
const (
	StageSecprobe            = "secprobe"
	TaskTypeSecprobe         = "secprobe"
	TaskSubtypeHostWeakAuth  = "host_weak_auth"
	TopicScanSecprobeHost    = "scan.secprobe.host"
	RouteCodeSecprobeHost    = "secprobe.host"
)
```

```go
{
	Key:           RouteCodeSecprobeHost,
	RouteCode:     RouteCodeSecprobeHost,
	Label:         "主机弱口令探测",
	Description:   "对结构化端口结果中的可支持协议执行 secprobe 弱口令探测。",
	TaskType:      TaskTypeSecprobe,
	TaskSubtype:   TaskSubtypeHostWeakAuth,
	Stage:         StageSecprobe,
	GroupCode:     GroupAttack,
	GroupOrder:    2,
	DispatchOrder: 25,
	DefaultTopic:  TopicScanSecprobeHost,
	SeedSource:    RouteSeedInputAsset,
	BudgetBucket:  RouteBudgetAttack,
}

func IsSecprobeRoute(taskType string, stage string) bool {
	item, ok := ResolveTaskRoute(taskType, stage)
	return ok && item.TaskType == TaskTypeSecprobe
}
```

```go
const (
	TaskTemplateSecprobe = "secprobe"
)

TaskTemplateSecprobe: {
	Code:                  TaskTemplateSecprobe,
	Name:                  "主机弱口令探测",
	Description:           "执行端口识别后，对 host + services 运行 GoMap secprobe。",
	Builtin:               true,
	Enabled:               true,
	DefaultStages:         []string{taskroute.StageScopeFilter, taskroute.StagePortScan, taskroute.StageSecprobe},
	DefaultPortScanMode:   "common",
	PortScanModeOptions:   portScanModeOptions("top_100", "common", "full", "custom"),
	DefaultConcurrency:    2000,
	DefaultRate:           3000,
	DefaultTimeoutMS:      2000,
	AllowPortModeOverride: true,
	AllowAdvancedOverride: true,
	DefaultParams: map[string]string{
		"timeout_ms":         "3000",
		"stop_on_success":    "true",
		"enable_enrichment":  "false",
	},
	PreviewSummary: []string{"范围过滤", "端口扫描", "主机弱口令探测"},
},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./pkg/taskroute ./internal/center/usecase -run 'Test(ResolveTaskRouteForSecprobe|LookupTaskTemplateSecprobeIncludesPortScanAndSecprobe)')`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/zvas add internal/platform/contracts/scan_unit.go pkg/taskroute/task_route.go pkg/taskroute/task_route_test.go internal/center/usecase/scan_task_usecase.go internal/center/usecase/scan_task_usecase_test.go
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "feat(zvas): add secprobe route and template"
```

### Task 4: Build the zvas Worker secprobe Listener and Request Parser

**Files:**
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/modules.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/secprobe_task.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/listener/listener_test.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/modules.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/request.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/secprobe.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/process_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/catalog.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/catalog_test.go`

- [ ] **Step 1: Write the failing listener/request tests**

```go
func TestSecprobeTaskListenerHandleNormalizesUnit(t *testing.T) {
	worker := &secprobeWorkerStub{}
	process := &secprobeProcessStub{name: secprobeProcessName, topic: secprobeTopic}
	listener, err := NewSecprobeTaskListener(worker, process)
	if err != nil {
		t.Fatalf("NewSecprobeTaskListener() error = %v", err)
	}
	unit := &contracts.ScanUnit{
		ID:        "unit-1",
		JobID:     "task-1",
		TargetKey: "192.0.2.10",
		Payload: map[string]string{
			"services_json": `[{"host":"192.0.2.10","port":22,"service":"ssh"}]`,
		},
	}
	if err := listener.Handle(context.Background(), unit); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if unit.Topic != taskroute.TopicScanSecprobeHost || unit.Stage != taskroute.StageSecprobe || unit.TaskType != taskroute.TaskTypeSecprobe || unit.TaskSubtype != taskroute.TaskSubtypeHostWeakAuth {
		t.Fatalf("unexpected normalized unit: %#v", unit)
	}
}
```

```go
func TestBuildSecprobeRequestParsesPayloadAndDefaults(t *testing.T) {
	unit := &contracts.ScanUnit{
		ID:        "unit-1",
		JobID:     "task-1",
		TargetKey: "demo.local",
		Payload: map[string]string{
			"target":            "demo.local",
			"resolved_ip":       "192.0.2.20",
			"services_json":     `[{"host":"demo.local","port":22,"service":"ssh?","version":"OpenSSH_9.8"},{"host":"demo.local","port":6379,"service":"redis","banner":"redis"}]`,
			"timeout_ms":        "3000",
			"stop_on_success":   "true",
			"enable_enrichment": "false",
		},
	}

	req, err := buildSecprobeRequest(unit)
	if err != nil {
		t.Fatalf("buildSecprobeRequest() error = %v", err)
	}
	if req.Target != "demo.local" || req.ResolvedIP != "192.0.2.20" || len(req.Services) != 2 {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.Timeout != 3*time.Second || !req.StopOnSuccess || req.EnableEnrichment {
		t.Fatalf("unexpected runtime defaults: %+v", req)
	}
	if req.Services[0].Version != "OpenSSH_9.8" || req.Services[1].Banner != "redis" {
		t.Fatalf("expected version/banner to survive payload parsing, got %+v", req.Services)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/worker/engines/attack/secprobe/... ./internal/worker/engines -run 'Test(SecprobeTaskListenerHandleNormalizesUnit|BuildSecprobeRequestParsesPayloadAndDefaults|BuildEnabled.*Secprobe)')`

Expected: FAIL because the secprobe worker package tree does not exist yet

- [ ] **Step 3: Implement the listener, request parser, process shell, and catalog registration**

```go
const (
	secprobeProcessName  = "secprobe-host"
	secprobeListenerName = "secprobe-host"
	secprobeTopic        = taskroute.TopicScanSecprobeHost
)
```

```go
type secprobeScanner interface {
	Scan(context.Context, gomapsecprobe.ScanRequest) gomapsecprobe.ScanResult
}

type gomapSecprobeScanner struct{}

func (gomapSecprobeScanner) Scan(ctx context.Context, req gomapsecprobe.ScanRequest) gomapsecprobe.ScanResult {
	return gomapsecprobe.Scan(ctx, req)
}

type SecprobeProcess struct {
	logger  *zap.Logger
	scanner secprobeScanner
}

func NewSecprobeProcess(_ conf.Worker, logger *zap.Logger) (module.Process, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &SecprobeProcess{
		logger:  logger,
		scanner: gomapSecprobeScanner{},
	}, nil
}
```

```go
func buildSecprobeRequest(unit *contracts.ScanUnit) (gomapsecprobe.ScanRequest, error) {
	if unit == nil {
		return gomapsecprobe.ScanRequest{}, fmt.Errorf("scan unit is nil")
	}
	target := firstNonEmptyString(strings.TrimSpace(unit.Payload["target"]), strings.TrimSpace(unit.TargetKey))
	if target == "" {
		return gomapsecprobe.ScanRequest{}, fmt.Errorf("secprobe target is required")
	}
	raw := strings.TrimSpace(unit.Payload["services_json"])
	if raw == "" {
		return gomapsecprobe.ScanRequest{}, fmt.Errorf("services_json is required")
	}
	var payloadItems []contracts.SecprobeServicePayload
	if err := json.Unmarshal([]byte(raw), &payloadItems); err != nil {
		return gomapsecprobe.ScanRequest{}, fmt.Errorf("parse services_json: %w", err)
	}
	services := make([]gomapsecprobe.ScanService, 0, len(payloadItems))
	for _, item := range payloadItems {
		services = append(services, gomapsecprobe.ScanService{
			Port:    item.Port,
			Service: item.Service,
			Version: item.Version,
			Banner:  item.Banner,
		})
	}
	return gomapsecprobe.ScanRequest{
		Target:            target,
		ResolvedIP:        strings.TrimSpace(unit.Payload["resolved_ip"]),
		Services:          services,
		Timeout:           parseDurationMS(unit.Payload["timeout_ms"], 3*time.Second),
		StopOnSuccess:     parseBoolString(unit.Payload["stop_on_success"], true),
		EnableEnrichment:  parseBoolString(unit.Payload["enable_enrichment"], false),
		EnableUnauthorized: false,
	}, nil
}

func parseDurationMS(raw string, fallback time.Duration) time.Duration {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

func parseBoolString(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
```

```go
func (p *SecprobeProcess) Name() string  { return secprobeProcessName }
func (p *SecprobeProcess) Topic() string { return secprobeTopic }

func (p *SecprobeProcess) Run(ctx context.Context, unit *contracts.ScanUnit) (map[string]any, error) {
	req, err := buildSecprobeRequest(unit)
	if err != nil {
		return nil, err
	}
	_ = p.scanner.Scan(ctx, req)
	return map[string]any{
		"engine":  secprobeProcessName,
		"target":  req.Target,
		"service_count": len(req.Services),
	}, nil
}
```

```go
func Catalog() map[string]module.Spec {
	registry := make(map[string]module.Spec)
	for _, spec := range assetprocess.Specs() {
		registry[spec.Name] = spec
	}
	for _, spec := range attacknucleiprocess.Specs() {
		registry[spec.Name] = spec
	}
	for _, spec := range attackweakscanprocess.Specs() {
		registry[spec.Name] = spec
	}
	for _, spec := range attacksecprobeprocess.Specs() {
		registry[spec.Name] = spec
	}
	return registry
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/worker/engines/attack/secprobe/... ./internal/worker/engines -run 'Test(SecprobeTaskListenerHandleNormalizesUnit|BuildSecprobeRequestParsesPayloadAndDefaults|BuildEnabled.*Secprobe)')`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/zvas add internal/worker/engines/attack/secprobe internal/worker/engines/catalog.go internal/worker/engines/catalog_test.go
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "feat(worker): add secprobe listener and process shell"
```

### Task 5: Map secprobe Results into Summary, Raw Findings, and `UnitVulnerability`

**Files:**
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/mapper/result.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/mapper/result_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/secprobe.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/process/process_test.go`

- [ ] **Step 1: Write the failing mapper/process tests**

```go
func TestResultFromScanKeepsSummaryFindingsAndVulnerabilities(t *testing.T) {
	req := gomapsecprobe.ScanRequest{
		Target:     "demo.local",
		ResolvedIP: "192.0.2.30",
		Services: []gomapsecprobe.ScanService{
			{Port: 22, Service: "ssh"},
			{Port: 6379, Service: "redis"},
		},
	}
	result := gomapsecprobe.ScanResult{
		Target:     "demo.local",
		ResolvedIP: "192.0.2.30",
		Meta:       gomapsecprobe.SecurityMeta{Candidates: 2, Attempted: 2, Succeeded: 1, Failed: 1},
		Results: []gomapsecprobe.SecurityResult{
			{
				Target:      "demo.local",
				ResolvedIP:  "192.0.2.30",
				Port:        22,
				Service:     "ssh",
				ProbeKind:   gomapsecprobe.ProbeKindCredential,
				FindingType: gomapsecprobe.FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "root",
				Evidence:    "ssh auth succeeded",
			},
			{
				Target:      "demo.local",
				ResolvedIP:  "192.0.2.30",
				Port:        6379,
				Service:     "redis",
				ProbeKind:   gomapsecprobe.ProbeKindCredential,
				FindingType: gomapsecprobe.FindingTypeCredentialValid,
				Success:     false,
				Error:       "dial tcp 192.0.2.30:6379: i/o timeout",
			},
		},
	}

	got := ResultFromScan(req, result)
	if got["service_count"] != 2 || got["attempted_count"] != 2 || got["matched_count"] != 1 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if got["partial_result"] != true {
		t.Fatalf("expected partial_result=true, got %+v", got)
	}
	findings, ok := got["findings"].([]map[string]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("expected 2 raw findings, got %+v", got["findings"])
	}
	items, ok := got["vulnerabilities"].([]contracts.UnitVulnerability)
	if !ok || len(items) != 1 {
		t.Fatalf("expected 1 vulnerability, got %+v", got["vulnerabilities"])
	}
	if items[0].RuleID != "gomap/secprobe/credential-valid" || items[0].Severity != "high" {
		t.Fatalf("unexpected vulnerability mapping: %+v", items[0])
	}
	if _, ok := items[0].Evidence["password"]; ok {
		t.Fatalf("expected top-level evidence to omit password, got %+v", items[0].Evidence)
	}
	if items[0].Raw["password"] != "root" {
		t.Fatalf("expected raw payload to keep password, got %+v", items[0].Raw)
	}
}
```

```go
func TestSecprobeProcessRunTreatsPartialFailuresAsSuccessfulUnitResult(t *testing.T) {
	process := &SecprobeProcess{
		logger: zap.NewNop(),
		scanner: scanStub{
			result: gomapsecprobe.ScanResult{
				Target:     "demo.local",
				ResolvedIP: "192.0.2.30",
				Meta:       gomapsecprobe.SecurityMeta{Candidates: 2, Attempted: 2, Succeeded: 1, Failed: 1},
				Results: []gomapsecprobe.SecurityResult{
					{Target: "demo.local", ResolvedIP: "192.0.2.30", Port: 22, Service: "ssh", ProbeKind: gomapsecprobe.ProbeKindCredential, FindingType: gomapsecprobe.FindingTypeCredentialValid, Success: true, Username: "root", Password: "root"},
					{Target: "demo.local", ResolvedIP: "192.0.2.30", Port: 6379, Service: "redis", ProbeKind: gomapsecprobe.ProbeKindCredential, FindingType: gomapsecprobe.FindingTypeCredentialValid, Success: false, Error: "timeout"},
				},
			},
		},
	}

	result, err := process.Run(context.Background(), &contracts.ScanUnit{
		ID:        "unit-1",
		JobID:     "task-1",
		TargetKey: "demo.local",
		Payload: map[string]string{
			"target":        "demo.local",
			"resolved_ip":   "192.0.2.30",
			"services_json": `[{"host":"demo.local","port":22,"service":"ssh"},{"host":"demo.local","port":6379,"service":"redis"}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected secprobe unit to finish successfully, got %v", err)
	}
	if result["partial_result"] != true {
		t.Fatalf("expected partial_result=true, got %+v", result)
	}
}

type scanStub struct {
	result gomapsecprobe.ScanResult
}

func (s scanStub) Scan(context.Context, gomapsecprobe.ScanRequest) gomapsecprobe.ScanResult {
	return s.result
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/worker/engines/attack/secprobe/... -run 'Test(ResultFromScanKeepsSummaryFindingsAndVulnerabilities|SecprobeProcessRunTreatsPartialFailuresAsSuccessfulUnitResult)')`

Expected: FAIL because the mapper functions do not exist yet and `SecprobeProcess.Run` still returns the minimal shell result from Task 4

- [ ] **Step 3: Implement the summary/findings/vulnerability mapping**

```go
func ResultFromScan(req gomapsecprobe.ScanRequest, result gomapsecprobe.ScanResult) map[string]any {
	findings := make([]map[string]any, 0, len(result.Results))
	vulnerabilities := make([]contracts.UnitVulnerability, 0, len(result.Results))
	matched := 0
	failed := 0
	for _, item := range result.Results {
		rawFinding := map[string]any{
			"host":         firstNonEmptyString(item.Target, result.Target, req.Target),
			"ip":           firstNonEmptyString(item.ResolvedIP, result.ResolvedIP, req.ResolvedIP),
			"port":         item.Port,
			"service":      item.Service,
			"probe_kind":   string(item.ProbeKind),
			"finding_type": item.FindingType,
			"success":      item.Success,
			"username":     item.Username,
			"password":     item.Password,
			"evidence":     item.Evidence,
			"enrichment":   cloneAnyMap(item.Enrichment),
			"error":        item.Error,
		}
		findings = append(findings, rawFinding)
		if item.Success {
			matched++
			vulnerabilities = append(vulnerabilities, contracts.UnitVulnerability{
				VulnerabilityKey: buildCredentialFindingKey(firstNonEmptyString(item.Target, req.Target), item.Port, item.Service, item.Username),
				RuleID:           "gomap/secprobe/credential-valid",
				RuleName:         "协议弱口令命中",
				Severity:         "high",
				Host:             firstNonEmptyString(item.Target, req.Target),
				IP:               firstNonEmptyString(item.ResolvedIP, req.ResolvedIP),
				Port:             item.Port,
				Classification: map[string]any{
					"engine":   "gomap-secprobe",
					"category": "weak-auth",
					"service":  item.Service,
				},
				Evidence: map[string]any{
					"service":      item.Service,
					"probe_kind":   string(item.ProbeKind),
					"finding_type": item.FindingType,
					"username":     item.Username,
					"evidence":     item.Evidence,
				},
				Raw: map[string]any{
					"host":         firstNonEmptyString(item.Target, req.Target),
					"ip":           firstNonEmptyString(item.ResolvedIP, req.ResolvedIP),
					"port":         item.Port,
					"service":      item.Service,
					"probe_kind":   string(item.ProbeKind),
					"finding_type": item.FindingType,
					"username":     item.Username,
					"password":     item.Password,
					"evidence":     item.Evidence,
					"enrichment":   cloneAnyMap(item.Enrichment),
					"error":        item.Error,
				},
			})
		}
		if strings.TrimSpace(item.Error) != "" {
			failed++
		}
	}
	out := map[string]any{
		"engine":          "gomap-secprobe",
		"target":          req.Target,
		"resolved_ip":     firstNonEmptyString(result.ResolvedIP, req.ResolvedIP),
		"service_count":   len(req.Services),
		"attempted_count": result.Meta.Attempted,
		"matched_count":   matched,
		"failed_count":    failed,
		"partial_result":  failed > 0 && matched > 0,
		"findings":        findings,
		"vulnerabilities": vulnerabilities,
	}
	if strings.TrimSpace(result.Error) != "" {
		out["error"] = result.Error
	}
	return out
}

func buildCredentialFindingKey(host string, port int, service string, username string) string {
	return fmt.Sprintf("%s|%d|%s|%s|credential-valid", strings.TrimSpace(host), port, strings.TrimSpace(service), strings.TrimSpace(username))
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		dst[key] = value
	}
	return dst
}
```

```go
func (p *SecprobeProcess) Run(ctx context.Context, unit *contracts.ScanUnit) (map[string]any, error) {
	req, err := buildSecprobeRequest(unit)
	if err != nil {
		return nil, err
	}
	result := p.scanner.Scan(ctx, req)
	return mapper.ResultFromScan(req, result), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/worker/engines/attack/secprobe/... -run 'Test(ResultFromScanKeepsSummaryFindingsAndVulnerabilities|SecprobeProcessRunTreatsPartialFailuresAsSuccessfulUnitResult)')`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/zvas add internal/worker/engines/attack/secprobe/mapper internal/worker/engines/attack/secprobe/process/secprobe.go internal/worker/engines/attack/secprobe/process/process_test.go
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "feat(worker): map secprobe results into findings and vulnerabilities"
```

### Task 6: Seed secprobe Units from Structured Port Results

**Files:**
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_port_structured.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed_runtime.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_route_seed_runtime_test.go`

- [ ] **Step 1: Write the failing seed test**

```go
func TestBuildSecprobeSeedUnitsFromPortResultsGroupsByHost(t *testing.T) {
	task := &model.ScanTask{
		RoutePlan: []string{taskroute.RouteCodePortScan, taskroute.RouteCodeSecprobeHost},
		Params: map[string]string{
			"timeout_ms":        "3000",
			"stop_on_success":   "true",
			"enable_enrichment": "false",
		},
	}

	units := buildSecprobeSeedUnitsFromPortResults(task, []structuredPortResultRow{
		{Target: "demo.local", ResolvedIP: "192.0.2.50", Port: 22, Service: "ssh", Version: "OpenSSH_9.8"},
		{Target: "demo.local", ResolvedIP: "192.0.2.50", Port: 6379, Service: "redis", Banner: "redis"},
		{Target: "demo.local", ResolvedIP: "192.0.2.50", Port: 80, Service: "http"},
		{Target: "api.local", ResolvedIP: "192.0.2.60", Port: 3306, Service: "mysql"},
	})

	if len(units) != 2 {
		t.Fatalf("expected 2 secprobe units, got %d", len(units))
	}
	if units[0].RouteCode != taskroute.RouteCodeSecprobeHost || units[0].Topic != taskroute.TopicScanSecprobeHost {
		t.Fatalf("unexpected unit: %+v", units[0])
	}
	if !strings.Contains(units[0].Payload["services_json"], `"ssh"`) || strings.Contains(units[0].Payload["services_json"], `"http"`) {
		t.Fatalf("expected only supported services in payload, got %s", units[0].Payload["services_json"])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/center/repo -run TestBuildSecprobeSeedUnitsFromPortResultsGroupsByHost)`

Expected: FAIL because the secprobe seed builder does not exist yet

- [ ] **Step 3: Implement host aggregation and route seeding**

```go
func buildSecprobeSeedUnitsFromPortResults(task *model.ScanTask, rows []structuredPortResultRow) []queuedTaskUnit {
	grouped := make(map[string][]contracts.SecprobeServicePayload)
	resolvedIPs := make(map[string]string)
	seenPorts := make(map[string]map[int]struct{})
	order := make([]string, 0)

	for _, row := range rows {
		host := strings.TrimSpace(targetHost(firstNonEmptyString(row.Target, row.ResolvedIP)))
		service := gomapsecprobe.NormalizeServiceName(row.Service, row.Port)
		if host == "" || service == "" || row.Port <= 0 {
			continue
		}
		if _, ok := grouped[host]; !ok {
			grouped[host] = []contracts.SecprobeServicePayload{}
			seenPorts[host] = map[int]struct{}{}
			order = append(order, host)
		}
		if _, ok := seenPorts[host][row.Port]; ok {
			continue
		}
		seenPorts[host][row.Port] = struct{}{}
		grouped[host] = append(grouped[host], contracts.SecprobeServicePayload{
			Host:    host,
			Port:    row.Port,
			Service: service,
			Version: row.Version,
			Banner:  row.Banner,
		})
		if resolvedIPs[host] == "" {
			resolvedIPs[host] = strings.TrimSpace(row.ResolvedIP)
		}
	}

	units := make([]queuedTaskUnit, 0, len(order))
	for _, host := range order {
		services := grouped[host]
		if len(services) == 0 {
			continue
		}
		servicesJSON, _ := json.Marshal(services)
		units = append(units, queuedTaskUnit{
			RouteCode:   taskroute.RouteCodeSecprobeHost,
			Stage:       taskroute.StageSecprobe,
			Topic:       defaultTopicForQueuedUnit(taskroute.TaskTypeSecprobe, taskroute.StageSecprobe, taskroute.TopicScanSecprobeHost),
			TaskType:    taskroute.TaskTypeSecprobe,
			TaskSubtype: taskroute.TaskSubtypeHostWeakAuth,
			TargetKey:   host,
			Payload: map[string]string{
				"target":             host,
				"resolved_ip":        resolvedIPs[host],
				"services_json":      string(servicesJSON),
				"task_type":          taskroute.TaskTypeSecprobe,
				"task_subtype":       taskroute.TaskSubtypeHostWeakAuth,
				"timeout_ms":         firstNonEmptyString(task.Params["timeout_ms"], "3000"),
				"stop_on_success":    firstNonEmptyString(task.Params["stop_on_success"], "true"),
				"enable_enrichment":  firstNonEmptyString(task.Params["enable_enrichment"], "false"),
				"source_asset_kind":  "port_result",
				"source_asset_key":   host,
			},
		})
	}
	sortQueuedUnitsByTargetKey(units)
	return units
}
```

```go
case taskroute.RouteCodeSecprobeHost:
	rows, err := queryTaskUnitPortResults(ctx, tx, `
select task_unit_id, task_id, task_type, task_subtype, target, resolved_ip, port, protocol, service, version, banner, subject, dns_names, fingerprinted, status, homepage_url
from task_unit_port_result
where task_id = $1
order by target asc, port asc
`, task.ID)
	if err != nil {
		return nil, err
	}
	return buildSecprobeSeedUnitsFromPortResults(task, rows), nil
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/center/repo -run TestBuildSecprobeSeedUnitsFromPortResultsGroupsByHost)`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/zvas add internal/center/repo/task_unit_port_structured.go internal/center/repo/task_route_seed.go internal/center/repo/task_route_seed_runtime.go internal/center/repo/task_route_seed_runtime_test.go
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "feat(center): seed secprobe units from structured ports"
```

### Task 7: Persist secprobe Results in center with Summary, Lease, and Unified Vulnerability Storage

**Files:**
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_repo_postgres.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_result_summary.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_result_summary_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/scan_task_record_detail_repo.go`
- Create: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/scan_task_record_detail_repo_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_vulnerability.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_unit_vulnerability_test.go`
- Modify: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/task_repo_postgres_result_test.go`

- [ ] **Step 1: Write the failing repo tests**

```go
func TestSummarizeTaskUnitResultSupportsSecprobe(t *testing.T) {
	summary := summarizeTaskUnitResult(taskroute.TaskTypeSecprobe, taskroute.StageSecprobe, map[string]any{
		"target":          "demo.local",
		"service_count":   2,
		"attempted_count": 2,
		"matched_count":   1,
		"partial_result":  true,
	})
	if summary != "demo.local | 尝试 2 个服务 | 命中 1 条 | 部分结果" {
		t.Fatalf("unexpected summary: %s", summary)
	}
}
```

```go
func TestTaskRepoPostgresApplyUnitStatusRunningUsesSecprobeLease(t *testing.T) {
	ctx := context.Background()
	pool := openAssetTestPool(t)
	repo, _, task := createSecprobeTestTask(t, ctx, pool, "secprobe 续租任务")

	unitID := insertSecprobeTaskUnit(t, ctx, pool, task.ID, "demo.local", contracts.UnitStatusRunning, 1)
	occurredAt := time.Now().UTC()
	if err := repo.ApplyUnitStatus(ctx, &contracts.UnitStatusEvent{
		UnitID:      unitID,
		JobID:       task.ID,
		WorkerID:    "worker-secprobe-1",
		RouteCode:   taskroute.RouteCodeSecprobeHost,
		Topic:       taskroute.TopicScanSecprobeHost,
		TaskType:    taskroute.TaskTypeSecprobe,
		TaskSubtype: taskroute.TaskSubtypeHostWeakAuth,
		Status:      contracts.UnitStatusRunning,
		Attempt:     1,
		OccurredAt:  occurredAt,
	}); err != nil {
		t.Fatalf("apply running status: %v", err)
	}

	var leaseExpiresAt time.Time
	if err := pool.QueryRow(ctx, `select lease_expires_at from task_unit where id = $1`, unitID).Scan(&leaseExpiresAt); err != nil {
		t.Fatalf("query renewed lease: %v", err)
	}
	if !leaseExpiresAt.After(occurredAt.Add(299 * time.Second)) {
		t.Fatalf("expected secprobe lease to use dedicated duration, got %s", leaseExpiresAt)
	}
}
```

```go
func TestTaskRepoPostgresApplyUnitVulnerabilityBatchKeepsSecprobeInUnifiedTable(t *testing.T) {
	ctx := context.Background()
	pool := openAssetTestPool(t)
	repo, _, task := createSecprobeTestTask(t, ctx, pool, "secprobe 漏洞事实任务")
	unitID := insertSecprobeTaskUnit(t, ctx, pool, task.ID, "demo.local", contracts.UnitStatusSucceeded, 1)

	err := repo.ApplyUnitVulnerabilityBatch(ctx, &contracts.UnitVulnerabilityBatchEvent{
		UnitID:      unitID,
		JobID:       task.ID,
		WorkerID:    "worker-1",
		RouteCode:   taskroute.RouteCodeSecprobeHost,
		Topic:       taskroute.TopicScanSecprobeHost,
		TaskType:    taskroute.TaskTypeSecprobe,
		TaskSubtype: taskroute.TaskSubtypeHostWeakAuth,
		Attempt:     1,
		BatchIndex:  0,
		OccurredAt:  time.Now().UTC(),
		Items: []contracts.UnitVulnerability{{
			VulnerabilityKey: "demo.local|22|ssh|root|credential-valid",
			RuleID:           "gomap/secprobe/credential-valid",
			RuleName:         "协议弱口令命中",
			Severity:         "high",
			Host:             "demo.local",
			IP:               "192.0.2.30",
			Port:             22,
			Evidence:         map[string]any{"service": "ssh", "username": "root"},
			Raw:              map[string]any{"password": "root"},
		}},
	})
	if err != nil {
		t.Fatalf("apply vulnerability batch: %v", err)
	}

	var unifiedCount int
	if err := pool.QueryRow(ctx, `select count(*) from task_unit_vulnerability where task_unit_id = $1`, unitID).Scan(&unifiedCount); err != nil {
		t.Fatalf("query task_unit_vulnerability: %v", err)
	}
	if unifiedCount != 1 {
		t.Fatalf("expected 1 unified vulnerability row, got %d", unifiedCount)
	}

	var weakScanCount int
	if err := pool.QueryRow(ctx, `select count(*) from task_unit_weak_scan_finding where task_unit_id = $1`, unitID).Scan(&weakScanCount); err != nil {
		t.Fatalf("query task_unit_weak_scan_finding: %v", err)
	}
	if weakScanCount != 0 {
		t.Fatalf("expected secprobe to bypass weak_scan finding table, got %d", weakScanCount)
	}
}
```

```go
func TestScanTaskRepoPostgresGetTaskRecordDetailLoadsSecprobeVulnerabilities(t *testing.T) {
	ctx := context.Background()
	pool := openAssetTestPool(t)
	repo, _, task := createSecprobeTestTask(t, ctx, pool, "secprobe record detail")
	unitID := insertSecprobeTaskUnit(t, ctx, pool, task.ID, "demo.local", contracts.UnitStatusSucceeded, 1)

	if _, err := pool.Exec(ctx, `
update task_unit
set result_json = '{"target":"demo.local","service_count":2,"attempted_count":2,"matched_count":1,"findings":[{"host":"demo.local","port":22,"service":"ssh","username":"root","password":"root"}]}'
where id = $1
`, unitID); err != nil {
		t.Fatalf("seed secprobe result_json: %v", err)
	}

	if err := repo.ApplyUnitVulnerabilityBatch(ctx, &contracts.UnitVulnerabilityBatchEvent{
		UnitID:      unitID,
		JobID:       task.ID,
		WorkerID:    "worker-1",
		RouteCode:   taskroute.RouteCodeSecprobeHost,
		Topic:       taskroute.TopicScanSecprobeHost,
		TaskType:    taskroute.TaskTypeSecprobe,
		TaskSubtype: taskroute.TaskSubtypeHostWeakAuth,
		Attempt:     1,
		BatchIndex:  0,
		OccurredAt:  time.Now().UTC(),
		Items: []contracts.UnitVulnerability{{
			VulnerabilityKey: "demo.local|22|ssh|root|credential-valid",
			RuleID:           "gomap/secprobe/credential-valid",
			RuleName:         "协议弱口令命中",
			Severity:         "high",
			Host:             "demo.local",
			IP:               "192.0.2.30",
			Port:             22,
		}},
	}); err != nil {
		t.Fatalf("apply vulnerability batch: %v", err)
	}

	detail, err := NewScanTaskRepoPostgres(pool).GetTaskRecordDetail(ctx, task.ID, unitID)
	if err != nil {
		t.Fatalf("get task record detail: %v", err)
	}
	if len(detail.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %+v", detail.Vulnerabilities)
	}
	if detail.ResultSummary == "" {
		t.Fatalf("expected non-empty result summary, got %+v", detail)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/center/repo -run 'Test(SummarizeTaskUnitResultSupportsSecprobe|TaskRepoPostgresApplyUnitStatusRunningUsesSecprobeLease|TaskRepoPostgresApplyUnitVulnerabilityBatchKeepsSecprobeInUnifiedTable|ScanTaskRepoPostgresGetTaskRecordDetailLoadsSecprobeVulnerabilities)')`

Expected: FAIL because secprobe is not yet recognized by summary, lease, record-detail, or vulnerability persistence paths

- [ ] **Step 3: Implement secprobe summary, unified persistence, and record-detail support**

```go
const (
	defaultRunningLeaseDuration = 120 * time.Second
	httpProbeLeaseDuration      = 90 * time.Second
	vulnScanLeaseDuration       = 240 * time.Second
	weakScanLeaseDuration       = 1800 * time.Second
	secprobeLeaseDuration       = 300 * time.Second
)

func runningLeaseDuration(taskType, routeCode, stage string) time.Duration {
	switch {
	case strings.HasPrefix(strings.TrimSpace(routeCode), "http_probe"), strings.TrimSpace(taskType) == taskroute.TaskTypeHTTPProbe, strings.TrimSpace(stage) == taskroute.StageHTTPProbe:
		return httpProbeLeaseDuration
	case strings.HasPrefix(strings.TrimSpace(routeCode), "vuln_scan"), strings.TrimSpace(taskType) == taskroute.TaskTypeVulnScan, strings.TrimSpace(stage) == taskroute.StageVulnScan:
		return vulnScanLeaseDuration
	case strings.HasPrefix(strings.TrimSpace(routeCode), "weak_scan"), strings.TrimSpace(taskType) == taskroute.TaskTypeWeakScan, strings.TrimSpace(stage) == taskroute.StageWeakScan:
		return weakScanLeaseDuration
	case strings.HasPrefix(strings.TrimSpace(routeCode), "secprobe"), strings.TrimSpace(taskType) == taskroute.TaskTypeSecprobe, strings.TrimSpace(stage) == taskroute.StageSecprobe:
		return secprobeLeaseDuration
	default:
		return defaultRunningLeaseDuration
	}
}
```

```go
case taskroute.IsSecprobeRoute(taskType, stage):
	target := strings.TrimSpace(firstNonEmptyString(stringFromAny(result["target"]), stringFromAny(result["resolved_ip"])))
	attempted := parseStructuredAnyInt(result["attempted_count"])
	matched := parseStructuredAnyInt(result["matched_count"])
	parts := make([]string, 0, 4)
	if target != "" {
		parts = append(parts, target)
	}
	parts = append(parts, fmt.Sprintf("尝试 %d 个服务", attempted))
	parts = append(parts, fmt.Sprintf("命中 %d 条", matched))
	if boolFromAny(result["partial_result"]) {
		parts = append(parts, "部分结果")
	}
	return strings.Join(parts, " | ")
```

```go
func isSecprobeTaskRecord(taskType string, stage string, routeCode string) bool {
	return strings.TrimSpace(taskType) == taskroute.TaskTypeSecprobe ||
		strings.TrimSpace(stage) == taskroute.StageSecprobe ||
		strings.TrimSpace(routeCode) == taskroute.RouteCodeSecprobeHost
}
```

```go
if isVulScanTaskRecord(item.TaskType, item.Stage, item.RouteCode) || isSecprobeTaskRecord(item.TaskType, item.Stage, item.RouteCode) {
	vulnRows, err := loadTaskUnitVulnerabilityRows(ctx, r.pool, item.UnitID)
	if err != nil {
		return nil, err
	}
	item.Vulnerabilities = mapTaskRecordVulnerabilities(vulnRows)
	localizations, err := loadVulnerabilityLocalizationMap(ctx, r.pool, collectRuleIDsFromTaskRecordRows(vulnRows))
	if err != nil {
		return nil, err
	}
	for idx := range item.Vulnerabilities {
		if loc, ok := localizations[item.Vulnerabilities[idx].RuleID]; ok {
			applyLocalizationToTaskRecord(&item.Vulnerabilities[idx], loc)
		} else {
			item.Vulnerabilities[idx].Severity = normalizeTaskFindingSeverityForDisplay("", item.Vulnerabilities[idx].Severity)
		}
	}
}
```

```go
isWeakScan := strings.TrimSpace(routeCode) == taskroute.RouteCodeWeakScanSite
if strings.TrimSpace(routeCode) == "" {
	isWeakScan = taskroute.IsWeakScanRoute(taskType, stage)
}
isSecprobe := strings.TrimSpace(routeCode) == taskroute.RouteCodeSecprobeHost
if strings.TrimSpace(routeCode) == "" {
	isSecprobe = taskroute.IsSecprobeRoute(taskType, stage)
}

for _, item := range items {
	targetURL := normalizeSiteURL(firstNonEmptyString(item.TargetURL, targetKey))
	siteAssetID := ""
	if targetURL != "" {
		var ok bool
		siteAssetID, ok = assetIDs[targetURL]
		if !ok {
			siteAssetID, err = lookupPoolSiteAssetIDTx(ctx, tx, assetPoolID, targetURL)
			if err != nil {
				return err
			}
			assetIDs[targetURL] = siteAssetID
		}
	}
	if isWeakScan {
		row := buildTaskUnitWeakScanFindingRow(event.UnitID, jobID, assetPoolID, snapshotID, targetURL, siteAssetID, item)
		if err := upsertTaskUnitWeakScanFindingRow(ctx, tx, row, occurredAt); err != nil {
			return err
		}
		continue
	}
	if targetURL == "" && !isSecprobe {
		continue
	}
	row := buildTaskUnitVulnerabilityRow(event.UnitID, jobID, assetPoolID, snapshotID, targetURL, siteAssetID, item)
	if err := upsertTaskUnitVulnerabilityRow(ctx, tx, row, occurredAt); err != nil {
		return err
	}
	if unitStatus == contracts.UnitStatusSucceeded && strings.TrimSpace(row.SiteAssetID) != "" {
		if err := upsertAssetPoolVulnerabilityTx(ctx, tx, row, occurredAt); err != nil {
			return err
		}
	}
}
```

```go
func createSecprobeTestTask(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) (*TaskRepoPostgres, *biz.AssetPoolUsecase, *model.ScanTask) {
	t.Helper()
	repo := NewTaskRepoPostgres(pool)
	assetRepo := NewAssetPoolRepoPostgres(pool)
	assetUC := biz.NewAssetPoolUsecase(assetRepo, nil)
	scanTaskUC := biz.NewScanTaskUsecase(NewScanTaskRepoPostgres(pool), nil, nil)

	createdPool, err := assetUC.CreateAssetPool(ctx, testAssetName(name+"池"), "用于 secprobe 结果测试", model.AssetPoolScopeRule{RootDomains: []string{"example.com"}}, []string{"external"})
	if err != nil {
		t.Fatalf("create asset pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `delete from asset_pool where id = $1`, createdPool.ID)
	})
	if _, err := assetUC.ImportSeeds(ctx, createdPool.ID, model.SeedImportInput{Mode: biz.AssetPoolSeedModeText, Source: biz.AssetPoolSeedSourceManual, Items: []string{"demo.local"}}); err != nil {
		t.Fatalf("import seeds: %v", err)
	}
	targetSet, err := assetUC.CreateTargetSet(ctx, model.CreateTargetSetInput{AssetPoolID: createdPool.ID, GenerationSource: biz.TargetSetGenerationSourcePoolAll, CreatedBy: "user-admin"})
	if err != nil {
		t.Fatalf("create target set: %v", err)
	}
	task, err := scanTaskUC.CreateTask(ctx, createdPool.ID, targetSet.ID, biz.TaskTemplateSecprobe, name, nil, nil, nil, "user-admin")
	if err != nil {
		t.Fatalf("create secprobe task: %v", err)
	}
	if _, err := pool.Exec(ctx, `update scan_task set desired_state = $2, status = $3 where id = $1`, task.ID, biz.TaskDesiredStateRunning, biz.ScanTaskStatusRunning); err != nil {
		t.Fatalf("activate secprobe task desired state: %v", err)
	}
	return repo, assetUC, task
}

func insertSecprobeTaskUnit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, taskID string, target string, status string, attempt int) string {
	t.Helper()
	unitID := testAssetName("unit-secprobe")
	occurredAt := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
insert into task_unit (id, job_id, stage, route_code, topic, task_type, task_subtype, target_key, payload_json, status, dispatch_attempt, lease_started_at, lease_expires_at, started_at, finished_at, created_at, updated_at)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $12, $14, $12, $12)
`, unitID, taskID, taskroute.StageSecprobe, taskroute.RouteCodeSecprobeHost, taskroute.TopicScanSecprobeHost, taskroute.TaskTypeSecprobe, taskroute.TaskSubtypeHostWeakAuth, target, []byte(`{"target":"`+target+`","resolved_ip":"192.0.2.30","services_json":"[{\"host\":\"`+target+`\",\"port\":22,\"service\":\"ssh\"}]","timeout_ms":"3000","stop_on_success":"true"}`), status, attempt, occurredAt, occurredAt.Add(10*time.Minute), nullableFinishedAt(status, occurredAt)); err != nil {
		t.Fatalf("insert secprobe task unit: %v", err)
	}
	return unitID
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/center/repo -run 'Test(SummarizeTaskUnitResultSupportsSecprobe|TaskRepoPostgresApplyUnitStatusRunningUsesSecprobeLease|TaskRepoPostgresApplyUnitVulnerabilityBatchKeepsSecprobeInUnifiedTable|ScanTaskRepoPostgresGetTaskRecordDetailLoadsSecprobeVulnerabilities)')`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/yrighc/work/hzyz/project/zvas add internal/center/repo/task_repo_postgres.go internal/center/repo/task_result_summary.go internal/center/repo/task_result_summary_test.go internal/center/repo/scan_task_record_detail_repo.go internal/center/repo/scan_task_record_detail_repo_test.go internal/center/repo/task_unit_vulnerability.go internal/center/repo/task_unit_vulnerability_test.go internal/center/repo/task_repo_postgres_result_test.go
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "feat(center): persist and summarize secprobe results"
```

### Task 8: Run Focused Verification Across GoMap and zvas

**Files:**
- Test: `/Users/yrighc/work/hzyz/project/GoMap/pkg/secprobe/scan_test.go`
- Test: `/Users/yrighc/work/hzyz/project/zvas/pkg/taskroute/task_route_test.go`
- Test: `/Users/yrighc/work/hzyz/project/zvas/internal/worker/engines/attack/secprobe/...`
- Test: `/Users/yrighc/work/hzyz/project/zvas/internal/center/repo/...`

- [ ] **Step 1: Run the full GoMap secprobe package tests**

Run: `(cd /Users/yrighc/work/hzyz/project/GoMap && go test -count=1 ./pkg/secprobe)`

Expected: PASS

- [ ] **Step 2: Run the focused zvas route and worker tests**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./pkg/taskroute ./internal/worker/engines/... )`

Expected: PASS

- [ ] **Step 3: Run the focused zvas center repo tests**

Run: `(cd /Users/yrighc/work/hzyz/project/zvas && go test -count=1 ./internal/center/repo -run 'Test(BuildSecprobeSeedUnitsFromPortResultsGroupsByHost|SummarizeTaskUnitResultSupportsSecprobe|TaskRepoPostgresApplyUnitStatusRunningUsesSecprobeLease|TaskRepoPostgresApplyUnitVulnerabilityBatchKeepsSecprobeInUnifiedTable|ScanTaskRepoPostgresGetTaskRecordDetailLoadsSecprobeVulnerabilities)')`

Expected: PASS

- [ ] **Step 4: Run a diff sanity check**

Run: `git -C /Users/yrighc/work/hzyz/project/GoMap diff --stat && git -C /Users/yrighc/work/hzyz/project/zvas diff --stat`

Expected: Only the planned GoMap/zvas files are modified; unrelated files such as `UPGRADE.md` or old secprobe notes stay untouched.

- [ ] **Step 5: Commit any verification-only fixes**

```bash
git -C /Users/yrighc/work/hzyz/project/GoMap add -A
git -C /Users/yrighc/work/hzyz/project/GoMap commit -m "test(secprobe): verify stable scan integration"
git -C /Users/yrighc/work/hzyz/project/zvas add -A
git -C /Users/yrighc/work/hzyz/project/zvas commit -m "test(secprobe): verify center worker integration"
```
