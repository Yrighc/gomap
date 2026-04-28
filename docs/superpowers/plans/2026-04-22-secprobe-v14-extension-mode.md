# secprobe v1.4 扩展模式整改 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `secprobe` 从“已经能继续加协议”整理成“能稳定、低成本、可持续扩协议”的模式，同时保持当前 CLI、结果结构和平台集成方式不变。

**Architecture:** 先把内置协议装配层从 `pkg/secprobe/run.go` 中拆出去，再把协议别名、端口、字典名和能力声明收敛为统一协议目录，最后补一份明确的扩展开发指南。协议交互逻辑仍然保持代码实现，配置层只承载元数据，不把 `secprobe` 改成纯配置驱动。

**Tech Stack:** Go 1.24、标准库 `testing`、现有 `testcontainers` 集成测试、Markdown 文档

---

## File Structure

- Create: `pkg/secprobe/default_registry.go`
  - 内置协议装配层，承载 `RegisterDefaultProbers` 与 `DefaultRegistry`
- Create: `pkg/secprobe/default_registry_test.go`
  - 锁定内置协议注册行为
- Create: `pkg/secprobe/protocol_catalog.go`
  - 内置协议目录，承载协议别名、端口、字典名、能力声明
- Create: `pkg/secprobe/protocol_catalog_test.go`
  - 锁定协议目录、别名归一化与能力查询
- Create: `pkg/secprobe/dictionaries.go`
  - 基于协议目录生成字典候选路径
- Create: `pkg/secprobe/dictionaries_test.go`
  - 锁定字典候选路径和未知协议回退行为
- Modify: `pkg/secprobe/run.go`
  - 删除内置协议 import 与 `DefaultRegistry` 本地装配逻辑，接入新的装配层与字典路径辅助
- Modify: `pkg/secprobe/candidates.go`
  - 使用协议目录统一做服务归一化，不再手写散落规则
- Modify: `pkg/secprobe/candidates_test.go`
  - 调整断言到新的协议目录入口
- Create: `docs/secprobe-protocol-extension-guide.md`
  - 协议扩展开发指南与 checklist
- Modify: `README.md`
  - 增加 v1.4 扩展模式说明和开发指南入口

### Task 1: 拆分默认协议装配层

**Files:**
- Create: `pkg/secprobe/default_registry.go`
- Create: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run.go`

- [ ] **Step 1: 写默认协议装配层的失败测试**

```go
package secprobe

import "testing"

func TestRegisterDefaultProbersRegistersBuiltinLookupTargets(t *testing.T) {
	r := NewRegistry()
	RegisterDefaultProbers(r)

	tests := []struct {
		name      string
		candidate SecurityCandidate
		kind      ProbeKind
		want      string
	}{
		{
			name:      "ssh credential",
			candidate: SecurityCandidate{Service: "ssh", Port: 22},
			kind:      ProbeKindCredential,
			want:      "ssh",
		},
		{
			name:      "redis credential",
			candidate: SecurityCandidate{Service: "redis", Port: 6379},
			kind:      ProbeKindCredential,
			want:      "redis",
		},
		{
			name:      "redis unauthorized",
			candidate: SecurityCandidate{Service: "redis", Port: 6379},
			kind:      ProbeKindUnauthorized,
			want:      "redis-unauthorized",
		},
		{
			name:      "mongodb unauthorized",
			candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
			kind:      ProbeKindUnauthorized,
			want:      "mongodb-unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prober, ok := r.Lookup(tt.candidate, tt.kind)
			if !ok {
				t.Fatalf("expected built-in prober for %+v", tt.candidate)
			}
			if got := prober.Name(); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDefaultRegistryDelegatesToRegisterDefaultProbers(t *testing.T) {
	r := DefaultRegistry()

	if _, ok := r.Lookup(SecurityCandidate{Service: "ssh", Port: 22}, ProbeKindCredential); !ok {
		t.Fatal("expected default registry to contain ssh credential prober")
	}
	if _, ok := r.Lookup(SecurityCandidate{Service: "redis", Port: 6379}, ProbeKindUnauthorized); !ok {
		t.Fatal("expected default registry to contain redis unauthorized prober")
	}
}
```

- [ ] **Step 2: 运行测试确认当前失败**

Run: `go test -count=1 ./pkg/secprobe -run 'TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestDefaultRegistryDelegatesToRegisterDefaultProbers'`

Expected: FAIL，提示 `RegisterDefaultProbers` 未定义。

- [ ] **Step 3: 实现最小装配层拆分**

```go
// pkg/secprobe/default_registry.go
package secprobe

import (
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	RegisterDefaultProbers(r)
	return r
}
```

```go
// pkg/secprobe/run.go
package secprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type probeStatus uint8

const (
	probeSkipped probeStatus = iota
	probeFailedBeforeAttempt
	probeAttemptFailed
	probeAttemptSucceeded
)

var runEnrichment = func(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	return enrichResult(ctx, result, opts)
}
```

说明：

- 删除 `pkg/secprobe/run.go` 里原有的内置协议 import
- 删除 `run.go` 里本地定义的 `DefaultRegistry`
- 保持 `Run` / `RunWithRegistry` 签名不变

- [ ] **Step 4: 运行测试确认通过**

Run: `go test -count=1 ./pkg/secprobe -run 'TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestDefaultRegistryDelegatesToRegisterDefaultProbers'`

Expected: PASS

- [ ] **Step 5: 提交装配层拆分**

```bash
git add pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/run.go
git commit -m "refactor(secprobe): 拆分默认协议装配层"
```

### Task 2: 提取内置协议目录与能力声明

**Files:**
- Create: `pkg/secprobe/protocol_catalog.go`
- Create: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/candidates.go`
- Modify: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: 写协议目录和归一化的失败测试**

```go
package secprobe

import "testing"

func TestLookupProtocolSpecSupportsAliasesAndPortFallback(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    string
	}{
		{name: "postgres alias", service: "postgres", want: "postgresql"},
		{name: "pgsql alias", service: "pgsql", want: "postgresql"},
		{name: "mongo alias", service: "mongo", want: "mongodb"},
		{name: "redis tls alias", service: "redis/tls", want: "redis"},
		{name: "mongodb port fallback", port: 27017, want: "mongodb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if spec.Name != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, spec.Name)
			}
		})
	}
}

func TestProtocolSupportsKindUsesCatalogDeclaration(t *testing.T) {
	if !ProtocolSupportsKind("redis", ProbeKindCredential) {
		t.Fatal("expected redis to support credential probing")
	}
	if !ProtocolSupportsKind("redis", ProbeKindUnauthorized) {
		t.Fatal("expected redis to support unauthorized probing")
	}
	if ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to stay unsupported")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to be declared")
	}
}
```

- [ ] **Step 2: 运行测试确认当前失败**

Run: `go test -count=1 ./pkg/secprobe -run 'TestLookupProtocolSpecSupportsAliasesAndPortFallback|TestProtocolSupportsKindUsesCatalogDeclaration'`

Expected: FAIL，提示 `LookupProtocolSpec` 和 `ProtocolSupportsKind` 未定义。

- [ ] **Step 3: 实现协议目录与候选归一化**

```go
// pkg/secprobe/protocol_catalog.go
package secprobe

import "strings"

type ProtocolSpec struct {
	Name               string
	Aliases            []string
	Ports              []int
	DictNames          []string
	ProbeKinds         []ProbeKind
	SupportsEnrichment bool
}

var builtinProtocolSpecs = []ProtocolSpec{
	{Name: "ftp", Ports: []int{21}, DictNames: []string{"ftp"}, ProbeKinds: []ProbeKind{ProbeKindCredential}},
	{Name: "ssh", Ports: []int{22}, DictNames: []string{"ssh"}, ProbeKinds: []ProbeKind{ProbeKindCredential}},
	{Name: "telnet", Ports: []int{23}, DictNames: []string{"telnet"}, ProbeKinds: []ProbeKind{ProbeKindCredential}},
	{Name: "mysql", Ports: []int{3306}, DictNames: []string{"mysql"}, ProbeKinds: []ProbeKind{ProbeKindCredential}},
	{
		Name:       "postgresql",
		Aliases:    []string{"postgres", "pgsql"},
		Ports:      []int{5432},
		DictNames:  []string{"postgresql", "postgres"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:               "redis",
		Aliases:            []string{"redis/tls", "redis/ssl"},
		Ports:              []int{6379},
		DictNames:          []string{"redis"},
		ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
		SupportsEnrichment: true,
	},
	{
		Name:               "mongodb",
		Aliases:            []string{"mongo"},
		Ports:              []int{27017},
		DictNames:          []string{"mongodb", "mongo"},
		ProbeKinds:         []ProbeKind{ProbeKindUnauthorized},
		SupportsEnrichment: true,
	},
}

func LookupProtocolSpec(service string, port int) (ProtocolSpec, bool) {
	token := normalizeProtocolToken(service)
	if token != "" {
		for _, spec := range builtinProtocolSpecs {
			if spec.Name == token {
				return spec, true
			}
			for _, alias := range spec.Aliases {
				if alias == token {
					return spec, true
				}
			}
		}
	}

	if port != 0 {
		for _, spec := range builtinProtocolSpecs {
			for _, candidatePort := range spec.Ports {
				if candidatePort == port {
					return spec, true
				}
			}
		}
	}

	return ProtocolSpec{}, false
}

func ProtocolSupportsKind(service string, kind ProbeKind) bool {
	spec, ok := LookupProtocolSpec(service, 0)
	if !ok {
		return false
	}
	for _, declared := range spec.ProbeKinds {
		if declared == kind {
			return true
		}
	}
	return false
}

func normalizeProtocolToken(service string) string {
	service = strings.ToLower(strings.TrimSpace(service))
	service = strings.TrimSuffix(service, "?")
	return service
}
```

```go
// pkg/secprobe/candidates.go
package secprobe

import (
	"sort"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

func NormalizeServiceName(service string, port int) string {
	spec, ok := LookupProtocolSpec(service, port)
	if !ok {
		return ""
	}
	return spec.Name
}
```

说明：

- 保持 `NormalizeServiceName` 对外签名不变
- 删除 `candidates.go` 中散落的 `supportedByPort` 和硬编码 alias 逻辑
- 现有 `BuildCandidates` 逻辑保持不变，只改归一化来源

- [ ] **Step 4: 运行测试确认通过**

Run: `go test -count=1 ./pkg/secprobe -run 'TestLookupProtocolSpecSupportsAliasesAndPortFallback|TestProtocolSupportsKindUsesCatalogDeclaration|TestNormalizeServiceNameSupportsWeakAuthAliases|TestBuildCandidatesFiltersSupportedOpenPorts'`

Expected: PASS

- [ ] **Step 5: 提交协议目录收敛**

```bash
git add pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/candidates.go pkg/secprobe/candidates_test.go
git commit -m "refactor(secprobe): 提取内置协议目录元数据"
```

### Task 3: 统一字典候选路径与协议能力查询入口

**Files:**
- Create: `pkg/secprobe/dictionaries.go`
- Create: `pkg/secprobe/dictionaries_test.go`
- Modify: `pkg/secprobe/run.go`
- Modify: `pkg/secprobe/protocol_catalog.go`

- [ ] **Step 1: 写字典候选路径的失败测试**

```go
package secprobe

import (
	"path/filepath"
	"testing"
)

func TestCredentialDictionaryCandidatesUsesCatalogDictNames(t *testing.T) {
	got := CredentialDictionaryCandidates("postgresql", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "postgresql.txt"),
		filepath.Join("/tmp/dicts", "secprobe-postgresql.txt"),
		filepath.Join("/tmp/dicts", "postgres.txt"),
		filepath.Join("/tmp/dicts", "secprobe-postgres.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol(t *testing.T) {
	got := CredentialDictionaryCandidates("customsvc", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "customsvc.txt"),
		filepath.Join("/tmp/dicts", "secprobe-customsvc.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
```

- [ ] **Step 2: 运行测试确认当前失败**

Run: `go test -count=1 ./pkg/secprobe -run 'TestCredentialDictionaryCandidatesUsesCatalogDictNames|TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol'`

Expected: FAIL，提示 `CredentialDictionaryCandidates` 未定义。

- [ ] **Step 3: 实现字典候选路径辅助并接入运行时**

```go
// pkg/secprobe/dictionaries.go
package secprobe

import (
	"path/filepath"
	"strings"
)

func CredentialDictionaryCandidates(protocol, dictDir string) []string {
	normalized := NormalizeServiceName(protocol, 0)
	if normalized == "" {
		normalized = strings.ToLower(strings.TrimSpace(protocol))
	}

	names := []string{normalized}
	if spec, ok := LookupProtocolSpec(normalized, 0); ok && len(spec.DictNames) > 0 {
		names = spec.DictNames
	}

	out := make([]string, 0, len(names)*2)
	seen := make(map[string]struct{}, len(names)*2)
	for _, name := range names {
		for _, path := range []string{
			filepath.Join(dictDir, name+".txt"),
			filepath.Join(dictDir, "secprobe-"+name+".txt"),
		} {
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}
```

```go
// pkg/secprobe/run.go
func loadCredentialsFromDir(protocol, dictDir string) ([]Credential, error) {
	candidates := CredentialDictionaryCandidates(protocol, dictDir)

	var lastErr error
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				lastErr = err
				continue
			}
			return nil, err
		}

		creds, err := parseCredentialLines(string(data))
		if err != nil {
			return nil, fmt.Errorf("parse %s credentials: %w", protocol, err)
		}
		return dedupeCredentials(creds), nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("credential dictionary not found for protocol %s in %s", protocol, dictDir)
	}
	return nil, fmt.Errorf("credential dictionary not found for protocol %s", protocol)
}
```

说明：

- 不改变 `credentialsForCandidate` 和 `loadCredentialsFromDir` 的对外行为
- 未知协议继续保持当前两条文件名回退
- 已声明协议开始走统一 `DictNames`

- [ ] **Step 4: 运行测试确认通过**

Run: `go test -count=1 ./pkg/secprobe -run 'TestCredentialDictionaryCandidatesUsesCatalogDictNames|TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol|TestRunWithRegistryMarksMissingCredentialsAsNoCredentials'`

Expected: PASS

- [ ] **Step 5: 提交字典路径与能力查询收口**

```bash
git add pkg/secprobe/dictionaries.go pkg/secprobe/dictionaries_test.go pkg/secprobe/run.go pkg/secprobe/protocol_catalog.go
git commit -m "refactor(secprobe): 统一字典候选与协议能力查询"
```

### Task 4: 编写协议扩展开发指南

**Files:**
- Create: `docs/secprobe-protocol-extension-guide.md`

- [ ] **Step 1: 写开发指南初稿**

```md
# secprobe 协议扩展开发指南

## 1. 目标

本文说明如何在 GoMap 中新增一个 `secprobe` 协议实现，同时保持：

- registry 装配方式一致
- 协议目录结构一致
- 结果语义一致
- 测试覆盖一致

## 2. 一个协议应该放在哪里

新增协议统一放到：

- `internal/secprobe/<protocol>/`

目录内按能力拆分：

- `prober.go`
- `unauthorized_prober.go`
- `enrichment.go`
- `*_test.go`

## 3. 哪些内容允许配置化

允许配置化：

- 协议别名
- 默认端口
- 默认字典名
- 支持的 `ProbeKind`
- 是否支持 enrichment

必须代码实现：

- 协议握手
- 认证流程
- 未授权确认动作
- enrichment 采集逻辑
- 失败分类

## 4. 新协议接入 checklist

1. 在 `pkg/secprobe/protocol_catalog.go` 增加协议元数据
2. 在 `internal/secprobe/<protocol>/` 实现协议能力
3. 在 `pkg/secprobe/default_registry.go` 注册内置 prober
4. 为成功、认证失败、超时/取消、确认不足补齐测试
5. 如支持 enrichment，保证 enrichment 失败不改主 finding

## 5. 结果语义要求

- 真实发起探测前不要标记 `StageAttempted`
- 确认成功后才进入 `StageConfirmed`
- 失败优先分类到：
  - `connection`
  - `authentication`
  - `timeout`
  - `canceled`
  - `insufficient-confirmation`
```

- [ ] **Step 2: 保存文档并人工自检**

Run: `sed -n '1,220p' docs/secprobe-protocol-extension-guide.md`

Expected: 文档包含目录结构、配置化边界、接入 checklist、结果语义要求 4 个核心部分。

- [ ] **Step 3: 提交开发指南**

```bash
git add docs/secprobe-protocol-extension-guide.md
git commit -m "docs(secprobe): 新增协议扩展开发指南"
```

### Task 5: 补 README 入口并做回归验证

**Files:**
- Modify: `README.md`

- [ ] **Step 1: 补 README 的 v1.4 扩展模式说明**

```md
### secprobe 扩展说明

- `secprobe` 采用“代码驱动协议实现 + 配置驱动协议元数据”的扩展模式
- 新增协议不建议只改配置文件，仍需要新增协议实现代码
- 内置协议装配与协议元数据已独立收敛，扩展时请先参考：
  - `docs/secprobe-protocol-extension-guide.md`
```

- [ ] **Step 2: 运行 secprobe 相关回归测试**

Run: `go test -count=1 ./pkg/secprobe ./internal/secprobe/... ./cmd`

Expected: PASS

- [ ] **Step 3: 运行全仓验证**

Run: `go test ./...`

Expected: PASS

- [ ] **Step 4: 提交 README 与最终验证**

```bash
git add README.md
git commit -m "docs(secprobe): 补充 v1.4 扩展模式说明"
```

## Self-Review

### Spec coverage

- `v1.4` 协议装配层整改：由 Task 1 实现
- `v1.4` 协议目录与能力骨架统一：由 Task 2 实现
- `v1.4` 协议能力声明与可配置元数据收敛：由 Task 2、Task 3 实现
- `v1.4` 协议扩展开发指南与测试模板：由 Task 4 实现
- 保持引擎端定位、不引入平台概念：全计划未新增平台侧模块，仅整改 `secprobe` 内部模式

### Placeholder scan

- 计划中没有 `TODO` / `TBD` / “类似上一任务” 之类占位语句
- 所有测试命令、提交命令、文件路径都已给出具体内容
- 所有新增函数名称在前后任务中保持一致：
  - `RegisterDefaultProbers`
  - `LookupProtocolSpec`
  - `ProtocolSupportsKind`
  - `CredentialDictionaryCandidates`

### Type consistency

- 协议目录统一使用 `ProtocolSpec`
- 能力声明统一使用 `ProbeKind`
- 仍沿用现有 `Stage` / `FailureReason` / `Capabilities` 结果语义，不新增第二套类型
