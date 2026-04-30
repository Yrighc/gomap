# GoMap secprobe 声明式策略与统一执行引擎设计

日期：2026-04-30

## 1. 背景

当前仓库的主定位仍然是资产探测，`secprobe` 作为协议安全探测子系统已经具备：

- 协议候选构建
- 协议注册与匹配
- 多协议认证/未授权探测
- 命中后补采
- 内部状态字段（`Stage`、`SkipReason`、`FailureReason` 等）

但目前 `secprobe` 仍然更像“多个协议 prober 的集合”，而不是一个统一的弱口令/协议安全探测引擎。核心原因在于：

- 调度层只对 candidate 做并发，很多协议仍在各自 `prober` 内部循环凭据
- 协议元数据仅用于识别/选字典，尚未形成完整的声明式策略层
- 失败分类、停止条件、重试语义、风险控制仍然分散在各协议实现中
- 对外结果模型隐藏了内部执行语义，上层难以基于状态做统一决策

本设计的目标不是把 `secprobe` 改造成 `nuclei` 式可编程模板系统，而是建立一种更稳的混合架构：

- YAML 只做声明式策略描述
- strategy 负责把声明编译为执行 Plan
- engine 统一负责执行控制
- plugin 只负责单次原子能力

## 2. 目标与非目标

### 2.1 目标

- 建立 `metadata -> strategy -> engine -> plugin` 的清晰分层
- 引入协议 YAML 元数据，但严格限制其为声明式，不承载循环、网络操作、状态机
- 将“凭据循环、停止条件、重试、退避、熔断、并发”统一收敛到 engine
- 将协议实现收敛为单次原子动作接口，降低扩展协议和统一执行逻辑的成本
- 为未来的简单模板能力预留位置，但模板不承担复杂协议执行职责
- 让 `secprobe` 逐步从“代码驱动协议实现”演进为“声明式策略驱动的执行引擎”

### 2.2 非目标

- 本阶段不追求把复杂协议认证逻辑 YAML 化
- 本阶段不引入可编程 DSL、表达式引擎、条件跳转或状态机模板
- 本阶段不重做 `assetprobe` 主链路
- 本阶段不一次性替换所有协议实现，可接受通过 adapter 渐进迁移
- 本阶段不强制对外公开全部内部执行状态，但内部模型必须先统一

## 3. 方案对比

### 方案 A：仅外置协议元数据，保留现有 prober 执行形态

做法：

- 把 `protocol_catalog.go` 迁移为 YAML
- `run.go` 读取 YAML 进行协议识别和字典定位
- 现有 `prober` 继续自己循环凭据和决定停止条件

优点：

- 落地快
- 外观上已经具备“配置化”能力

缺点：

- 执行控制问题没有真正解决
- 协议行为仍然不统一
- 未来很容易形成“元数据辅助代码”，而不是“元数据驱动引擎”

### 方案 B：建立统一 engine，并同时引入声明式 YAML 元数据

做法：

- 引入 protocol YAML，替换硬编码 catalog
- 新增 strategy，把 YAML + 运行时参数 + 目标画像编译为 Plan
- 新增 engine，统一执行 Plan
- 协议插件改为单次原子动作接口
- 通过 adapter 包裹现有 `prober`，逐步把凭据循环外移

优点：

- 同时解决扩展成本和执行一致性
- 能控制 YAML 不越权侵入执行逻辑
- 便于分阶段迁移，不要求全部协议重写

缺点：

- 第一阶段改动较大
- 需要同时改 registry、run、协议接口、目录结构

### 方案 C：尽量模板化，复杂协议只留少量插件

做法：

- 把更多行为抽到模板或元数据
- 尽量减少 Go 插件代码

优点：

- 看起来更接近 `nuclei` 风格
- 简单协议扩展快

缺点：

- 复杂协议（SSH/RDP/SMB/VNC）很难自然表达
- 容易把 YAML 逐渐演变成 DSL
- 维护上会出现“模板像代码但比代码更难调试”的问题

### 结论

选择方案 B。

## 4. 设计原则

### 4.1 声明性边界

YAML 必须严格保持声明性，只描述协议事实、能力和策略标签，不描述：

- 循环
- 网络操作
- 状态机
- 条件分支脚本
- 重试/退避具体执行过程

### 4.2 单一决策入口

`strategy` 是唯一负责把 `Spec` 编译为 `Plan` 的层。

它负责：

- 基于协议元数据、运行时参数、目标画像生成执行计划
- 决定 capability 组合
- 选择凭据来源和扩展 profile
- 计算执行策略的默认值与 hint 落地

它不负责执行。

### 4.3 单一执行入口

`engine` 是唯一负责执行控制的层。

它负责：

- 任务调度
- 凭据循环
- stop-on-success
- 并发控制
- 重试/退避
- 熔断/限速
- enrichment 触发
- 结果汇总

### 4.4 单次原子能力

`plugin` 只做单次原子动作：

- `AuthenticateOnce`
- `CheckUnauthorizedOnce`
- `EnrichOnce`

plugin 不再决定：

- 是否继续下一个凭据
- 是否全局停止
- 是否重试
- 是否切换阶段

## 5. 总体架构

```text
Protocol YAML Spec
        |
        v
     strategy
        |
        v
       Plan
        |
        v
      engine
   /     |      \
 cred  unauth  enrich
  |       |       |
  v       v       v
plugins plugins plugins
```

职责分层如下：

- `metadata`：加载并校验 YAML 协议声明
- `strategy`：把 `Spec` 编译为 `Plan`
- `engine`：执行 `Plan`
- `plugin`：执行单次原子能力

## 6. YAML Spec 设计

### 6.1 Spec 允许承载的内容

YAML 只包含以下四类信息：

1. 协议身份信息
2. 能力声明
3. 策略标签
4. 数据源声明

推荐字段：

```yaml
name: redis
aliases: ["redis/ssl", "redis/tls"]
ports: [6379]

capabilities:
  credential: true
  unauthorized: true
  enrichment: true

policy_tags:
  lockout_risk: low
  auth_family: password
  transport: tcp

dictionary:
  default_sources: ["redis"]
  allow_empty_username: true
  allow_empty_password: true
  expansion_profile: "static-basic"

results:
  credential_success_type: "credential_valid"
  unauthorized_success_type: "unauthorized_access"
  evidence_profile: "redis-basic"
```

### 6.2 Spec 不允许承载的内容

以下语义禁止进入 YAML：

- `continue_after_xxx_success`
- 凭据循环顺序脚本
- retry 次数
- backoff 细节
- transport 切换流程
- 错误字符串匹配逻辑
- 条件表达式
- 任意状态机

### 6.3 命名规范

- 使用统一 snake_case
- `dictionary` 使用单数，避免与 `dicts` 混用
- finding type 统一使用下划线风格，例如 `credential_valid`、`unauthorized_access`
- `capabilities` 先保持粗粒度，复杂能力用 `policy_tags` 细化

## 7. Strategy 设计

### 7.1 输入

- 协议 `Spec`
- 运行时参数（CLI / SDK）
- candidate 目标画像
- 可选的全局执行配置

### 7.2 输出

输出统一的 `Plan`，而不是直接调用 plugin。

### 7.3 职责

strategy 负责：

- capability 选择
- 凭据源选择
- 扩展 profile 选择
- 默认执行参数落地
- 风险标签到执行参数的映射

例如：

- `lockout_risk: high` -> 更小的 per-host 并发、更保守的 retry profile
- `capabilities.unauthorized = true` -> 允许在 Plan 中包含 `unauthorized` 阶段
- `dictionary.expansion_profile = static-basic` -> 使用对应扩展器生成凭据集

strategy 不负责：

- 网络 IO
- 循环执行
- stop/break 决策
- 失败分类解释

## 8. Plan 设计

### 8.1 Plan 定义

`Plan` 是 strategy 编译后的任务单，代表“这次 engine 要怎么执行”，但不包含脚本化流程。

### 8.2 最小字段集

```yaml
target:
  host: 10.0.0.8
  ip: 10.0.0.8
  port: 6379
  protocol: redis

capabilities:
  - unauthorized
  - credential

credential_set:
  source: builtin
  dictionaries: ["redis"]
  expansion_profile: static-basic

execution_policy:
  stop_on_first_success: true
  concurrency:
    scope: per_host
    value: 10
  retry_profile: low_risk_default
  backoff_profile: none
  rate_limit_profile: redis_default

result_policy:
  credential_success_type: credential_valid
  unauthorized_success_type: unauthorized_access
  enrich_on_success: true
  evidence_profile: redis-basic
```

### 8.3 关键约束

- `Plan` 是 strategy 产物，不是 YAML 手写执行脚本
- `execution_policy` 只表达执行参数，不表达流程语句
- `concurrency` 必须显式区分作用域，如 `per_host`、`per_protocol`、`global`

## 9. Engine 设计

### 9.1 核心职责

engine 统一执行 Plan，负责：

- candidate 级调度
- capability 级调度
- credential 级循环
- stop-on-first-success
- per-host / per-protocol / global 并发协调
- retry / backoff / rate limit
- 熔断与降速
- enrichment 触发
- 元结果统计

### 9.2 失败语义

engine 必须只消费统一错误枚举，而不是直接消费协议错误字符串。

需要建立统一枚举，例如：

- `authentication`
- `connection`
- `timeout`
- `canceled`
- `insufficient_confirmation`

可再扩展为：

- `soft_failure`
- `hard_failure`
- `retryable`
- `terminal`

具体哪个协议错误映射到哪个枚举，由 plugin 负责返回标准结果，engine 只解释标准码。

### 9.3 运行时策略解释

engine 根据 `execution_policy` 执行，而不是让 YAML 直接控制行为。

例如：

- `retry_profile` 决定重试器配置
- `backoff_profile` 决定固定/线性/指数退避
- `rate_limit_profile` 由 engine 映射到具体 limiter

## 10. Plugin 设计

### 10.1 能力接口

建议拆成三个能力接口：

- `CredentialAuthenticator`
- `UnauthorizedChecker`
- `Enricher`

### 10.2 原子接口示意

```go
type CredentialAuthenticator interface {
    AuthenticateOnce(ctx context.Context, target Target, cred Credential) AttemptResult
}

type UnauthorizedChecker interface {
    CheckUnauthorizedOnce(ctx context.Context, target Target) AttemptResult
}

type Enricher interface {
    EnrichOnce(ctx context.Context, finding AttemptResult) EnrichmentResult
}
```

### 10.3 迁移原则

现有 `prober` 不要求一次性删除，可先通过 adapter 包装：

- 第一阶段保留原有实现
- 将凭据循环逐步外移到 engine
- 逐步收敛为单次原子动作实现

## 11. 目录结构建议

推荐将 `pkg/secprobe` 收敛为如下结构：

```text
pkg/secprobe/
  metadata/
    loader.go
    schema.go
    validator.go
  strategy/
    planner.go
    credential_builder.go
    profiles.go
  engine/
    runner.go
    scheduler.go
    retry.go
    backoff.go
    limiter.go
  registry/
    registry.go
    adapters.go
  result/
    types.go
    codes.go
    export.go

internal/secprobe/
  plugins/
    ssh/
    rdp/
    smb/
    redis/
    ...

app/secprobe/
  protocols/
    ssh.yaml
    redis.yaml
    ...
  dicts/
    *.txt
```

说明：

- `protocol_catalog.go` 的职责迁移到 `metadata`
- `run.go` 未来的核心执行职责迁移到 `engine`
- `assets.go` 中的字典读取逻辑迁移到 `strategy` 的凭据构建部分
- 对外导出模型收敛到 `result`

## 12. 渐进迁移计划

### 阶段 1：建立 metadata / strategy / engine 骨架

- 新增协议 YAML schema 与 loader
- 将现有 catalog 映射到 YAML
- 引入 `Plan`、统一错误码、统一结果导出模型
- 保持现有协议仍可通过 adapter 接入

### 阶段 2：把执行控制从 `prober` 外移

- engine 接管 candidate 调度与 credential 循环
- stop-on-success、并发、retry、backoff 统一进入 engine
- plugin 改造为单次原子能力接口

### 阶段 3：补齐简单模板和 profile 体系

- 为简单未授权探测和明文协议补充模板执行器
- 建立 `retry_profile` / `backoff_profile` / `rate_limit_profile`
- 建立统一 schema 校验和配置测试

## 13. 测试策略

需要新增三类测试：

1. 元数据测试
- YAML schema 校验
- 字段默认值
- 命名规范
- 配置一致性

2. strategy 测试
- `Spec -> Plan` 编译结果
- 风险标签到执行策略映射
- 字典扩展 profile 输出

3. engine 测试
- stop-on-first-success
- per-host / per-protocol / global 并发控制
- retry / backoff / limiter 协同
- failure code 驱动的终止/继续语义

协议插件测试继续保留，但重点转为单次动作语义测试。

## 14. 风险与约束

### 14.1 主要风险

- YAML 逐渐膨胀成 DSL
- strategy 越权承担执行逻辑，演变为“第二个引擎”
- plugin 回流控制逻辑，破坏 engine 中心化
- 各协议 YAML 风格不一致，形成配置漂移

### 14.2 控制手段

- 严格 schema 校验
- 明确禁止控制流字段
- 统一 `Plan` 作为唯一执行输入
- 统一错误码与结果码
- 使用 golden tests 校验 `Spec -> Plan`

## 15. 最终边界结论

本设计采用以下四条硬约束：

- YAML 严格保持声明性
- strategy 唯一负责决策并生成 Plan
- engine 完全掌控执行控制
- plugin 只做单次原子能力

只要这四条边界不被打破，`secprobe` 就能在不把 YAML 变成 DSL 的前提下，逐步演进为一个更强、更稳、可扩展的协议安全探测引擎。
