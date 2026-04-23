# GoMap secprobe center / worker 集成方案 v1 设计

日期：2026-04-23

## 1. 背景

截至 `GoMap v0.4.5-alpha`，`secprobe` 已具备继续作为引擎端 SDK 被上层系统复用的基础能力：

- `pkg/secprobe` 已形成统一入口和稳定协议目录
- `credential` 与 `unauthorized` 的内部执行模型已经拆开
- 认证探测、未授权探测、命中后 enrichment 的内部边界已经基本清晰
- `zvas` 已存在成熟的 `center -> worker -> GoMap SDK` 集成模式，资产探测已采用本地 SDK 调用

当前真实需求不是把 GoMap 改造成常驻平台服务，而是把 `secprobe` 以与现有 GoMap 能力一致的方式，纳入 `center -> zvas worker -> GoMap` 的统一执行链。

本设计面向 `v1`，目标是把整条链路设计到“可直接开发”的状态。

## 2. 目标与非目标

### 2.1 目标

- 为 `center -> zvas worker -> GoMap` 定义一条完整的 `secprobe` 集成链
- 保持 GoMap 继续作为引擎端 SDK，而不是平台服务
- 为 GoMap `pkg/secprobe` 增加稳定的请求式集成入口
- 为 `zvas` 增加独立的 `secprobe` 路由、listener、process、mapper
- 明确 center 播种规则、worker 执行流程、结果落库方式
- 让结果同时保留：
  - 任务摘要
  - 原始 findings
  - 统一漏洞事实 `UnitVulnerability`

### 2.2 非目标

- 本次不把 GoMap 改造成 HTTP / gRPC 常驻服务
- 本次不让 worker 回查资产结果或依赖本地持久化
- 本次不开放 center 显式下发 `credentials[]`
- 本次不在 `v1` 放开复杂字典策略、批量喷洒策略、多目标编排策略
- 本次不把 `Stage`、`FailureReason`、`Capabilities`、`Risk` 直接稳定为平台契约
- 本次不要求 `v1` 立即开放完整 `unauthorized` 能力

## 3. 已确认的 v1 设计决策

本次讨论已确认以下硬约束，后续实现与计划均以此为准：

1. `v1` 只使用 GoMap 内置字典，不接收 center 下发 `credentials[]`
2. `zvas` 为 `secprobe` 新增独立路由体系，不复用现有站点 `weak_scan`
3. `center` 只从已有端口识别结果自动播种 `secprobe` 任务
4. 任务粒度采用 `1 host + N services`
5. 结果必须同时保留任务摘要、原始 findings、`UnitVulnerability`
6. GoMap 侧不再使用 `facade` 命名，命名风格需贴合现有 `assetprobe` / `secprobe`
7. `v1` 主能力只做 `credential`
8. `unauthorized` 与 `enrichment` 可以在 GoMap 请求模型中保留字段位，但 `zvas v1` 不作为默认开放能力

## 4. 方案对比

### 方案 A：`zvas` 直接长期调用 `pkg/secprobe.Run(...)`

做法：

- worker 直接构造 `[]SecurityCandidate`
- worker 直接构造 `CredentialProbeOptions`
- worker 直接调用 `secprobe.Run(...)`

优点：

- 接入最快
- GoMap 代码改动最少

缺点：

- `zvas` 直接依赖 GoMap 内部执行模型
- `SecurityCandidate`、`CredentialProbeOptions`、`BuildCandidates` 等内部概念会泄漏到平台集成层
- 后续 GoMap 若调整输入模型或选项结构，`zvas` 必须同步调整
- 不利于稳定 `center payload` 契约

### 方案 B：在 `pkg/secprobe` 内新增稳定请求式入口

做法：

- 保留现有低层入口 `Run(...)`
- 在同一个 `pkg/secprobe` 包内新增 `Scan(ctx, req)` 一类稳定集成入口
- `Scan` 内部负责：
  - 输入校验
  - `services[] -> SecurityCandidate`
  - `ScanRequest -> CredentialProbeOptions`
  - `RunResult -> ScanResult`

优点：

- 命名与 `GoMap` 现有风格一致
- 不新增概念上多余的子包
- 可以隔离 `pkg/secprobe` 当前内部输入细节
- 能让 `center payload` 与 `worker` 请求模型保持稳定

缺点：

- GoMap 需要补一层请求和结果映射
- 需要新增对应测试

### 方案 C：新增 `pkg/secprobe/integration` 子包

做法：

- 把稳定集成入口放进 `pkg/secprobe/integration`

优点：

- 包层次看起来更显式

缺点：

- 让同一能力出现两套公开入口
- 与当前 GoMap 命名风格不一致
- 调用方需要额外判断应该用哪个包

### 结论

选择方案 B。

即：

- GoMap 在 `pkg/secprobe` 内新增稳定集成入口
- 入口命名采用 `Scan(ctx, req)`，而不是 `facade`
- `Run(...)` 继续保留为低层候选执行入口

## 5. 总体架构

整体调用链定义如下：

1. `center` 基于结构化端口识别结果筛选 secprobe 支持协议
2. `center` 以 `1 host + N services` 为单位生成 queued unit
3. queued unit 的 `payload` 直接携带 `services_json`
4. `worker listener` 负责路由规范化和基础校验
5. `worker process` 将 `payload` 映射为 GoMap `secprobe.ScanRequest`
6. `GoMap secprobe.Scan(...)` 内部转为低层执行模型并调用 `Run(...)`
7. `worker mapper` 将结果收口为：
   - 任务摘要
   - 原始 findings
   - `UnitVulnerability`

职责边界定义如下：

- `center`
  - 负责从平台已有结果播种任务
  - 负责把平台上下文物化成可重放输入
- `worker`
  - 负责执行本地 SDK
  - 负责结果收口和事实映射
- `GoMap`
  - 负责探测引擎能力
  - 负责协议语义、内部选项、执行细节

## 6. zvas 路由与任务模型

### 6.1 独立路由体系

不复用现有站点 `weak_scan` 路由。

推荐新增：

- `StageSecprobe = "secprobe"`
- `TaskTypeSecprobe = "secprobe"`
- `TaskSubtypeHostWeakAuth = "host_weak_auth"`
- `RouteCodeSecprobeHost = "secprobe.host"`
- `TopicScanSecprobeHost = "scan.secprobe.host"`

原因：

- 现有 `weak_scan` 明显是 URL / site 语义
- 当前 `secprobe` 是 `host + services[]` 语义
- 两者请求模型、结果模型、播种方式都不同
- 后续 `unauthorized` 扩展也更适合在独立路由下演进

### 6.2 任务粒度

`v1` 固定使用：

- `1 host + N services`

不采用：

- `1 host + 1 service`

原因：

- center 的播种来源本来就是 host 级结构化端口结果
- GoMap 当前 `secprobe.Run(...)` 本就面向候选集合执行
- 更利于表达 host 级摘要字段：
  - `service_count`
  - `attempted_count`
  - `matched_count`
  - `partial_result`
- 能减少 queued unit 数量与调度碎片化

`1 host + 1 service` 可作为后续扩展策略，但不进入 `v1`

## 7. center 播种设计

### 7.1 播种来源

`secprobe` unit 仅从结构化端口识别结果派生，不从资产快照直接猜测生成。

### 7.2 播种规则

对每个 host：

1. 读取结构化端口结果
2. 只保留：
   - `open = true`
   - `service` 可归一化为 secprobe 支持协议
3. 将同一 host 的可支持服务聚合为一个 queued unit
4. 将服务列表序列化为 `payload["services_json"]`
5. 若该 host 无任何可支持服务，则不生成 `secprobe` unit

### 7.3 queued unit 推荐结构

- `RouteCode = "secprobe.host"`
- `Stage = "secprobe"`
- `Topic = "scan.secprobe.host"`
- `TaskType = "secprobe"`
- `TaskSubtype = "host_weak_auth"`
- `TargetKey = <host>`

`Payload` 至少包含：

- `target`
- `resolved_ip`
- `services_json`
- `task_type`
- `task_subtype`
- `source_asset_kind`
- `source_asset_key`
- `timeout_ms`
- `stop_on_success`
- `enable_enrichment`

## 8. center -> worker 任务契约

由于 `zvas/internal/platform/contracts/scan_unit.go` 中 `ScanUnit.Payload` 当前为 `map[string]string`，`services[]` 不采用多层结构字段，而采用 JSON 字符串承载。

### 8.1 Payload 约定

- `TargetKey`
  - 主机标识，建议为 host
- `payload["target"]`
  - 与 `TargetKey` 对齐的 host
- `payload["resolved_ip"]`
  - 可选；若 center 已有解析结果可直接下发
- `payload["services_json"]`
  - `[]ScanServicePayload` 的 JSON 字符串
- `payload["timeout_ms"]`
  - 可选
- `payload["stop_on_success"]`
  - 可选，默认 `true`
- `payload["enable_enrichment"]`
  - 可选，默认 `false`
- `payload["task_type"]`
- `payload["task_subtype"]`
- `payload["source_asset_kind"]`
- `payload["source_asset_key"]`

### 8.2 `services_json` 最小结构

worker 侧建议定义仅用于 payload 解析的结构：

```go
type ScanServicePayload struct {
    Host    string `json:"host"`
    Port    int    `json:"port"`
    Service string `json:"service"`
    Version string `json:"version,omitempty"`
    Banner  string `json:"banner,omitempty"`
    TLS     bool   `json:"tls,omitempty"`
    Source  string `json:"source,omitempty"`
}
```

```json
[
  {
    "host": "192.168.1.10",
    "port": 22,
    "service": "ssh",
    "version": "OpenSSH 8.4",
    "banner": "SSH-2.0-OpenSSH_8.4",
    "tls": false,
    "source": "port_scan"
  }
]
```

强契约字段仅为：

- `host`
- `port`
- `service`

其他字段为可选透传补充信息。

## 9. GoMap 侧稳定集成入口设计

### 9.1 入口位置与命名

推荐新增：

- 包位置：
  - `pkg/secprobe`
- 新文件：
  - `pkg/secprobe/scan.go`
  - `pkg/secprobe/scan_types.go`
- 新入口：
  - `func Scan(ctx context.Context, req ScanRequest) ScanResult`

理由：

- 与 `assetprobe` 公开入口风格一致
- 比 `Execute`、`ProbeServices`、`RunRequest` 更符合现有命名
- 不需要引入新的 `facade` 或 `integration` 术语

### 9.2 `ScanRequest`

```go
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
}
```

说明：

- `Target`
  - 对应 host
- `ResolvedIP`
  - 用于保持与内部连接逻辑一致
- `Services`
  - 直接贴合 `1 host + N services`
- `Timeout` / `Concurrency` / `StopOnSuccess`
  - 保留为最有价值的运行控制项
- `EnableEnrichment`
  - GoMap 继续保留字段位
- `EnableUnauthorized`
  - GoMap 请求模型中可保留字段位，但 `zvas v1` 默认固定传 `false`

`v1` 不在 `ScanRequest` 中暴露：

- `Credentials`
- `DictDir`
- 复杂协议 allowlist
- 复杂字典策略

### 9.3 `ScanResult`

```go
type ScanResult struct {
    Target     string
    ResolvedIP string
    Meta       SecurityMeta
    Results    []SecurityResult
}
```

说明：

- 尽量复用当前公开结果结构
- `Meta` 与 `Results` 延续当前 `RunResult` 语义
- 新增 `Target` / `ResolvedIP` 便于 host 级消费

### 9.4 内部映射职责

`secprobe.Scan(...)` 内部负责：

1. 校验 `ScanRequest`
2. 校验并归一化 `Services`
3. 将 `Services` 转为 `[]SecurityCandidate`
4. 将 `ScanRequest` 转为 `CredentialProbeOptions`
5. 固定走 GoMap 内置字典
6. 在 `v1` 默认固定 `EnableUnauthorized = false`
7. 调用现有 `Run(...)`
8. 将结果收敛为 `ScanResult`

### 9.5 不对 zvas 暴露的内部概念

不建议让 `zvas` 直接依赖：

- `SecurityCandidate`
- `CredentialProbeOptions`
- `BuildCandidates(...)`
- `RunWithRegistry(...)`
- `Registry`
- `DefaultRegistry()`
- `CredentialsFor(...)`
- `BuiltinCredentials(...)`
- `Stage`
- `FailureReason`
- `Capabilities`
- `Risk`

这些概念属于 GoMap 内部执行模型或后续演进预留，不应成为 `center` / `worker` 的稳定契约。

## 10. zvas worker 模块设计

建议在 `zvas/internal/worker/engines/attack/secprobe` 下新增独立引擎：

- `listener/secprobe_task.go`
- `listener/modules.go`
- `process/secprobe.go`
- `process/request.go`
- `process/modules.go`
- `mapper/result.go`
- `mapper/finding.go`

### 10.1 listener 职责

listener 只负责：

- 校验 unit 基本身份字段
- 规范化：
  - `topic`
  - `stage`
  - `task_type`
  - `task_subtype`
- 确认：
  - `TargetKey` 非空
  - `payload["services_json"]` 存在
- 补齐默认 payload 字段

listener 不负责：

- 服务列表构造
- GoMap 调用
- finding 映射

### 10.2 process 职责

process 只负责执行：

- 解析 `services_json`
- 构造 `secprobe.ScanRequest`
- 调用 GoMap `secprobe.Scan(...)`
- 产出任务级摘要结果

process 不负责：

- 协议语义解释
- `UnitVulnerability` 映射
- 结构化 port 结果回查

### 10.3 mapper 职责

mapper 只负责结果收口：

- 将 `ScanResult` 映射为平台任务结果 JSON
- 保留任务摘要字段
- 保留原始 findings
- 将成功 finding 映射为 `[]UnitVulnerability`

## 11. 结果模型设计

### 11.1 统一要求

`secprobe` 结果必须同时保留三层：

1. 任务摘要
2. 原始 findings
3. 统一漏洞事实 `UnitVulnerability`

`UnitVulnerability` 不是唯一存档，只是平台标准化投影视图。

### 11.2 任务摘要字段

worker 最终任务结果中建议稳定保留：

- `engine`
- `target`
- `resolved_ip`
- `service_count`
- `attempted_count`
- `matched_count`
- `partial_result`
- `error`
- `findings`

其中：

- `findings`
  - 直接保留原始 findings

### 11.3 原始 findings

原始 findings 尽量贴近 GoMap 公开结果语义。

每条 finding 至少保留：

- `host`
- `ip`
- `port`
- `service`
- `probe_kind`
- `finding_type`
- `username`
- `password`
- `evidence`
- `enrichment`
- `error`
- `raw`

`password` 可保留在原始 findings 中，用于闭环处置与审计。

## 12. `UnitVulnerability` 映射设计

### 12.1 映射原则

- 平台统一事实层负责标准化检索与告警
- 不要求承载全部 GoMap 内部语义
- 细节通过 `Raw` 和任务原始 findings 保留

### 12.2 `v1` 规则映射

由于 `v1` 主能力只做 `credential`，统一规则如下：

- `finding_type = credential_valid`
  - `RuleID = "gomap/secprobe/credential-valid"`
  - `RuleName = "协议弱口令命中"`

### 12.3 `Severity`

`v1` 统一映射为：

- `high`

原因：

- 该 finding 已经过实际认证成功验证
- 平台先统一为高危最稳
- 后续如有协议级差异需求，可再扩展映射表

### 12.4 `VulnerabilityKey`

建议由以下组合稳定生成：

- `host`
- `port`
- `service`
- `finding_type`
- `username`

便于同一账号重复命中时去重。

### 12.5 `Evidence` / `Classification` / `Raw`

`Evidence` 最少保留：

- `service`
- `probe_kind`
- `finding_type`
- `username`
- `evidence`

`Classification` 最少保留：

- `engine = "gomap-secprobe"`
- `category = "weak-auth"`
- `service = <service>`

`Raw` 直接保留原始 finding。

说明：

- `password` 不要求进入 `Evidence`
- `password` 仍保留在任务原始 findings 和 `Raw` 中

## 13. 错误、部分结果与重试语义

### 13.1 unit 成功

只要 GoMap `Scan(...)` 正常返回稳定结果，不管是否命中，任务都视为执行成功。

包括：

- 命中 `credential_valid`
- 未命中
- 有部分 service 失败但已返回稳定结果

### 13.2 unit 失败

只有整体执行无法得到稳定结果时，任务才视为失败。

例如：

- `services_json` 非法
- 请求字段缺失且无法构造 `ScanRequest`
- 调用 GoMap 直接报错且无稳定结果
- 执行前上下文已取消

### 13.3 未命中

未命中不是错误。

推荐结果语义：

- `attempted_count > 0`
- `matched_count = 0`
- `findings = []`
- `error = ""`

### 13.4 部分结果

当部分 service 已产出结果，但整体过程中有 service 失败、超时或取消时：

- `partial_result = true`
- `error` 保留任务级摘要错误
- `findings` 保留已得到的结果

### 13.5 重试粒度

`v1` 固定采用 unit 级重试：

- 即 `1 host + N services` 一起重试

不做：

- service 级拆分重试

## 14. 测试设计

### 14.1 GoMap

新增 `secprobe.Scan(...)` 相关测试，覆盖：

- `ScanRequest -> candidate/options` 映射
- 空 `services`
- 非法 `port`
- 非法或不支持的 `service`
- `v1` 固定内置字典策略
- `ScanResult` 结构稳定
- 不外露内部执行字段

### 14.2 zvas worker

覆盖：

- listener 路由规范化
- `services_json` 解析
- `ScanRequest` 构造
- 摘要结果映射
- 原始 findings 保留
- `UnitVulnerability` 映射
- 空结果 / 未命中 / 部分结果 / 整体失败

### 14.3 center

覆盖：

- 从结构化端口结果聚合 `1 host + N services`
- 不支持协议不播种
- 同 host 多端口正确聚合
- `services_json` 序列化正确
- 新 route / topic / stage / task_type / task_subtype 生效

## 15. 最小交付拆分

建议按以下四步交付：

### 第一步：GoMap

- 在 `pkg/secprobe` 内新增 `Scan(ctx, ScanRequest) ScanResult`

### 第二步：zvas worker

- 新增 `secprobe` 路由常量
- 新增 worker `listener/process/mapper`

### 第三步：center

- 从结构化端口结果播种 `secprobe` queued unit

### 第四步：结果落库

- 映射任务摘要
- 保留原始 findings
- 映射 `UnitVulnerability`

这样每一步都能单独验证，避免一次性把 center、worker、GoMap 改成一个大耦合变更。

## 16. 结论

`v1` 的推荐方案如下：

- GoMap 在 `pkg/secprobe` 内新增稳定入口：
  - `Scan(ctx, ScanRequest) ScanResult`
- `zvas` 新增独立 `secprobe` 路由体系，不复用现有 site `weak_scan`
- `center` 只从结构化端口结果播种 `1 host + N services` 的 secprobe unit
- `worker` 继续采用统一 `listener -> process -> mapper`
- 结果同时保留：
  - 任务摘要
  - 原始 findings
  - `UnitVulnerability`
- `v1` 只使用 GoMap 内置字典，主能力只做 `credential`

这条方案同时满足：

- 保持 GoMap 作为引擎端 SDK 的定位
- 保持 `zvas` 当前多引擎执行流程的一致性
- 保持 `center payload` 可重放、可审计、可排障
- 为后续 `unauthorized` 和更细粒度调度保留演进空间
