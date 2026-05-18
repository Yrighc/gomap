# GoMap 端口扫描主机存活验证与双阶段扫描设计

日期：2026-05-18

## 1. 背景

当前 `pkg/assetprobe` 的 TCP 端口扫描主链路采用“单 worker 串行完成端口连通性判断与服务识别”的执行方式：

1. 解析目标地址
2. 遍历端口表达式
3. worker 对单个端口执行 `DialTimeout`
4. 如果端口开放，则在同一个 worker 中继续执行服务识别
5. 汇总开放端口结果并返回 `ScanResult`

这一实现存在两个直接的性能瓶颈：

- 对于整机不可达或黑洞型目标 IP，扫描器不会先做主机级可达性验证，而是对全部端口逐个等待超时，导致单目标全端口扫描耗时极长。
- 对于可达目标，开放端口的服务识别会在同一个 worker 中串行执行，慢识别端口会占住 worker，拖慢后续端口发现，尤其在 `1-65535` 这类大端口范围扫描中影响明显。

当前仓库中存在历史遗留的 `DisablePing` 字段与 `PingHost` 方法，但它们并未接入现行 `port` 扫描主链路，因此当前实现本质上等价于“跳过 host discovery，直接扫描全部目标端口”。

本设计的目标是在不修改 `ScanResult`、`BatchScanResult` 及其 JSON 结构的前提下，引入可配置的主机存活验证能力，并把正式 TCP 端口扫描重构为“端口发现层 + 服务识别层”的双阶段内部流水线。

## 2. 目标与非目标

### 2.1 目标

- 为 `assetprobe` 新增独立的主机存活验证能力
- 支持多种主机存活验证模式：`ICMP Echo`、`TCP ACK`、`TCP SYN`、`ARP`，并允许扩展兼容模式
- 主机存活验证作为正式端口扫描前的显式阶段参与执行
- CLI 默认启用主机存活验证，并提供 `-Pn` 兼容参数来禁用该阶段
- 主机存活验证命中失败时，直接跳过该 IP 的正式端口扫描
- 正式 TCP 端口扫描内部重构为“端口发现层 + 服务识别层”
- 保持 `ScanResult`、`BatchScanResult`、CLI JSON 输出结构完全兼容
- 保持 `ScanTargets` 的目标顺序、局部失败隔离和整体返回契约

### 2.2 非目标

- 本设计不修改 `ScanResult`、`BatchScanResult` 字段
- 本设计不引入新的公开流式结果 API
- 本设计不改动 UDP 扫描模型
- 本设计不在本轮定义复杂的存活验证 DSL
- 本设计不要求首版必须在所有平台完整支持所有原始探测模式
- 本设计不解决首页识别、目录爆破或 `secprobe` 的调度问题

## 3. 方案对比

### 方案 A：仅新增常用端口预探测

做法：

- 扫描前固定探测少量常用 TCP 端口
- 若少量端口都无法命中，则跳过正式端口扫描

优点：

- 变更面小
- 能改善黑洞型 IP 的全端口扫描耗时

缺点：

- 只能表达一种非常窄的 host discovery 策略
- 无法覆盖 `ICMP Echo`、`TCP SYN`、`TCP ACK`、`ARP` 等通用模式
- 与用户期望的“独立主机存活验证能力”不一致

### 方案 B：仅重构正式扫描为双阶段流水线

做法：

- 不增加主机存活验证
- 仅把 TCP 扫描拆成“发现开放端口”和“服务识别”两段

优点：

- 能提升可达主机上的全端口扫描吞吐
- 不改变 CLI 默认入口语义

缺点：

- 对整机不可达目标几乎无帮助
- 无法解决黑洞型 IP 的海量端口逐个超时问题

### 方案 C：主机存活验证 + 双阶段正式扫描

做法：

- 在正式端口扫描前引入独立的 `HostDiscovery`
- 默认执行 `HostDiscovery`，`-Pn` 禁用
- `HostDiscovery` 未命中时直接跳过该 IP 的正式端口扫描
- 通过 `HostDiscovery` 后再进入“端口发现层 + 服务识别层”双阶段 TCP 扫描

优点：

- 同时解决黑洞型 IP 慢和开放端口识别阻塞两类核心性能问题
- 设计边界清晰，便于扩展更多主机发现模式
- 能与 `-Pn` 形成与 Nmap 接近的使用习惯

缺点：

- 会改变 CLI 默认行为
- 内部调度与测试复杂度高于前两种方案

### 结论

选择方案 C。

## 4. 总体设计

### 4.1 总体执行流

新的 TCP 扫描执行流定义为：

1. `ResolveTarget`
2. `HostDiscovery`（默认启用，`-Pn` 禁用）
3. `Port Discovery Stage`
4. `Service Fingerprint Stage`
5. 汇总并返回现有 `ScanResult`

若 `HostDiscovery` 未命中，则跳过步骤 3 和 4，直接返回空开放端口结果。

### 4.2 默认行为与 `-Pn` 兼容语义

CLI 语义调整为：

- 默认：先做 `HostDiscovery`，命中后再做正式端口扫描
- `-Pn`：禁用 `HostDiscovery`，直接执行正式端口扫描

这意味着当前项目的默认行为将发生变化：

- 现有用户升级后，不加 `-Pn` 时，部分目标可能在主机存活验证阶段被跳过
- 结果变少的原因是目标未通过主机存活验证，而不是端口扫描失败

该行为变更必须在 CLI 帮助文案与文档中明确说明。

### 4.3 对外兼容性边界

本轮只允许新增内部处理逻辑，不修改以下对外契约：

- `ScanResult`
- `BatchScanResult`
- `PortResult`
- `ToJSON(...)` 序列化结构
- `ScanTargets` 返回顺序与错误隔离语义

因此：

- `HostDiscovery` 的状态不直接暴露到 `ScanResult`
- 若目标在 `HostDiscovery` 阶段被跳过，对外只表现为“该目标没有开放端口结果”
- CLI 可以新增过程日志，但 JSON 结构保持现状

## 5. HostDiscovery 模块设计

### 5.1 模块定位

新增独立内部模块，建议路径为：

- `internal/hostdiscovery`

该模块职责单一：

- 在正式端口扫描前，对目标主机执行主机存活验证
- 只返回“是否命中可达信号”
- 不参与正式端口扫描结果建模

### 5.2 输入输出语义

建议统一入口语义如下：

```go
type DiscoveryMode string

const (
    DiscoveryICMPEcho  DiscoveryMode = "icmp-echo"
    DiscoveryTCPSYN    DiscoveryMode = "tcp-syn"
    DiscoveryTCPACK    DiscoveryMode = "tcp-ack"
    DiscoveryARP       DiscoveryMode = "arp"
    DiscoveryTCPConnect DiscoveryMode = "tcp-connect"
)

type DiscoveryOptions struct {
    Modes           []DiscoveryMode
    Timeout         time.Duration
    Retries         int
    Ports           []int
}

type DiscoveryResult struct {
    Matched bool
    Method  string
}
```

约束：

- `Matched=true`：至少一种模式拿到正信号，可以进入正式端口扫描
- `Matched=false`：所有可执行模式都未命中，直接跳过该 IP 的正式端口扫描
- 该结果仅用于内部控制流，不写入 `ScanResult`

### 5.3 支持的探测模式

首版设计支持以下模式：

- `icmp-echo`
- `tcp-syn`
- `tcp-ack`
- `arp`
- `tcp-connect`

说明：

- `tcp-connect` 不是设计初衷中的核心模式，但作为无特权环境兼容模式非常重要
- 它可作为 `tcp-syn` / `tcp-ack` 不可用时的降级选择

### 5.4 模式组合策略

默认采用“有序短路”策略：

1. 按用户配置顺序执行模式
2. 任一模式命中则立即返回 `Matched=true`
3. 未命中则继续尝试后续模式
4. 所有可执行模式都未命中时返回 `Matched=false`

不采用默认全并行的原因：

- 避免 `HostDiscovery` 本身变成高开销阶段
- 更便于控制权限需求与调试过程
- 更符合用户显式配置模式顺序的直觉

### 5.5 权限与环境降级策略

不同模式对运行环境的要求不同：

- 需要特权或原始套接字支持：
  - `icmp-echo`
  - 原始 `tcp-syn`
  - 原始 `tcp-ack`
  - `arp`
- 普通权限可运行：
  - `tcp-connect`

降级规则定义为：

- 某个模式不可执行时，不直接让整次扫描失败
- 记录该模式不可执行，并继续尝试后续模式
- 若用户启用的全部模式都不可执行，则返回错误给调用层

这样可以避免把“目标没有信号”和“当前环境无法执行探测”混为一谈。

## 6. 正式 TCP 扫描双阶段流水线

### 6.1 设计目标

正式 TCP 扫描阶段需要解决的问题是：

- 当前单 worker 模式下，开放端口的深度识别会阻塞后续端口发现
- 在 `1-65535` 这类全端口扫描中，整体耗时被少量慢识别端口放大

因此新的内部模型应将“端口是否开放”和“开放端口服务识别”拆为两个阶段。

### 6.2 第一层：端口发现层

端口发现层职责：

- 只负责快速判断端口是否开放
- 不做 banner 读取
- 不做 probe 匹配
- 不做 TLS 证书解析
- 不做 Web fallback

输入：

- 目标 IP
- 端口列表
- 发现阶段超时与并发配置

输出：

- 关闭端口：直接结束
- 开放端口：投递到服务识别层

这层的目标是以尽可能高的吞吐尽快扫完整个端口面。

### 6.3 第二层：服务识别层

服务识别层职责：

- 只消费发现层筛出来的开放端口
- 复用现有 `detectTCPServiceWithBudget(...)`
- 复用现有 `tcpservices.TcpPortServer(...)`
- 保留现有 `MaxFingerprintPorts` 和蜜罐判定逻辑

特点：

- 它是重任务层
- 并发必须与发现层分离
- 失败不应回退为整次扫描失败，只影响该端口识别完整度

### 6.4 双阶段调度收益

新的流水线可以把当前：

- “扫一个端口 -> 若开放则在同一个 worker 中完整识别 -> 再扫下一个”

重构为：

- “先快速遍历端口集合筛出开放端口 -> 再并发识别开放端口”

预期收益：

- 大量关闭端口能更快被清空
- 开放端口识别不再阻塞发现阶段吞吐
- 全端口扫描总耗时显著下降

### 6.5 两阶段与现有结果契约的关系

尽管内部执行流改变，对外仍保持：

- 最终只返回开放端口
- 返回时开放端口已经带有完整的服务识别结果
- `ScanResult` 字段不变

因此调用方无需感知内部是单阶段还是双阶段。

## 7. Scan 与 ScanTargets 的集成方式

### 7.1 单目标 `Scan`

新的 `Scan` 逻辑建议为：

1. 校验请求参数
2. 解析目标地址
3. 若协议为 `tcp` 且未显式禁用，则执行 `HostDiscovery`
4. 若 `HostDiscovery` 未命中，则直接返回空开放端口 `ScanResult`
5. 若命中或已通过 `-Pn` 禁用，则进入双阶段 TCP 扫描
6. 汇总开放端口与统计信息，返回现有 `ScanResult`

### 7.2 多目标 `ScanTargets`

`ScanTargets` 需要保证原有契约：

- 保持输入目标顺序
- 单目标失败不影响其他目标
- 每个目标独立产出结果或错误

因此建议：

- 每个目标独立执行 `ResolveTarget -> HostDiscovery`
- 未命中 `HostDiscovery` 的目标，直接构造空开放端口结果
- 只有通过 `HostDiscovery` 的目标才参与后续端口任务池

这样可以减少对黑洞型目标的无效端口任务展开，同时不改变返回顺序。

## 8. 错误处理与降级策略

### 8.1 HostDiscovery 错误分类

`HostDiscovery` 阶段需要区分三类结果：

1. 命中可达信号
2. 未命中可达信号
3. 当前模式不可执行

其中：

- “未命中”不是错误
- “模式不可执行”应继续尝试后续模式
- 只有“全部模式都不可执行”才应把该目标视为错误

### 8.2 正式扫描阶段错误策略

正式扫描阶段继续保持保守处理：

- 端口发现层单端口失败：按关闭处理
- 服务识别层单端口失败：保留该端口 `Open=true`，服务识别结果按现有语义降级为 `open` 或 `unknown`
- 不因单端口识别失败中断整次扫描

### 8.3 CLI 过程反馈

虽然 `ScanResult` 不改，但 CLI 可以增加过程日志，帮助用户理解阶段耗时：

- `host discovery start`
- `host discovery matched by tcp-syn`
- `host discovery no signal, skip target`
- `port discovery stage start`
- `service fingerprint stage start`

这些日志只作为控制台辅助信息，不影响 JSON 结果结构。

## 9. 配置与参数设计

### 9.1 CLI 参数语义

新增或调整参数建议如下：

- 默认启用 `HostDiscovery`
- `-Pn`：禁用 `HostDiscovery`
- `--host-discovery-mode`：指定模式列表，如 `icmp-echo,tcp-syn,arp`
- `--host-discovery-timeout`：单模式超时
- `--host-discovery-retries`：重试次数
- `--host-discovery-ports`：为 `tcp-syn` / `tcp-ack` / `tcp-connect` 指定探测端口

其中 `-Pn` 作为 Nmap 兼容参数保留简洁入口。

### 9.2 库层配置

库调用也需要有等价控制能力，但不改现有结果模型。

建议在扫描请求配置中新增 host discovery 相关选项，而不是混入 `ScanResult`。

是否对外公开新的请求字段，属于实现期 API 设计问题；本设计先只确定：

- 需要存在显式的启用/禁用能力
- 需要存在模式、端口、超时、重试配置入口

## 10. 测试方案

### 10.1 HostDiscovery 单元测试

覆盖以下场景：

- 单模式命中返回成功
- 多模式前置未命中、后置命中
- 模式不可执行时能继续降级
- 全部模式不可执行时返回错误
- 全部可执行但都未命中时返回 `Matched=false`

### 10.2 `Scan` 流程测试

覆盖以下场景：

- 默认启用 `HostDiscovery`
- `-Pn` 禁用 `HostDiscovery`
- `HostDiscovery` 未命中时返回空开放端口结果
- `HostDiscovery` 命中时进入正式扫描

### 10.3 `ScanTargets` 测试

覆盖以下场景：

- 多目标下部分目标被 `HostDiscovery` 跳过
- 结果仍按输入顺序返回
- 单目标解析失败或 discovery 错误不影响其他目标

### 10.4 双阶段扫描测试

覆盖以下场景：

- 发现层和识别层拆分后，最终开放端口结果保持兼容
- 开放端口仍能拿到完整服务识别结果
- 识别失败不会丢失开放端口

### 10.5 回归测试

保留并扩展当前：

- `pkg/assetprobe/scanner_test.go`
- `cmd/main_test.go`

重点保护：

- JSON 结构
- 目标顺序
- 空结果语义
- 批量扫描局部失败隔离

## 11. 风险与权衡

### 11.1 默认行为变更风险

默认启用 `HostDiscovery` 会改变当前项目行为：

- 某些目标会在 discovery 阶段被提前跳过
- 用户如果需要旧行为，必须显式使用 `-Pn`

这是本设计最大的兼容性风险，必须通过文档、帮助文案和变更日志明确告知。

### 11.2 平台与权限风险

部分 discovery 模式需要更高权限或原始套接字支持：

- 若环境不支持，应有清晰降级路径
- 实现中应避免把权限问题误判成目标不存活

### 11.3 复杂度上升

引入 `HostDiscovery` 与双阶段流水线后，内部复杂度会显著增加。

为控制风险，需要：

- 保持模块边界清晰
- 不修改结果模型
- 用测试锁住默认语义和兼容行为

## 12. 结论

本设计决定：

- 在 `assetprobe` 中新增独立 `HostDiscovery` 内部模块
- 默认启用 `HostDiscovery`
- 通过 `-Pn` 提供禁用 `HostDiscovery` 的 Nmap 兼容语义
- `HostDiscovery` 支持多种模式：`ICMP Echo`、`TCP ACK`、`TCP SYN`、`ARP`，并保留兼容模式扩展位
- 通过 `HostDiscovery` 后，正式 TCP 扫描内部重构为“端口发现层 + 服务识别层”双阶段流水线
- 整个设计只新增内部处理逻辑，不修改 `ScanResult`、`BatchScanResult` 和现有 JSON 结构

该方案能够同时改善：

- 黑洞型或整机不可达目标的全端口扫描耗时
- 可达目标在全端口扫描时因开放端口识别串行而导致的整体吞吐下降
