# AssetProbe HostDiscovery Review Fixes Design

## 背景

当前 HostDiscovery 已接入端口扫描流程，用于在正式 TCP 端口扫描前判断目标是否存在存活信号，并通过 `-Pn` 提供跳过探活、直接扫描端口的兼容语义。

本轮 review 暴露出两个核心偏差：

- HostDiscovery 的错误分类过粗，ICMP 超时会中断后续 `tcp-connect` 兜底，可能误伤禁 ping 但 TCP 端口开放的目标。
- HostDiscovery 的批量目标处理和 TCP 常用端口探测仍偏串行，不存活 IP 较多时，探活层本身会成为新的耗时瓶颈。

本设计只修复这些 review 问题，不扩大公开 API，不调整 `ScanResult` 结构，不重写 `tcp-syn`、`tcp-ack`、`arp` 的实现。

## 目标

1. 禁 ping 目标不能因为 ICMP timeout 阻断后续 TCP 探活。
2. ICMP 探活必须可被 context 取消，避免大批目标下遗留后台 ping 进程或 goroutine。
3. 批量目标扫描时，HostDiscovery 应按目标并发执行，避免不存活 IP 线性阻塞后续流程。
4. `tcp-connect` 常用端口探活应使用小并发竞速，任一端口命中即尽快返回。
5. 保持现有 CLI/API 形态，`-Pn` 仍表示禁用 HostDiscovery 并直接端口扫描。

## 非目标

- 不新增 `ScanResult` 字段。
- 不新增 CLI 参数，例如 `--host-discovery-concurrency`。
- 不改变默认 HostDiscovery 模式列表，仍为 `icmp-echo,tcp-connect`。
- 不重构 `nping`/`arping` 外部命令模式，只保留现有可选能力和降级行为。
- 不改变 UDP 扫描流程。

## 行为设计

### HostDiscovery 结果语义

HostDiscovery 内部按三类结果处理：

- `matched`：确认目标有存活信号，立即允许进入正式端口扫描。
- `no-signal`：当前 mode 没有探到存活信号，但这不是错误，应继续尝试后续 mode。
- `fatal error`：父 context 取消、配置不可用、内部不可恢复错误，应停止本目标扫描并返回错误。

ICMP timeout、ICMP no reply、TCP connect 失败都属于 `no-signal`。只有外层扫描 context 被取消时，才作为 fatal error 返回。

### ICMP Echo

`icmp-echo` 不再通过 goroutine 包装不可取消的 `achieve.PingHost`。实现应改为 context-aware ping：

- 每次 ICMP 探测使用 `context.WithTimeout` 控制单次预算。
- 底层使用 `exec.CommandContext` 启动系统 ping 命令。
- 超时或无响应返回 `Result{Matched:false}, nil`。
- 父 context 已取消时返回对应 context error。

这样可以避免 HostDiscovery 已超时返回后，系统 ping 仍继续运行。

### TCP Connect 探活

`tcp-connect` 对 `opts.Ports` 使用小并发竞速：

- 并发上限使用内部常量，不暴露为公开配置，建议为 `min(len(ports), 8)`。
- 任一端口 connect 成功后立即返回 `matched`，并取消剩余端口探测。
- 全部端口失败后返回 `no-signal`。
- 父 context 取消时尽快停止并返回 context error。

默认端口仍为 `80,443,22,445,3389`。该改动把 filtered 目标的最坏耗时从接近 `ports * timeout * retries` 收敛到接近 `ceil(ports/concurrency) * timeout * retries`。

### ScanTargets 批量探活

`ScanTargets` 的目标准备阶段改为并发执行：

1. 为每个输入目标保留固定结果槽位，保证输出顺序不变。
2. 每个目标独立执行 `resolveTarget`。
3. TCP 且未禁用 HostDiscovery 时，对该目标执行 HostDiscovery。
4. 未命中 HostDiscovery 的目标直接填充空 `ScanResult`。
5. 通过 HostDiscovery 的目标才创建 `batchTargetContext`，进入后续正式端口扫描任务池。

并发度不新增配置，复用现有 `portConcurrency` 作为上限，并限制不超过目标数量。这样保持配置简单，也让用户已有的 `-concurrency` 对整体扫描速度仍有直觉意义。

### 单目标 Scan

单目标 `Scan` 保持当前结构：

1. resolve 目标。
2. 若 TCP 且未禁用 HostDiscovery，则运行 HostDiscovery。
3. 未命中返回空结果。
4. 命中后进入 TCP discovery stage。
5. 仅对开放端口进入 fingerprint stage。

单目标性能收益主要来自 `tcp-connect` 探活端口竞速和 ICMP timeout 后的正确 fallback。

## 错误处理

- HostDiscovery mode 不可用仍按现有 `ErrModeUnavailable` 语义跳过。
- 所有 mode 都不可用时返回 `ErrNoUsableModes`。
- 单个 mode 的 timeout/no response 不应计为不可用，也不应终止 runner。
- 扫描父 context 取消时，应尽快返回 context error。
- `-Pn` 禁用 HostDiscovery 后，不受上述探活错误影响，直接进入端口扫描。

## 测试计划

### HostDiscovery 单元测试

- ICMP timeout 返回 no-signal，不返回 fatal error。
- ICMP 父 context 取消时返回 context error。
- runner 在 ICMP no-signal 后继续执行 `tcp-connect` 并可匹配成功。
- `tcp-connect` 在多个端口中任一端口成功时返回 matched。
- `tcp-connect` 在父 context 取消时尽快停止。

### Scanner 测试

- `Scan` 默认模式下，ICMP no-signal 后仍可通过 TCP 常用端口探活进入正式端口扫描。
- `ScanTargets` 对多个目标的 HostDiscovery 并发执行，并保持输出顺序。
- `ScanTargets` 中未命中 HostDiscovery 的目标不进入正式端口扫描。
- `-Pn` 或 `HostDiscovery.Disabled=true` 仍跳过 HostDiscovery。

### 验证命令

```bash
go test ./cmd ./pkg/assetprobe ./internal/hostdiscovery -v
```

必要时增加针对具体测试的 `-run` 命令，先看失败，再修复到通过。

## 风险与边界

- 并发探活会增加瞬时连接数，但默认常用端口数量很小，且复用现有 `portConcurrency` 上限，风险可控。
- `tcp-syn`、`tcp-ack`、`arp` 仍依赖外部命令，本轮不扩大使用范围；文档中应明确这些是可选模式。
- 保持 `ScanResult` 不变意味着用户无法直接区分“未存活跳过”和“扫描后无开放端口”，这是本轮已接受的约束。

## 成功标准

- 禁 ping 但 TCP 常用端口开放的目标不会被 ICMP timeout 阻断。
- 大批不存活 IP 的 HostDiscovery 不再按目标串行等待。
- 所有新增并发路径都有 context 取消测试。
- 现有 `-Pn` 行为保持兼容。
- 相关测试全部通过。
