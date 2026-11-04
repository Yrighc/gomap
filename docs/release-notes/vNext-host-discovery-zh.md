# GoMap Host Discovery / UDP 扫描变更说明（草案）

> 本文保留主机发现与 UDP 的历史预发布说明。正式发布内容及升级边界以 [v0.4.10 发布说明](v0.4.10-zh.md) 为准。

## 概览

Host Discovery 的未显式指定 `Modes` 默认行为已从固定串行 `icmp-echo → tcp-connect` 升级为按目标的自动策略。该变化可观察，不能视为“结果完全不变”的内部修复。

同时，UDP 端口只有在收到实际 UDP 数据报后才会判定为开放；服务表中的端口名称不再单独构成开放证据。

## Host Discovery 默认策略

- Linux 直连以太网 IPv4 且 ARP 可用：仅 ARP；正常无响应不追加 IP 层探针。
- Linux 非直连 IPv4：ICMP Echo 与 TCP SYN 并发；仅 SYN 明确不可用时降级 TCP Connect。
- Linux IPv6、macOS：ICMP Echo + TCP Connect。
- Windows：TCP Connect。
- TCP ACK 不会由自动策略发送，只能经显式 `Modes` 选择。

显式旧组合保持可用：SDK 调用方传入有序 `Modes: []HostDiscoveryMode{HostDiscoveryICMPEcho, HostDiscoveryTCPConnect}` 即可选择它。`nil` 请求覆盖继承 Scanner 配置；非 nil 空切片明确选择自动策略。

平台和权限边界：Linux 原生支持 ICMPv4/v6、IPv4 SYN/ACK 与直连以太网 IPv4 ARP；macOS 仅原生 ICMPv4/v6；Windows 保留 TCP Connect。原始报文权限、路由和接口条件不足时会降级或返回能力错误；不会调用 `ping`、`nping` 或 `arping` 作为替代。只有所有允许的探针均未能有效执行时才经原有错误通道返回诊断；任何有效命中优先，至少一项有效执行但正常无信号时返回未确认。

## UDP 开放判定

- `Dial` 或 `Write` 成功但没有接收数据报：不开放。
- 服务表有端口名称但没有 UDP probe 或没有响应：不开放，也不额外发送探针。
- 收到非空或合法零长度 UDP 数据报：开放；未匹配服务时才可使用服务表名称猜测，否则为 `unknown`。
- 单条 UDP probe 的拨号、写入和读取共用调用方传入的 timeout；非正 timeout 在内部回退 3 秒。

公开 `PortResult`、事件类型和端口状态枚举未增加字段。OpenPort / ServiceMatch 仍只在开放结果上触发。

## 验证边界

受控单测、race、vet、跨平台 `CGO_ENABLED=0` 编译及授权 Linux/PVE 实网验收见 [host-discovery-network-acceptance-matrix.md](../host-discovery-network-acceptance-matrix.md)。无路由修复已在本地 Docker Linux/arm64 及原 Debian 13/amd64 隔离 netns 同环境复验；相关 R4 实网门禁已关闭。该记录不替代正式发布检查，未实测的平台能力不因交叉编译而宣称通过。
