# GoMap Host Discovery 完善路线

日期：2026-09-21

状态：R1、R2、R3 已完成验收；R4 直连 ARP、非默认接口、经网关、IPIP、自动 Connect 降级、能力恢复、取消及无路由错误分类均已通过授权 Debian 13/amd64 实网或隔离 netns 验证，无路由场景另通过本地 Docker Linux/arm64 验证；R5 本地兼容收尾与交付材料已完成，所依赖的 R4 实网门禁已关闭（不等于已执行发布）；R6 已完成独立修复验收。

## 1. 目标与已确认边界

GoMap 是引擎端，提供主机发现、端口探测、服务识别、页面获取及应用指纹等能力。业务流程编排、持久化、是否继续或复测由上层应用控制。本路线不设计“发现资产到漏洞探测”的内置业务流水线，不修改上层应用，也不扩展漏洞探测能力。

Host Discovery 同时保留两种入口，复用同一套实现：

1. 新增独立调用：接受目标和探测选项，返回发现结果，不自动触发端口扫描。
2. 保留 `Scan / ScanTargets` 的可选前置发现：命中后扫描端口，正常未命中时保持现有跳过行为；`HostDiscovery.Disabled` / CLI `-Pn` 继续跳过发现。

最终方向：GoMap 内置 ICMP、TCP SYN、TCP ACK、ARP 探测能力，不要求调用方另行安装 `ping`、`nping`、`arping`；保留 TCP Connect 作为无原始报文能力环境的降级方式。自动选择为主，显式模式可覆盖；ACK 不默认启用。

“内置”不等于全部手写。先借鉴已验证实现、评估成熟库，再确定最小实现方案；不将 Nmap/Nping 可执行文件打包当作原生能力的替代品。

## 2. R1 实施前代码基线与问题

以下是制定 R1 时的历史代码检查结论，用于说明修复来源；R1 后的实际状态见本节实施与验证记录。该记录不代表已完成真实服务器上的协议验证。

| 项目 | R1 实施前实现与证据 | 缺口 / 后果 |
| --- | --- | --- |
| 默认策略 | `pkg/assetprobe/scanner.go`：`applyDefaults` 设置 `icmp-echo,tcp-connect`，发现端口为 `80,443,22,445,3389` | 默认不使用 SYN/ACK/ARP，也不按网络条件选择 |
| 模式执行 | `internal/hostdiscovery/runner.go`：按 `Modes` 顺序运行，命中即返回 | 没有路由、接口、权限感知策略 |
| ICMP | `internal/hostdiscovery/icmp_echo.go`：启动系统 `ping/ping6` | 命令缺失、权限或执行错误可能被归为无响应 |
| TCP Connect | `internal/hostdiscovery/tcp_connect.go`：连接成功才命中，错误直接跳过 | 连接拒绝信号被忽略，可能漏掉其他端口提供业务的主机 |
| SYN/ACK | `internal/hostdiscovery/command_modes.go`：调用 `nping`，以输出包含 `RCVD` 判定命中 | 外部依赖；未结构化校验响应来源、类型、请求关联 |
| ARP | 同上：调用 `arping`，检查 `reply from / bytes from` | 外部依赖；依赖文本格式，缺少网络适用性判断 |
| 执行控制 | `Retries` 仅 TCP Connect 使用；SYN/ACK 为各端口分别创建超时；命令模式未一致传递父 context 取消 | 相同配置语义不一致，失败与取消可能被隐藏 |
| 结果 | `internal/hostdiscovery/modes.go`：仅 `Matched/Method`，另有 `error` | 内部缺少足够诊断信息；不要求因此扩展旧公开结构 |
| SDK 接入 | `pkg/assetprobe/scanner.go`：发现嵌入 TCP 扫描，未命中直接跳过 | 缺少独立公开发现入口；现有前置用法应保留 |

上层若仅指定 `ProtocolTCP`、未覆盖发现模式，走的是上述默认策略。TCP Connect 的握手本身包含 SYN，但不等于使用了独立 SYN 探针。不能仅凭模式枚举宣称 SYN/ACK/ARP 开箱即用。

风险分开处理：

- **假阴性**：存活目标未被发现；作为前置时可能跳过整台主机，导致端口和服务资产漏扫。
- **假阳性**：非目标或无关响应被当作存活；产生虚假存活记录和额外扫描成本，但不会直接把 TCP 端口判为开放。
- **执行失败伪装成无响应**：环境问题表现为目标问题，可能导致批量漏扫且难以定位。

## 3. 兼容约束

- 不修改现有 `ScanRequest`、`ScanCommonOptions`、`HostDiscoveryOptions` 字段布局及旧入口签名。
- 不向 `ScanResult`、`BatchScanResult`、`TargetScanResult`、`PortResult`、`ScanMeta` 增删字段或改变 JSON 字段布局。
- 不强制扩展 `ScanEvent`、`HostDiscoverySummary`、`HostDiscoveryTarget`；保留既有事件类型和字段契约。
- 单目标仍使用返回 `error`，批量仍使用现有目标级 `Error`；保持目标顺序、局部失败隔离和取消契约。
- 新独立调用是增量能力，旧调用方不必接入；新接口的最小结果模型不回灌旧端口结果。
- 命中端口、响应类型、模式失败原因等可保留在内部，必要时由新独立接口提供；不要求上层数据库或消息迁移。
- `ProtocolTCP` 只约束端口扫描协议，不限制前置发现必须使用 TCP；本路线不把 TCP 端口扫描改为 SYN 半开放扫描。
- 当前 UDP 端口扫描不执行前置发现，本路线不悄悄改变该行为。
- 结构兼容不等于结果不变：修复会让部分漏掉的目标被发现，也会使原先隐藏的错误显现。默认自动策略切换单独验收、单独说明。

## 4. 处理顺序

按 R1 → R2 → R3 → R4 → R5 逐项推进。R3 内部也分批交付，不一次性提交全部平台和协议。R6 是单独登记的 UDP 问题，不是主机发现的前置任务。

每阶段先形成针对该阶段的最小设计与验收清单，经确认后实施；前一阶段未通过验收，不继续下一阶段。遇到依赖、权限或环境阻塞，明确报告，不擅自安装系统工具、提权、访问服务器或扩大范围。

| 编号 | 交付项 | 状态 |
| --- | --- | --- |
| R1 | 判活语义与执行控制修复 | 已验收 |
| R2 | 独立 Host Discovery SDK 入口 | 已验收 |
| R3 | 内置 ICMP / SYN / ACK / ARP 探测 | 已实施；声明支持的 Linux 直连能力与 macOS ICMP 已实测，限制已记录 |
| R4 | 路由与能力感知的自动策略 | 已通过授权 Debian 13/amd64 隔离 netns 同环境复验及本地 Linux/arm64 验证 |
| R5 | 兼容回归与默认策略发布 | 本地兼容收尾已完成；R4 实网复验门禁已关闭，未执行实际发布 |
| R6 | UDP 开放判定问题，独立处理 | 已完成独立本地修复验收；不解除 R3/R4 实网门禁 |

### R1 — 先修可靠性，不切换默认模式

范围：

- TCP Connect 将明确的连接拒绝作为存活信号；不能把超时、网络不可达或任意连接错误都当作存活。
- 区分命中、正常无响应、模式不可用、执行失败、调用方取消；响应超时本身不等于执行失败。
- 某模式不可用可继续其他已允许模式；其他模式确认存活时仍可成功；全部无法有效执行时返回错误。部分失败且其余无响应的汇总规则须在本阶段明确，不能把失败计作成功执行，也不能任意错误都中断可用探测。
- 明确 `Timeout`、`Retries` 的单位和总预算；特别区分重试次数与总尝试次数。复用已有字段，不新增一组复杂配置；旧默认值含义不悄悄翻转。
- 修复父 context 取消传递、调度交接和资源清理，确保取消后不继续启动新探测。
- 外部命令过渡实现不能仅凭 `RCVD` 或通用文本就认定目标存活；无法校验的输出不作为正信号。优先最小修正，不为即将替换的文本接口建设复杂解析框架。
- 保持默认 `icmp-echo,tcp-connect`；本阶段不自动启用 SYN/ACK/ARP。

验收：

- [x] ICMP 无响应，TCP 返回连接拒绝：发现命中；但正式 TCP 端口探测仍将被拒绝端口视为未开放。
- [x] ICMP 无响应不能阻断后续可用探测；未知或异常命令输出不作为存活信号。
- [x] 命令缺失、权限失败、探测超时、父 context 取消具有可验证的不同处理。
- [x] 取消发生于派发、接收任务、等待及拨号/启动命令前等交接点时，不再开始新探测，已有资源能退出。
- [x] 重试与预算有确定性测试；现有前置扫描和 `-Pn` 相关回归通过。

实施记录：

- `internal/hostdiscovery/runner.go` 新增配置预校验、统一总尝试轮数调度，以及不可用/执行失败的顺序聚合；后续 R4 无路由修复将汇总语义明确为“命中优先、有效无信号其次、全部无法有效执行才返回错误”；公开 `Result` 与 SDK 结构保持不变。
- `internal/hostdiscovery/tcp_connect.go` 将明确连接拒绝识别为存活信号，按平台 errno 区分无响应、能力不可用和执行失败，并保持最多 8 个端口并发及命中后的在途清理。
- R1 当时的 `internal/hostdiscovery/icmp_echo.go` 使用 Linux/macOS 外部命令过渡实现；该路径已在 R3 被原生 ICMP 替换。
- R1 当时暂停的 `tcp-syn`、`tcp-ack`、`arp` 外部命令适配已在 R3 按平台矩阵替换为原生实现；模式名称和注册项未变。
- `pkg/assetprobe/scanner.go` 在单目标和批量前置交接处增加取消检查，批量结果预填目标，取消后不再创建端口任务；域名解析改为在扫描准备路径使用调用方 context。
- `HostDiscoveryOptions` 和 README 已明确 `Timeout` 是一次探针上限、`Retries` 是总尝试轮数，以及默认组合的等待预算。

验证记录：

- 通过：`go test ./internal/hostdiscovery -count=1`。
- 通过：`go test ./pkg/assetprobe ./cmd -count=1`。
- 通过：`go test -race ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1`。
- 修复了两个既有 CLI verbose 测试问题：结果型 stub 未触发实时事件，以及依赖真实 Scanner 初始化和固定 3 秒等待的时序测试；修正后普通及 race 模式各连续运行 20 次通过。
- 通过：`go vet ./internal/hostdiscovery ./pkg/assetprobe ./cmd`、LSP 错误检查及 `git diff --check`。
- 通过：`CGO_ENABLED=0` 下 Linux/macOS/Windows 的 amd64/arm64，针对 `internal/hostdiscovery`、`pkg/assetprobe`、`cmd` 的测试二进制编译检查。
- Linux/Windows 仅完成编译检查，未宣称平台运行验证；本轮未安装命令、提权、访问外部服务器或重做 Nmap 对比。

复验修复记录（2026-09-21）：

- `tcp_connect.go` 现在先采用明确平台 errno 的分类，再处理通用 `net.Error.Timeout()`；`EAGAIN/EWOULDBLOCK` 即使经 `os.SyscallError`、`net.OpError` 包装也保留为 `ErrProbeFailed`，不会伪装成无响应。
- `icmp_echo.go` 仅在本次探针 deadline 已实际成功请求终止命令时归为无响应。调用方取消、明确启动错误、正常成功和正常异常退出都以实际执行结果优先。测试使用 Go 测试二进制 helper 实际观测启动、调用方取消/自身超时后的 `Wait` 回收，以及启动前取消零进程。
- 本次通过：`go test ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s`、`go test -race ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s`、`go vet ./internal/hostdiscovery ./pkg/assetprobe ./cmd`、LSP 错误检查、`git diff --check`，以及 `CGO_ENABLED=0` 下 Linux/macOS/Windows × amd64/arm64 的三个相关包测试二进制编译检查。
- 本次通过：`GOMAXPROCS=8 go test -race ./internal/hostdiscovery -run '^TestTCPConnectReturnsAfterFirstMatchedPortAndCancelsInflightDial$' -count=1000 -timeout=60s`。该压力验证只覆盖 TCP 并发取消测试；跨平台运行验证仍未执行。R1 已验收；这里保留的是历史验证范围限制，不是 R1 的未完成状态。

### R2 — 新增独立发现入口，保留前置用法

范围：

- 在 `pkg/assetprobe` 增加独立 SDK 方法，接受 IP/CIDR 和探测选项；具体命名及最小签名在本阶段确定。
- 复用现有目标展开、结果顺序和局部错误隔离能力，不另建一套目标管理框架。
- 独立调用与 `Scan / ScanTargets` 前置调用使用同一发现实现。
- 独立调用正常无响应表示“未确认”，不是“确定离线”；执行失败经错误通道表达。
- 明确批量取消、部分结果、并发上限以及旧选项 `Disabled` 在新入口的含义，避免出现“禁用发现却报告存活”。
- 不增加业务编排、持久化或新的公开流式框架；本阶段不扩展 CLI 探针选项。

验收：

- [x] 独立调用只执行发现，不调用端口扫描、服务识别或页面获取。
- [x] 同一探针函数 `runHostDiscovery` 被独立调用及 `Scan`/`ScanTargets` 前置调用复用。
- [x] CIDR 展开、混合成功/失败、顺序、限额、并发及取消行为有受控测试。
- [x] 旧调用代码和旧结果结构无需修改；前置发现开启和关闭两条路径保留原有回归。

实施记录：

- `pkg/assetprobe/types.go` 追加 `DiscoverHostsOptions`、`BatchHostDiscoveryResult` 与 `TargetHostDiscoveryResult`，不修改任何既有扫描结果、事件或 JSON 结构。
- `pkg/assetprobe/host_discovery.go` 提供 `Scanner.DiscoverHosts`：支持零值 Scanner，局部应用既有默认配置和请求覆盖，忽略 `Disabled`，默认目标并发 `32`、展开去重上限 `65,536`；使用无缓冲 worker 任务通道，取消时等待在途 R1 探针清理并返回部分结果。
- `pkg/assetprobe/scanner.go` 将 CIDR 规范化最小抽取为可取消、可限量的内部实现；旧 `normalizeTargets` 仍为不设上限的包装入口，继续支持旧入口的域名语义。
- `internal/hostdiscovery/runner.go` 公开 `ValidateOptions`，使批次 SDK 和 `Run` 共用模式及 TCP 端口的配置校验。
- `pkg/assetprobe/host_discovery_test.go` 覆盖零值/Disabled、结果顺序、IPv4/IPv6 CIDR 边界、重叠去重、限额、切片隔离、共享配置预校验、并发边界和取消部分结果；受控并发测试不依赖 sleep。

验证记录：

- 通过：`go test ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s`。
- 通过：`GOMAXPROCS=8 go test ./pkg/assetprobe -run '^(TestDiscoverHostsConcurrencyBound|TestDiscoverHostsCancellationPreservesPartialResults)$' -count=100 -timeout=120s`。
- 通过：`go test -race ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s`、`go vet ./internal/hostdiscovery ./pkg/assetprobe ./cmd`、`git diff --check`。
- 通过：`GOMAXPROCS=8 go test -race ./pkg/assetprobe -run '^(TestDiscoverHostsConcurrencyBound|TestDiscoverHostsCancellationPreservesPartialResults)$' -count=100 -timeout=120s`。
- 通过：`CGO_ENABLED=0` 下 Linux/macOS/Windows × amd64/arm64，针对 `internal/hostdiscovery`、`pkg/assetprobe`、`cmd` 的测试二进制编译检查。编译不等同于跨平台运行验证。
- LSP 错误检查未发现诊断；其中一个 Go 服务为 silent-on-clean，未将其无输出表述为额外运行证据。R3 未自动开始。

### R3 — 分批内置报文能力，去掉命令依赖

#### R3.1 最小实现方案与平台边界

- 核对仓库已有依赖和已支持部署平台，参照成熟实现确定网络库与收发方式；不要仅凭开发机环境假定服务器平台。
- 明确各平台/地址族的协议支持、所需权限、运行时依赖和降级方式。不会因“编译进程序”就消除原始报文权限要求。
- 核查库的维护状况、许可证及是否引入额外本地库/驱动；避免消除命令依赖后又隐藏新的部署依赖。
- 给出最小发包、收包和请求关联方案；不提前搭建通用网络扫描框架。
- IPv4 为 ARP 适用范围；不把 IPv6 错送入 ARP。保持现有 IPv6 可用路径，原生协议覆盖逐项说明；NDP 不作为本轮完成前提。

#### R3.2 内置 ICMP Echo

- 替换系统 `ping/ping6` 依赖，校验响应地址、Echo 类型、标识与请求关联。
- 权限或平台不支持时返回能力不可用，允许策略层降级；不能静默改回依赖系统命令。

#### R3.3 内置 TCP SYN / ACK

- SYN 的有效 SYN/ACK 或 RST 可作为存活信号；ACK 的有效 RST 可作为存活信号。
- 校验地址、端口、标志及相应的序列关联；无关响应、迟到响应或其他目标响应不能误命中。
- 网关返回的 ICMP 不可达不能直接作为目标存活证明。
- 处理 SYN/ACK 后的连接清理、共享收包并发和资源释放，避免遗留半开状态；ACK 仅在显式策略允许时发送。

#### R3.4 内置 ARP

- 按正确出接口、源地址构造请求，匹配目标 IPv4、请求方地址和有效 ARP 回复。
- 只在适用的二层接口上使用，不能拿网关 MAC 当远端目标存活证据；记录代理 ARP 等网络行为的判定局限，不宣称 ARP 绝无误报。

验收：

- [x] 对声明支持的环境，未安装 `ping/nping/arping` 也能完成相应发现；运行路径不再启动这些命令。
- [x] 有权限、无权限、不支持平台/接口等路径有明确结果，不把环境问题伪装成目标无响应。
- [x] 报文构造、响应匹配、跨目标隔离、迟到/重复响应、超时及取消有受控测试。
- [x] ACK 默认不启用；原生主机探针不改动正式 TCP 端口扫描方式。
- [x] 原生网络路径在获授权且具备条件的环境完成验证；未验证的平台明确标记，不能仅凭 mock 测试宣称全部支持。

实施记录（2026-09-22）：

- Linux/macOS 的 `icmp-echo` 已改为 `x/net/icmp` 原生双栈收发，不再启动 `ping/ping6`；Linux ping socket 使用实际分配的 identifier，raw socket 只在能力错误时回退。
- Linux `tcp-syn`/`tcp-ack` 已接入 IPv4 raw IP 会话、仅 bind 的 TCP 源端口保留、最多 8 个在途端口、严格 token/flag 关联及 SYN+ACK 后有界 RST 清理；IPv6 明确不可用。
- Linux `arp` 已接入单目标 `RTM_GETROUTE`、直连路由/接口校验和 `AF_PACKET/SOCK_DGRAM` 收发；有 gateway、非以太网或无法确定源地址时明确不可用。
- macOS 的 SYN/ACK/ARP、Windows 的 ICMP/SYN/ACK/ARP 保持明确不可用；默认模式未改变，R4 自动策略未提前实现。
- 受控测试已在 macOS 运行，并通过 Docker Linux arm64 测试；Linux/macOS/Windows × amd64/arm64 均完成 `CGO_ENABLED=0` 编译。授权 Debian 13 / amd64 测试机已实测 Linux 原生 ICMP、SYN、ACK、ARP、开放/关闭端口判活、无响应和 SYN+ACK 后 RST；macOS / arm64 loopback 已实测 IPv4/IPv6 ICMP。平台矩阵中声明不支持的能力继续返回不可用，不以交叉编译冒充运行验证。
- 集成测试统一以 `GOMAP_HOSTDISCOVERY_INTEGRATION=1` 显式开启；开启后所有目标和端口变量均为必填，缺失必须失败而不能静默跳过。已执行命令、目标、权限和限制记录在 [host-discovery-network-acceptance-matrix.md](host-discovery-network-acceptance-matrix.md)。

### R4 — 自动选择，显式模式可覆盖

目标：调用方不需要为每台目标选择探针。依据系统已有路由、出接口及本机能力选择策略，不修改系统路由，也不声称能预知远端防火墙策略。

自动策略：

1. Linux 二层直连 IPv4 且 ARP 可用：仅执行 ARP；ARP 正常无响应时不追加 IP 层探针。
2. ARP 不适用或不可用、以及非 Linux 直连目标：每轮并发 ICMP Echo 与 TCP SYN；SYN 仅在不可用时同轮降级 TCP Connect。
3. ARP、ICMP、SYN 或 Connect 判定为不可用后，本次调用后续轮次不再重复打开对应 socket；SYN 不可用后若 Connect 可用则后续轮次直接使用 Connect。
4. ACK 不默认发送，只有显式配置时参与；显式 `Modes` 严格维持调用方顺序和范围。
5. 命中即取消并回收该目标剩余发现；正常未命中不等于离线；全部无法执行有效探测返回错误。

范围：

- 不用“私网/公网 IP”替代实际路由判断；覆盖网关、多网卡、VPN/隧道和非以太网接口。
- ARP 正常无响应明确为 ARP-only 重试，不追加 IP 层探测；`ErrModeUnavailable` 进入 IP 计划。ARP `ErrProbeFailed` 可继续独立 IP 探针：其他探针命中优先，至少一种实际可执行并正常无信号时返回未确认；仅所有允许的探针都无法有效执行时经现有错误通道返回原因。ICMP 与 SYN 的每轮预算重叠，命中立即停止后续轮次。
- 复用已有发现端口配置，自动策略不擅自扩成全端口扫描。
- 显式 `Modes` 保留顺序和限制，不偷偷加入未选择探针；只有自动模式负责自动组合与降级。
- 自动作为最终默认，需保留“调用方未指定模式”的信息；当前默认值填充逻辑不能提前把它变成显式旧模式列表。
- 控制目标及探针并发和报文预算，取消能贯穿路由选择、能力检查与收发；不引入跨系统调度依赖。

实施记录：

- `internal/hostdiscovery/runner.go` 保留非空 `Modes` 的顺序和重试；空 `Modes` 进入私有自动策略，不新增公开模式、结果字段或错误类型。显式和自动模式均按“命中 > 有效无信号 > 全部无法有效执行”汇总。
- 自动策略每轮先调用既有 ARP runner 作为目标级路由、接口和 `AF_PACKET` 能力判定；ARP 命中或正常无信号均只执行 ARP。ARP 不可用时进入 IP 计划；ARP 执行失败也可运行独立 IP 探针，若后者有效执行但无信号则整体返回未确认。IP 计划并发调度 ICMP 与 SYN，SYN 不可用时才运行 Connect；ACK 不进入自动路径。
- `pkg/assetprobe/scanner.go` 不再把空 Modes 填充为旧组合；`ScanTargets` 的发现调用受独立 32 目标 semaphore 限制，不受端口扫描并发度放大。
- 受控单测覆盖 ARP-only、ARP 不可用后 IP 计划、SYN→Connect 降级、ICMP/SYN 重叠、ACK 未调用、ARP 执行失败保留和批量发现 32 并发上限。授权 Debian 13 / amd64 环境已通过同二层自动 ARP、非默认 `docker0`、隔离网关、`POINTOPOINT,NOARP` IPIP、普通用户自动 Connect 降级、同进程权限恢复、取消后不启动后续轮次及资源回收。原无路由 namespace 复现出 ARP route-unavailable 后 ICMP/SYN/Connect 都把 `ENETUNREACH` 视为正常无信号；现已修复本地建链/发送阶段的错误分类，本地 Linux/arm64 无路由 network namespace 的自动和显式模式均返回错误，原 Debian 13/amd64 隔离 netns 已于 2026-09-23 使用当前交叉编译测试二进制复验：仅 loopback 启用，内核自动创建的 `tunl0` 处于 DOWN、无路由；自动与显式 ICMP/SYN/Connect 均通过现有 error 通道返回本地 `ENETUNREACH`。集成测试隔离保护已收窄为拒绝启用中的非 loopback 接口，并在 Docker bridge 环境验证探测前拒绝。

验收：

- [x] 空 `Modes` 自动策略与显式模式范围隔离；仅指定 `ProtocolTCP` 的调用可使用自动发现。
- [x] 默认不发送 ACK；`Disabled` / `-Pn` 继续在进入发现前短路。
- [x] 直连 IPv4、非默认 Docker 网桥、经网关与 IPIP 已在授权 Linux/PVE 环境实测通过。
- [x] 无路由分类已在本地 Docker Linux/arm64 独立 network namespace 中验证：自动及显式 ICMP/SYN/Connect 都经现有 error 通道报告无法执行，不再返回正常未确认。
- [x] 原 Debian 13/amd64 隔离 netns 的无路由场景已于 2026-09-23 使用修复后版本复验；自动与显式 ICMP/SYN/Connect 均报告本地路由错误，验收记录见实网矩阵。
- [x] “ICMP 静默但 Connect 可达”的自动无权限降级、跨调用权限恢复、取消后不启动后续轮次及资源回收均已在隔离网络实测通过。

### R5 — 兼容验收、默认策略切换与交付

范围：

- 在 R1—R4 验收后，明确发布“默认 ICMP→Connect 升级为自动策略”，不把它混同为结果完全不变的小修复。
- 文档说明权限要求、降级行为、协议/平台范围，以及通过显式 `Modes` 选择旧组合的方法；旧组合的判活错误不予保留。
- 更新 SDK 示例和 CLI 帮助中的实际能力描述，不再将命令封装描述为无条件可用。
- 检查既有事件及日志用语：未获取存活信号不等于确定离线；无需新增字段即可纠正文案。

验收：

- [x] 旧 SDK 调用样例编译通过，公开旧结构和 JSON 形状保持不变。
- [x] 单目标/批量、目标顺序、局部错误、取消、前置开关、显式旧模式、自动模式均通过回归。
- [x] `Scan / ScanTargets` 的 UDP 路径、服务识别和 Web 返回结构没有被本路线顺带改动。
- [x] 无外部探测命令环境和普通权限降级路径有验证记录；权限或平台验证缺失必须列为未完成项。
- [x] 更新本表状态，记录对应改动、测试命令及结果、限制与可定位代码证据，再交付上层验证。

### R6 — 单独登记：UDP 开放判定问题

本次检查还发现：`internal/updservices/updservices.go` 中的 `UcpPortServer` 在没有识别结果时会按端口服务表回填 `service`；`pkg/assetprobe/scanner.go` 的 `scanUDPPort` 接受非空 `service` 并设置开放。这意味着无实际响应也可能被服务表推断成开放，不能描述为“必须收到 UDP 响应才开放”。

- 单独确认并修复“响应证据”与“端口服务名猜测”的混用，不并入 Host Discovery。
- 保持既有结果结构，不因修复强制引入新的端口状态枚举。
- 验收至少覆盖：无响应但服务表有记录不能仅据此开放；实际有效响应无需匹配到产品名称也能作为开放证据。
- 此项待单独安排，不阻塞 R1—R5，也不扩展为整个 UDP 引擎重构。

实施与本地验收记录（2026-09-22）：

- `internal/updservices/updservices.go` 现以私有 `ProbeResult.Responded` 分离 UDP 数据报证据与服务名称；无 UDP probe、拨号/写入/读取失败或仅有服务表时均不返回响应证据。只有收到数据报（包括零长度）才允许未识别时的服务表猜测。UDP payload 解析继续保留旧有的通用转义回退，混合 ASCII、`\xNN` 与 `\0` 的 SNMP 等探针不会退化为空数据报。
- 每条 probe 以 `DialContext`、单一 deadline、同步写读和取消时关闭连接执行；每条探针独占连接与缓冲区，不再启动遗留 reader goroutine。调用方 timeout 现在覆盖该 probe 的拨号、写入及读取；内部非正值回退 3 秒。
- `pkg/assetprobe/scanner.go` 只以 `Responded` 设置 `PortResult.Open` 与开放事件；UDP 单目标和批量路径均传递 context，且仍不进入 Host Discovery。
- 通过：`GOMAP_HOSTDISCOVERY_INTEGRATION=0 go test ./internal/hostdiscovery ./internal/updservices ./pkg/assetprobe ./cmd -count=1 -timeout=120s`（225 tests）；对应 race 命令同样 225 tests；`go vet`、`git diff --check` 通过。
- 通过：新增 UDP/取消受控用例及 Host Discovery lane 用例在 `GOMAXPROCS=8`、`-race`、`-count=100` 下通过；其中覆盖跨 Run 的能力恢复、真实模式名的显式 ACK 顺序、DiscoverHosts / ScanTargets 默认 32 并发上限，以及 UDP 每 probe timeout、连接释放、超时后的后续 probe、取消后不启动下一 probe和混合编码 payload 兼容。Linux/macOS/Windows × amd64/arm64、`CGO_ENABLED=0` 的四个相关包测试二进制共 24 个均实际生成。原生集成开关关闭时显式 skip，未执行真实网络或权限测试。

## 5. 验证原则与不在本轮的事项

- 优先复用已有测试，新增受控网络响应、报文样例和路由/权限注入测试；不重新组织与 Nmap 的大数据量性能或准确率对比，不将 benchmark 或新样本集作为前置条件。
- 每阶段运行相关包测试；最终至少覆盖 `go test ./internal/hostdiscovery ./pkg/assetprobe ./cmd`，并按实际并发改动补充 race 检查。R1 已执行普通及 race 全量测试；后续阶段仍需分别重新验证。
- 原生发包验证只在明确授权的环境和目标上进行；权限不足或平台不可用时报告阻塞，不以替代命令输出冒充原生验证。
- 本轮不做：SYN 半开放端口扫描、UDP 主机发现探针、IPv6 NDP、操作系统识别、业务编排、漏洞探测扩展、上层应用迁移。
- IPv6 当前可用能力不得回退；本路线不承诺未设计、未验证的完整 IPv6 原生发现覆盖。

## 6. 历史文档关系

参考：

- [主机存活验证与双阶段扫描设计](superpowers/specs/2026-05-18-assetprobe-host-discovery-and-scan-pipeline-design.md)
- [HostDiscovery Review Fixes](superpowers/specs/2026-05-18-assetprobe-host-discovery-review-fixes-design.md)

历史文档保留为当时的设计记录。本路线延续其旧结果结构兼容和前置发现用法，后续分阶段升级其“固定默认模式、外部命令实现、TCP 连接错误统一视为无响应”等限制；不回头重做已完成的端口发现/服务识别双阶段拆分。
