# GoMap Host Discovery R4：自动策略一手来源研究

日期：2026-09-22

范围：2026-09-22 的只读研究快照；研究时未运行真实网络探针或修改代码。后续实现、实网验收及“有效无信号优先于部分探针失败”的最终汇总语义，以 [roadmap](../host-discovery-roadmap.md) 和[实网验收矩阵](../host-discovery-network-acceptance-matrix.md)为准；本文建议不代表当前行为。

Nmap 源码基线：[`d70c2d9fd18e1129f0ce1423629d14998808de4f`](https://github.com/nmap/nmap/tree/d70c2d9fd18e1129f0ce1423629d14998808de4f)（2026-09-22）。

本文把 **来源事实** 与 **对 GoMap 的建议** 分开。除标为“建议”的内容外，结论均直接来自 Nmap 官方文档/源码、Linux man-pages 或 Go 官方源码/文档。

## 结论摘要

| 问题 | 来源事实 | 对 GoMap R4 的建议 |
|---|---|---|
| 本地以太网 IPv4 | Nmap 默认用 ARP **替代** IP 层 discovery；ARP 扫描一旦执行，随后不会再调用 IP `massping`。ARP 正常无响应后不继续 ICMP/TCP。 | 路由确认直连、接口确认可 ARP 且 ARP socket 可用时，默认只做 ARP；只有 ARP **能力不可用** 才改走 IP 方案，不把“无响应”当“能力不可用”。 |
| 非本地默认探针 | 有原始报文权限时为 ICMP Echo、TCP SYN/443、TCP ACK/80、ICMP Timestamp；无特权 Unix 默认用 `connect` 对 80、443 发起 SYN。 | GoMap 已确定 ACK 不默认启用，因此自动组合取 ICMP Echo + TCP SYN；无 raw TCP 能力时取可用 ICMP + TCP Connect。端口沿用 `HostDiscovery.Ports`，不新增扫描端口。 |
| 并发与命中停止 | Nmap 的探针有优先顺序，但在同一异步扫描引擎和拥塞窗口内发送，不等待前一类失败后才发下一类；默认初始窗口为 10。收到任一存活信号后销毁该目标其他在途探针并停止新探针，但命中前已发出的包无法撤回。 | 自动模式按“轮”并发/重叠调度 ICMP 与 TCP，不复用当前显式模式的串行语义；命中后取消同目标剩余任务。显式 `Modes` 继续保持现有顺序。 |
| 权限不足 | Nmap 非特权时把 raw TCP/ICMP 方案降为 TCP Connect；显式 ACK 也会归并成 SYN Connect。Linux raw/packet socket 需要 `CAP_NET_RAW`，不能只按 UID 判断。 | 以实际 socket 打开结果判断能力；`EPERM/EACCES` 归为 `ErrModeUnavailable` 后降级。任意 `ErrProbeFailed` 不应静默伪装成降级成功。 |
| 预算/重试 | Nmap 固定 fresh probe 集合，使用拥塞窗口、RTT、自适应重传；默认重传上限为 10（每探针最多 11 次），但实际允许轮数从较低值开始随丢包证据增长。它不是简单的固定全局包预算。 | 不复制 Nmap 的完整自适应引擎。沿用 GoMap `Retries=总轮数`：每轮只发送选定的固定 probe 集，命中停止；总包数由公式明确约束。 |

## 1. 本地以太网目标：ARP 是替代，不是叠加

### 1.1 来源事实

Nmap 官方 Host Discovery 文档明确：默认远端 IPv4 探针是 `-PE -PS443 -PA80 -PP`，但“本地以太网目标”是例外，改用 ARP；即使用户指定其他 `-P*`，默认仍会执行 ARP，除非使用 `--disable-arp-ping` 或 `--send-ip`。文档同时指出 proxy ARP 会让未占用目标也显得存活，这是允许关闭隐式 ARP 的原因之一。

- [Nmap Host Discovery 官方文档](https://nmap.org/book/man-host-discovery.html)
- [同页：`--disable-arp-ping` 与 proxy ARP 说明](https://nmap.org/book/man-host-discovery.html#host-discovery-disable-arp-ping)

源码流程进一步消除了“ARP 后是否继续 IP ping”的歧义：

1. `setup_target` 通过路由结果记录 `direct_connect`、接口类型、源地址和 MAC。[`targets.cc#L375-L420`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L375-L420)
2. `refresh_hostbatch` 仅在以太网、真实 Ethernet datalink、目标直连且启用隐式 ARP 时调用 `arpping`，随后设置 `arpping_done=true`。[`targets.cc#L552-L577`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L552-L577)
3. IP 层 `massping` 只在 `!arpping_done` 时执行。因此只要本批已选择 ARP，ARP 无响应后也不会追加 ICMP/TCP。[`targets.cc#L591-L609`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L591-L609)
4. ARP 使用独立 `PING_SCAN_ARP`；初始 ARP RTT timeout 为 200 ms，而普通初始 RTT timeout 为 1 s。[`targets.cc#L83-L117`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L83-L117)、[`nmap.h#L187-L200`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.h#L187-L200)
5. 一旦收到关联 ARP reply，Nmap 标记 `HOST_UP` 并销毁该目标其他 ARP 在途探针。[`scan_engine_raw.cc#L1494-L1507`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine_raw.cc#L1494-L1507)

因此准确结论是：**Nmap 默认对直连以太网 IPv4 使用 ARP 替代 IP discovery；ARP 正常无响应即结束该 discovery，不做 ICMP/TCP 后备。** “先 ARP，失败再 IP ping”不是 Nmap 默认行为。

### 1.2 对 GoMap 的建议

1. R4 对 Linux 直连以太网 IPv4 采用同样边界：
   - 路由确认 `RTN_UNICAST`、有 `RTA_OIF`/有效源地址、无 `RTA_GATEWAY`/`RTA_VIA`/multipath/encap；
   - 接口 Up、非 loopback/point-to-point、可 ARP；
   - `AF_PACKET` ARP socket 实际可打开。
2. 上述条件成立时，自动策略只执行 ARP。达到 `Retries` 轮仍无响应，返回正常未命中；**不继续 ICMP/SYN**。
3. 只有准备阶段返回 `ErrModeUnavailable`（非 IPv4、非直连、接口不适用、缺少 `CAP_NET_RAW` 等）才重新规划为 IP 层方案。
4. 路由协议损坏、解析异常、收发异常等 `ErrProbeFailed` 保留为执行失败，不静默降级；否则会把环境故障伪装成正常探测。
5. 保留 proxy ARP 局限说明。自动策略不需要为此默认叠加 IP probe；显式 `Modes` 仍是调用方覆盖入口。

GoMap R3 已有可直接复用的事实来源和实现边界：`internal/hostdiscovery/route_linux.go` 已执行目标级 `RTM_GETROUTE` 并拒绝 gateway/via/multipath，`arp_linux.go` 已校验接口并用 `AF_PACKET/SOCK_DGRAM`。R4 不需要另建路由系统，只需把 ARP 专用判定结果提升为自动规划输入。

## 2. 非本地目标：默认探针、并发方式与命中停止

### 2.1 默认探针和端口——来源事实

Nmap 默认组合由官方文档和常量共同确认：

- 特权 IPv4：ICMP Echo、TCP SYN/443、TCP ACK/80、ICMP Timestamp，即 `-PE -PS443 -PA80 -PP`。
- 特权 IPv6：ICMPv6 Echo、TCP SYN/443、TCP ACK/80；无 ICMP Timestamp。
- 非特权 Unix：通过 `connect` 对 TCP 80、443 发起 SYN。

源码常量及注释称四探针组合是经验选择：[`nmap.h#L230-L243`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.h#L230-L243)。`validate_scan_lists` 按权限装载上述默认端口与类型：[`nmap.cc#L378-L434`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.cc#L378-L434)。

端口有一个容易误读的细节：

- **整体默认 discovery** 显式选择 SYN/443、ACK/80；
- 用户只写 `-PS` 而不带端口时，`-PS` 自身默认端口是 80；
- 非特权整体默认 Connect 是 80、443。

官方文档还确认：Connect 快速成功或 `ECONNREFUSED` 都说明底层收到 SYN/ACK 或 RST，因而目标存活；超时才是无响应。[Nmap Host Discovery：TCP SYN Ping](https://nmap.org/book/man-host-discovery.html)

### 2.2 并发而非串行回退——来源事实

Nmap 的探针选择有顺序：Echo → SYN → ACK → Timestamp → UDP/SCTP/Protocol；源码注释称按有效性排序。[`scan_engine.cc#L1273-L1444`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L1273-L1444)

但这个顺序只是**取下一个 fresh probe 的顺序**，不是“等待 Echo 超时后再发 SYN”的串行状态机：

- `doAnyNewProbes` 在全局和目标拥塞窗口允许时循环各未完成目标，不断发送下一探针。[`scan_engine.cc#L2235-L2264`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L2235-L2264)
- 主循环先安排重传和 fresh probes，再统一等待响应、处理状态。[`scan_engine.cc#L2785-L2802`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L2785-L2802)
- 默认 host/group 初始拥塞窗口均为 10，足以让单目标四个默认探针同时在途；多目标时会跨目标交错发送。[`timing.cc#L267-L274`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/timing.cc#L267-L274)
- 官方文档对多个 SYN 端口也明确写明 probes “will be sent in parallel”。[Nmap Host Discovery：`-PS`](https://nmap.org/book/man-host-discovery.html)

准确表述应是：**探针按优先级取出、由同一异步引擎在拥塞窗口内重叠发送；不是每类等待失败后才启动下一类。**

### 2.3 命中停止——来源事实

当 raw probe 得出 `HOST_UP` 时，Nmap 调用 `destroyAllOutstandingProbes`；Connect probe 得出 `HOST_UP` 时也相同：

- raw：[`scan_engine_raw.cc#L829-L839`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine_raw.cc#L829-L839)
- Connect：[`scan_engine_connect.cc#L318-L332`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine_connect.cc#L318-L332)
- `destroyAllOutstandingProbes` 的用途注释即“ping scan 已知 host up 后停止等待响应”。[`scan_engine.cc#L1571-L1584`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L1571-L1584)

这表示逻辑命中即停，但不能把已经送入网络的并发探针撤回。在大批目标、拥塞窗口尚未给该目标发完所有 fresh probes 时，命中还会阻止未发送部分；单目标默认四探针常会在第一次收包处理前已经全部发出。

### 2.4 对 GoMap 的建议

1. 自动模式的远端一轮探测应重叠执行：
   - raw TCP 可用：`ICMP Echo + TCP SYN(configured ports)`；
   - raw TCP 不可用但 ICMP 可用：`ICMP Echo + TCP Connect(configured ports)`；
   - ICMP 也不可用：`TCP Connect(configured ports)`。
2. ACK 保持路线图已定边界：不默认启用；仅显式 `Modes` 使用。
3. 自动模式沿用调用方或当前默认 `HostDiscovery.Ports`，去重后保持顺序；不新增端口、不做端口扫描。Nmap 的 443 可作为当前默认列表中 SYN 优先级的依据，但不能覆盖显式列表。
4. 任一探针命中后取消该目标同轮其他 goroutine/session，并阻止下一轮。已有 raw SYN 的有界 RST 清理仍需完成，不能因外层取消跳过必要清理。
5. 当前 `internal/hostdiscovery/runner.go` 明确按 `Modes` 串行执行。该语义应保留给显式模式；自动模式需要独立的最小 planner/executor，不能悄悄改变显式调用顺序。

## 3. 权限不足时的降级

### 3.1 Nmap——来源事实

`validate_scan_lists` 的非特权路径会：

- 默认只选择 TCP Connect，并使用 80、443；
- 将 ICMP 类型移除并改为 TCP；
- 将 TCP ACK/SYN 端口列表合并，最终按 SYN Connect 执行，因为非特权 `connect` 无法真正发送 ACK。

源码：[`nmap.cc#L378-L434`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.cc#L378-L434)。官方文档给出同样结论：[Nmap Host Discovery](https://nmap.org/book/man-host-discovery.html)。

Nmap 主要在解析阶段按是否有 raw 权限选择方案；若已经选择 raw scan、运行时仍无法打开 raw/ethernet handle，初始化会报致命错误，并非任意运行错误都自动改为 Connect。[`scan_engine.cc#L939-L970`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L939-L970)

### 3.2 Linux 与 Go 接口——来源事实

#### 路由和接口

Linux `RTM_GETROUTE` 提供目标路由结果；`RTA_OIF` 是出接口，`RTA_GATEWAY` 是网关，`RTA_PREFSRC` 是首选源地址，`RTN_UNICAST`/`RTN_LOCAL` 等给出路由类型。[`rtnetlink(7)`](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)

Go 标准库 `net.Interfaces`、`InterfaceByIndex` 和 `Interface.Addrs` 只提供接口及地址枚举；接口结构包含 Index、MTU、Name、HardwareAddr、Flags。[Go `net/interface.go#L29-L173`](https://go.dev/src/net/interface.go#L29-L173)。它不返回“内核针对某一目标最终选择的路由”。因此 Linux 自动策略必须使用 RTNETLINK（GoMap 已通过 `golang.org/x/sys/unix` 完成最小实现），不能仅用“目标是否落在某接口 CIDR”推断直连。

#### 原始报文能力

- Linux `AF_PACKET` 创建要求调用进程在其 network namespace 对应 user namespace 中具有 `CAP_NET_RAW`；可通过 `sll_ifindex` 绑定具体接口。[`packet(7)`](https://man7.org/linux/man-pages/man7/packet.7.html)
- IPv4 raw socket同样要求有效 UID 0 或 `CAP_NET_RAW`；无权限返回 `EPERM`。[`raw(7)`](https://man7.org/linux/man-pages/man7/raw.7.html)
- `CAP_NET_RAW` 明确授权 RAW 与 PACKET socket。[`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)

因此“是否 root”不是充分判断：容器中的 root 可能没有该 capability，非 root 进程也可能被授予 capability。最可靠的能力判断是实际打开所需 socket，并按 errno 分类。

#### TCP Connect

Go `net.Dialer` 提供 `Timeout`、`Deadline`、`LocalAddr` 和 `DialContext`，可在普通权限下执行有界 TCP Connect。[Go `net.Dialer`](https://pkg.go.dev/net#Dialer)。GoMap R1 已将明确连接拒绝归为存活信号，符合 Nmap 对 Connect host discovery 的官方语义。

### 3.3 对 GoMap 的建议：最小降级矩阵

| 条件 | 自动策略 |
|---|---|
| Linux、直连以太网 IPv4、ARP socket 可用 | ARP only |
| 直连 IPv4 但 ARP 返回 `ErrModeUnavailable` | 按远端 IP 方案：可用 ICMP + raw SYN；raw SYN 不可用则 Connect |
| 非直连 IPv4，raw ICMP/raw TCP 可用 | ICMP Echo + TCP SYN |
| raw TCP 不可用，但 ICMP ping socket 可用 | ICMP Echo + TCP Connect |
| ICMP 不可用，Connect 可用 | TCP Connect only |
| IPv6 | 不做 ARP；保留现有 ICMPv6，TCP raw 未支持时配 TCP Connect |
| 路由查询无法证明直连 | 不尝试 ARP；可继续 IP 层方案，但将路由诊断保留。若错误表明整个目标无路由，则按现有错误分类返回。 |
| 所有候选均 `ErrModeUnavailable` | 返回 `ErrNoUsableModes`/聚合不可用错误 |
| 任一候选 `ErrProbeFailed` 且没有命中 | 保持现有 R1 规则：执行失败优先返回，不把它折叠成正常无响应 |

能力探测应限定在目标实际需要的 socket 上，不做独立“预检发包”；打开 socket、查询路由不等于真实探针，不修改系统路由。

## 4. Nmap 可借鉴的预算与重试模型

### 4.1 来源事实

Nmap 的约束不是单个简单 `MaxRequests`，而是四层组合：

1. **固定 fresh probe 集**：默认特权 IPv4 每目标四种 probe；`numProbesPerHost` 根据启用类型和端口数计算。[`scan_engine.cc#L980-L1045`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L980-L1045)
2. **拥塞窗口**：host/group 初始均为 10，出现丢包后降低，正常响应后增长；默认最大窗口 300。[`timing.cc#L267-L292`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/timing.cc#L267-L292)
3. **自适应 RTT**：普通初始 1000 ms、ARP 初始 200 ms，默认最小 100 ms、最大 10 s。[`nmap.h#L187-L200`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.h#L187-L200)
4. **自适应重传**：默认 hard cap 是 10 次重传，即一个 probe 最多发送 11 次；但 `allowedTryno` 从至少 1 次重传开始，根据成功发生在更高 try number 的丢包证据提高，而不是一开始就预算 11 次。[`NmapOps.cc#L262-L273`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/NmapOps.cc#L262-L273)、[`scan_engine.cc#L675-L735`](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc#L675-L735)

命中后销毁其他在途 probe，使实际消耗通常低于“probe 数 × 最大重传”。但在单目标默认窗口内，多个 fresh probe 可能已在命中处理前发出。

### 4.2 对 GoMap 的建议

不要复制 Nmap 整个拥塞/RTT/重传引擎。GoMap 已有稳定公开语义：`Timeout` 是单次探针上限，`Retries` 是每 mode 的**总尝试轮数**。R4 应把它最小化为自动计划的确定预算：

#### 每目标、每轮 fresh probe 数

- 直连 ARP：`1`
- 远端 raw：`1 ICMP + P 个 TCP SYN`
- 降级：`I 个 ICMP（0 或 1）+ P 个 TCP Connect`

其中 `P = len(unique valid HostDiscovery.Ports)`；不添加 ACK，不添加未知端口。

#### 总发送上限

设 `R = max(1, Retries)`：

- ARP：`R`
- 远端 raw：`R × (1 + P)`
- Connect 降级：`R × (I + P)`

这是**发送尝试上限**；命中停止会减少实际数量。若某候选在发包前即能力不可用，不计真实发包，但要进入降级决策。

#### 时间上限

- 同一轮 ICMP 与 TCP 应重叠，而不是把 mode timeout 相加。
- 当前 native TCP 每批最多 8 个在途端口，因此 TCP 部分最坏批次数为 `ceil(P/8)`；当前默认 `P=5` 只需一批。
- 不新增复杂自适应字段。外层每目标总截止可由 `R × ceil(P/8) × Timeout` 加有界准备/清理余量推导；调用方 context 始终是更高上限。

#### 重试规则

- 一轮内只发送一次每种 fresh probe；整轮正常无信号后才开始下一轮。
- `ErrModeUnavailable` 触发同轮重新规划/降级，不消耗后续正常重试语义。
- `ErrProbeFailed` 不按“无信号”重试所有模式；沿用现有聚合规则。
- 保持当前默认 `Retries=1`，不因借鉴 Nmap 而暗改成 11 次；若未来需要自适应重传，应单独设计和验收。

## 5. 建议的 R4 自动决策流程

以下是建议，不是 Nmap 原样行为：

1. **保留意图**：只有调用方未显式给 `Modes` 时进入 auto；显式 `Modes` 继续走现有串行 `Run`，不自动增删模式。
2. **解析目标族**：
   - IPv4：执行目标路由查询；
   - IPv6：跳过 ARP，进入 IP 探针计划。
3. **直连 IPv4 ARP 分支**：复用 R3 的 route/interface/packet socket 判定。
   - 可用：执行 ARP-only，共 `R` 轮，命中停止；正常无响应后结束。
   - `ErrModeUnavailable`：进入 IP 计划。
   - `ErrProbeFailed`：保留失败，不伪装降级。
4. **IP 计划**：按实际 opener/socket 结果选择 ICMP、SYN 或 Connect；ICMP 与 TCP 同轮重叠，ACK 不参与。
5. **统一停止**：首个确认存活结果取消同目标剩余工作；等待资源回收和必要 SYN+ACK RST 清理后返回。
6. **统一汇总**：有命中则成功；无命中且有 `ErrProbeFailed` 则错误；至少一个可用模式正常完成则正常未命中；全部不可用则 `ErrNoUsableModes`。
7. **不做的事**：不按私网地址判断直连、不查询或修改系统路由、不引入外部命令、不新增端口、不默认 ACK、不把未命中写成确定离线。

## 6. 对四个问题的直接回答

1. **Nmap 本地以太网目标是 ARP 替代还是叠加？** 默认是替代。ARP 一旦选中，源码不再执行 IP `massping`；ARP 正常无响应后不继续 ICMP/TCP。只有显式禁用隐式 ARP或强制 IP 才使用 IP discovery。
2. **非本地探针是并发还是顺序？默认端口和命中停止？** 探针有 Echo→SYN→ACK→Timestamp 的发送优先级，但由异步引擎在拥塞窗口内重叠发送，不逐类等待。特权默认 SYN/443、ACK/80；非特权 Connect 80、443。任一存活信号命中后停止该目标后续探针并销毁在途状态，但已发包无法撤回。
3. **权限不足如何降级？** Nmap 非特权默认降为 TCP Connect，ACK 也无法保留为 ACK。Linux raw/packet socket看 `CAP_NET_RAW`，不应只看 UID。GoMap 应按实际 socket errno 将能力不足归为 unavailable，再降为可用 ICMP + Connect；运行失败不得静默降级。
4. **可借鉴的预算/重试？** 借鉴“固定 probe 集、并发窗口、命中停止、有限重传”，不复制完整自适应引擎。GoMap 用现有 `Retries` 作为固定总轮数，预算明确为 `R × 每轮 probe 数`，保持默认一轮。

## 一手来源索引

### Nmap

- [Host Discovery 官方文档](https://nmap.org/book/man-host-discovery.html)
- [`nmap.h`：默认探针、端口、RTT 与重传上限](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.h#L187-L243)
- [`nmap.cc`：按权限选择 raw 或 Connect](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/nmap.cc#L378-L434)
- [`targets.cc`：路由/直连判定、ARP 替代 IP massping](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L375-L420)
- [`targets.cc`：host batch 的 ARP 与 massping 分支](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/targets.cc#L523-L609)
- [`scan_engine.cc`：probe 顺序、调度、重试与停止](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine.cc)
- [`scan_engine_raw.cc`：raw/ARP 命中停止](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine_raw.cc)
- [`scan_engine_connect.cc`：Connect 命中停止](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/scan_engine_connect.cc)
- [`timing.cc`：默认拥塞窗口](https://github.com/nmap/nmap/blob/d70c2d9fd18e1129f0ce1423629d14998808de4f/timing.cc#L267-L292)

### Linux / Go

- [`rtnetlink(7)`：目标路由、OIF、gateway、preferred source](https://man7.org/linux/man-pages/man7/rtnetlink.7.html)
- [`packet(7)`：AF_PACKET、ifindex、CAP_NET_RAW](https://man7.org/linux/man-pages/man7/packet.7.html)
- [`raw(7)`：raw socket 与 EPERM/CAP_NET_RAW](https://man7.org/linux/man-pages/man7/raw.7.html)
- [`capabilities(7)`：CAP_NET_RAW 权限定义](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Go `net.Interface`/`Interfaces`/`Addrs` 源码](https://go.dev/src/net/interface.go#L29-L173)
- [Go `net.Dialer` 官方文档](https://pkg.go.dev/net#Dialer)
