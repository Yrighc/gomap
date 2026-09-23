# Host Discovery R3：原生探针实施计划

日期：2026-09-22

状态：历史 R3 实施计划；原生探针已完成受控测试、六目标编译及授权 Debian/PVE 与 macOS loopback 运行验证。后续 R4 已调整默认策略及错误汇总，当前状态以 [roadmap](../../host-discovery-roadmap.md) 和[实网验收矩阵](../../host-discovery-network-acceptance-matrix.md)为准。

依据：[Host Discovery roadmap](../../host-discovery-roadmap.md)。R1、R2 已通过功能验收。本计划不重做它们，不进入 R4 自动策略。

## 1. 已确定的范围

用户已确认：**Linux 完整实现原生探针，新增 SYN/ACK 首版只支持 IPv4。**

| 平台 | ICMP Echo | TCP SYN / ACK | ARP | TCP Connect |
| --- | --- | --- | --- | --- |
| Linux amd64/arm64 | 原生 IPv4、IPv6 | 原生 IPv4；IPv6 明确不可用 | 原生 IPv4，以太网直连适用 | 保留双栈 |
| macOS amd64/arm64 | 原生 IPv4、IPv6 | 明确不可用 | 明确不可用 | 保留双栈 |
| Windows amd64/arm64 | 本阶段明确不可用 | 明确不可用 | 明确不可用 | 保留双栈 |
| 其他系统 | 本阶段明确不可用 | 明确不可用 | 明确不可用 | 保留既有实现；不新增平台承诺 |

这里的“原生”是 GoMap 自行调用 socket 接口并构造、关联报文，不启动 `ping/ping6/nping/arping`。有权限和正确网络条件仍是必要条件；发布时须另外标记各平台的实际验证状态。

不做：SYN 端口扫描、UDP 主机发现、NDP、Windows/macOS 二层适配、CLI 新参数、自动模式、路由修改、提权、系统 sysctl 修改、上层业务编排。IPv6 不扩展 `%zone` 输入语法；缺少作用域信息的 link-local IPv6 不猜测接口，返回模式不可用。已支持的 IPv6 全局地址及 loopback 发现不得回退。

## 2. 兼容与依赖决策

### 保留现有调用契约

- 不修改公开方法、Options/结果字段、JSON、ScanEvent 或 `Scanner` 生命周期；不要求调用方新增 `Close`。
- `DiscoverHosts` 与 `Scan/ScanTargets` 继续复用 `runHostDiscovery → hostdiscovery.Run`。
- 默认仍为 `icmp-echo → tcp-connect`。SYN、ACK、ARP 仅在调用方显式选择时执行；ACK 不默认发送。
- 显式模式不偷偷增加其他协议。ICMP 在不同 ICMP socket 类型之间切换属于同一模式，不是自动策略。
- `Disabled`/`-Pn`、R2 默认并发 32 和 MaxTargets=65,536 不变。
- `Retries` 仍由 `Run` 统一管理：每模式的总尝试轮数；仅正常未命中重试。新 runner 内部不再增加重传轮数。
- `Timeout` 仍为单个探针预算，不是整批或整个模式所有端口的总时限。内部 runner 遇到 `Timeout<=0` 时沿用 R1 的 1 秒默认；SDK 现有默认填充与覆盖逻辑不改。

### 使用现有依赖，不引入捕获框架

- 将已经锁定的 `golang.org/x/net v0.50.0`、`golang.org/x/sys v0.41.0` 改为直接依赖；不借本次任务升级其他模块。
- ICMP 使用 `x/net/icmp`；TCP IPv4 使用标准库 IP socket 与 `x/net/ipv4.RawConn`；Linux ARP/route 使用 `x/sys/unix` 和标准库 netlink 解码辅助函数。
- 不引入 libpcap、Npcap、CGO、原生命令、新驱动或完整扫描器依赖。
- mdlayher/arp、packet、netlink 和成熟扫描器用于核对协议、收发和生命周期，不整库搬入。GPL/Nmap 代码只用于理解行为，不复制实现。
- 维持 `.github/workflows/release.yml` 的六目标 `CGO_ENABLED=0` 构建。

## 3. 最小内部结构与通用规则

### 资源归属

每次 `Runner.Run(ctx, ip)` 是一轮，拥有本轮 socket、关联记录和关闭操作。TCP 同目标本轮的端口共用一个收包 socket；不创建跨目标或进程级收包中心、持久化路由/权限缓存、后台常驻 goroutine。

- ICMP：本轮一个选定的 ICMP socket。
- TCP：本轮一个目标专用 raw IP socket，加一个仅 bind 的 TCP socket 保留源端口。
- ARP：本轮一次 route 查询和一个绑定接口的 AF_PACKET socket。
- `Run` 返回前完成全部关闭和必要的取消回调收尾；失败的初始化也不能遗留 FD。

测试接缝只放在实际变化处：打开 socket、Linux route 查询、收发与时钟/随机数。使用包内小接口或私有函数参数；不新增公开 transport/config 框架，不重构正式 TCP Connect 扫描。

### 超时与取消

- 进入模式、准备完成后、每次发包前以及收到响应后检查调用方取消；取消优先于命中和探针自身超时。
- socket 打开、route 查询等本地准备阶段有不超过 `Timeout` 的独立上限；准备超时不能冒充“已发探针但目标无响应”。
- ICMP/ARP 从本轮准备开始使用固定探针截止时间；不会因无关报文刷新期限。
- TCP 准备只做一次；每端口从开始发送时计算独立 `Timeout`，排队端口不提前消耗预算。最多 8 个在途端口，与现有 Connect 的规模保持一致。
- Go 网络连接使用 deadline；通过 `context.AfterFunc` 关闭连接唤醒等待，返回前确认回调不会继续操作已结束的会话。
- Linux 原始 FD 使用 nonblocking + `poll`；单次 poll 最多 50ms，并受实际剩余预算限制。取消时不从另一 goroutine 关闭可复用的裸 FD；由拥有该 FD 的执行路径退出并关闭。
- syscall 的 `EINTR` 重试；nonblocking 接收的 `EAGAIN/EWOULDBLOCK` 表示尚无数据，回到有期限的等待。不能照搬 TCP Dial 的 errno 分类把这种正常接收状态当成资源失败。

### 结果与错误

| 情况 | 结果 |
| --- | --- |
| 合法、匹配本轮的响应 | `Matched=true`，Method 为既有模式名 |
| 探针已成功发出，预算耗尽且未收到合法信号 | `Matched=false`、空 Method、nil error |
| 权限不足、协议/平台不支持、ARP 不适用或无法安全确定出接口 | 包装 `ErrModeUnavailable` |
| 本地资源耗尽、随机数失败、socket 配置失败、短写、无法完成准备、意外 I/O 错误 | 包装 `ErrProbeFailed` |
| 调用方取消/截止 | 原始 context 错误 |

- 明确 errno 分类优先于宽泛的 `net.Error.Timeout()`；仅真实等待期限到达才按无响应处理，保持 R1 修复。
- TCP/IP 的明确无路由、主机不可达和 ICMP socket 报告的目标不可达只表示无存活信号，不算目标存活；ARP 无可用直连 route 表示该模式不适用。
- 原始 TCP/ICMP socket 的 `ECONNREFUSED` 只按无存活信号处理，不能复用 TCP Connect 的“连接拒绝即存活”规则；原生 TCP 必须收到并关联合法 TCP 回包才能命中。
- 外部畸形/无关报文丢弃并继续等待；本地系统调用或本地协议解码设施失败不能被吞掉。
- `Run` 的“其他模式命中优先；没有命中时保留执行失败；仅不可用允许后续可用模式完成”聚合规则不变。

## 4. 原生 ICMP Echo

### 收发选择

Linux/macOS 首先尝试 `icmp.ListenPacket("udp4"/"udp6", wildcard)` 的非特权 ICMP socket；这里的 udp4/udp6 是库对 ICMP datagram socket 的命名，**不会发送 UDP 探针**。

只有在创建/必要能力配置阶段明确遇到权限或协议能力不可用时，尝试 `ip4:icmp` / `ip6:ipv6-icmp` 原始 ICMP socket。资源错误直接失败；已经发包后不通过重新打开另一个 backend 隐式重发；两者均不可用时交给既有模式序列继续处理，不回退外部命令。

### 请求与匹配

- 每轮重新生成 16 字节 `crypto/rand` nonce、sequence 和适用的 identifier。只发送一条 Echo Request，Code=0。
- Linux 非特权 ping socket 会由内核重写 identifier：从成功 bind 后的 `LocalAddr().(*net.UDPAddr).Port` 取得实际 ID，验证在 1..65535 后用于匹配；不得拿请求的随机 ID 直接比较。无法取得实际 ID 属于本地失败，不静默取消 ID 校验。
- macOS datagram socket 和 raw socket 使用本轮发送 ID。回应须同时满足：地址族相同、来源等于目标、Echo Reply 类型、Code=0、ID、sequence、完整 nonce 相等。
- 使用 `icmp.Message.Marshal` 和 `ParseMessage`；IPv4 出包校验和由库计算，IPv6 `Marshal(nil)` 由内核完成发送校验和。
- 兼容 macOS 非特权 IPv4 路径可能附带 IPv4 头的情况：先检查 version、IHL、实际收到的长度和协议，再决定是否剥离；不能无条件跳过 20 字节。
- 非 Echo Reply、网关 ICMP 错误、短包、旧 nonce、重复或其他目标响应均不命中。socket 隔离不是替代字段关联的理由。

删除旧 ICMP 命令构造、stderr 分类、进程回收 helper 及只针对它们的测试；以 native socket 的同等错误/取消/关闭测试替换，而不是删除对应行为覆盖。

## 5. Linux 原生 TCP SYN / ACK（IPv4）

### 会话与发包

1. 使用带 context 和准备上限的 `net.Dialer.DialContext("ip4:tcp", target)` 创建连接到目标的原始 IP socket。这里不建立 TCP 连接；由内核选择路由和本地 IPv4。使用 raw-IP 路由语义，不承诺与按 TCP 四元组、mark 等条件配置的复杂策略路由完全等价；不为此自行修改系统策略。
2. 验证获得的源地址，再包装 `ipv4.NewRawConn`。不以公网/私网判断路由，不自己 ARP 查询远端或网关 MAC。
3. 创建 `AF_INET/SOCK_STREAM` socket，bind 所选源地址和端口 0；读取并保留分配的端口直到本轮结束。**不 listen、不 connect、不设置地址复用**，避免探针与业务连接共用本地 TCP 端口。
4. 使用固定最小 TCP 头，无 payload/options；IPv4 TTL=64。显式构造并测试 TCP pseudo-header 校验和；IPv4 header 使用 `x/net/ipv4`，允许内核填充 IP ID/校验和。
5. 仅发送配置端口。新原生 runner 内部按首次出现顺序去重，最多 8 个在途；维护端口、seq、ack token、发送状态及独立 deadline。外层统一重试，不额外扩端口或自动补 Connect。
6. 一个调度/收包循环负责本轮端口的共享收包，独占关联表与 socket deadline；不由多个端口 goroutine 互改读取期限。读取期限为最近的在途到期时间；过期项退出窗口，再补入等待端口。最多 8 个在途请求不等于创建 8 个捕获线程。

`ValidateOptions` 把 `tcp-syn`、`tcp-ack` 加入需要有效 TCP 端口的模式，与 Connect 共用 `validPorts` 规则。无有效端口在 R2 派发前失败；不修改旧模式对混合合法/非法端口的既有过滤规则。

### 关联规则

所有候选响应先验证 IPv4/TCP 长度、协议、目标→本机的地址对、远端端口、本轮保留的本地端口及尚未过期的请求记录；不接收未发送端口。序号使用 uint32 模运算。

| 请求 | 允许的响应 | 必需关联 |
| --- | --- | --- |
| SYN，seq=S | SYN+ACK | ACK=S+1，且不含 RST/FIN 等冲突标志 |
| SYN，seq=S | RST+ACK | ACK=S+1，且不含 SYN/FIN |
| ACK，seq=S、ack=A | RST，ACK 位未设置 | SEQ=A，且不含 SYN/FIN |

- S/A 每轮、每端口随机生成，不使用 PID、固定 0 或固定常数作为关联依据。
- 采用上述 RFC 关联规则，不照搬 Nmap 针对异常协议栈的宽松兼容分支。可能漏掉非标准回复，必须说明这一覆盖边界，不声称与 Nmap 判活结果完全相同。
- 不接收无法证明关联的裸 RST 作为 SYN 命中，也不把任何 RST 一概当存活。
- 非首片/不完整报文、不相关 flag 组合、错误 token、重复和过期响应不命中。
- 本阶段只监听 TCP 响应；不把网关 ICMP 不可达当目标存活。收包软件检查不以 TCP checksum 为硬性匹配条件，避免把缺少 offload 元数据的 raw socket 字节误当成完整线缆校验和；出包校验和必须正确，收包的字段关联不能因此放松。

### 清理与错误汇总

- 有效 SYN+ACK 命中后，不完成三次握手；发送一次匹配该连接的 RST，SEQ 使用收到的 ACK。清理写入最多使用 `min(Timeout, 100ms)`，并服从调用方取消。
- 不安装防火墙规则抑制 Linux 自身 RST；内核自动 RST 不作为业务判活证据，也不替代受控测试中的清理验证。
- 清理是有界的尽力操作：写失败不推翻已确认的存活信号，不借现有 Error 字段把命中变成未命中；不承诺网络故障下可以强制消除远端半开状态。
- 命中后不再派发新探针，关闭本轮 raw socket 和保留端口。取消、初始化失败、发送失败也要走相同回收路径。
- 无命中时按端口顺序聚合错误：执行失败优先；有正常无信号结果可覆盖仅能力不可用的结果。保持与 `raceTCPConnectPorts` 一致的行为，不为此重构 Connect。

## 6. Linux 原生 ARP（IPv4）

### 只做发包所需的 route 查询

这是 ARP 正确执行的必要条件，不是 R4 自动策略。每轮向内核执行针对目标的 `RTM_GETROUTE`，不解析命令输出、不 dump 后自行挑“最像”的路由，也不修改路由或邻居表。

- 使用 `AF_NETLINK/NETLINK_ROUTE`、独立 socket/sequence；发起非 dump 的 `RTM_GETROUTE` 单目标请求，使用 `RTM_F_LOOKUP_TABLE`、IPv4 Dst_len=32 和 `RTA_DST`。校验 sockaddr 来源 PID=内核 0、消息序号及消息头 PID=本地 netlink port ID（不是一律要求消息头 PID=0），检查消息/属性长度、对齐及截断，处理 `NLMSG_ERROR`、`NLMSG_DONE` 和多消息回复。
- 读取实际出接口、preferred source、gateway/via、route type。仅接受单一、可确定的 on-link unicast 路由；有 gateway/via、local/blackhole/unreachable 路由、无法解析的多路径/下一跳 ID/封装、缺少可靠源地址均返回不可用，不猜测。
- 私有 route socket 的来源/序号/PID/结构错误按 `ErrProbeFailed` 处理；合法结果显示路由不适用于 ARP 才是 `ErrModeUnavailable`，两者不能混淆。
- preferred source 必须是该接口现有 IPv4；接口须 up、支持 ARP、具有 6 字节以太网 MAC，不是 loopback/point-to-point/tunnel。
- VLAN 使用内核 VLAN 接口，不自行构造 VLAN tag。桥接/虚拟以太网只在上述条件成立时适用。
- 旧邻居缓存命中不是新的存活证明；本轮仍需合法回复。

### 收发与匹配

- 使用 `AF_PACKET/SOCK_DGRAM`，绑定 route 指定的接口和 `ETH_P_ARP`（按网络字节序传给 socket/bind），不启用混杂模式。由内核处理以太网头；GoMap 构造标准 28 字节 Ethernet/IPv4 ARP 请求。
- 请求：本机 MAC、选定源 IPv4、目标 IPv4；通过该接口发往以太网广播地址。不能把目标替换成 gateway IP。
- 回复必须满足：正确接口与链路类型、`PACKET_HOST`（二层目的为本机）、ARP reply、Ethernet/IPv4 类型及长度、sender IPv4=目标、target IPv4=本机源地址、target MAC=本机接口 MAC。排除 outgoing、other-host、广播和组播接收副本。
- sender MAC 必须为有效单播 MAC，并与 AF_PACKET 返回的链路来源一致。畸形/无关包只丢弃，不延长预算。
- ARP 不包含 nonce/事务 ID：只能限定当前监听窗口和完整地址/接口关联，不能保证分辨字段相同的迟到重试回复。代理 ARP 也可能代答；文档必须明确这些协议局限，不能宣称证明了某台物理主机身份。

## 7. 顺序实施与阶段门禁

各阶段先补受控测试，再实现，阶段通过后进入下一项；不将整个 R3 一次性替换后才验收。

### S1：能力边界与公共基础

- 固定上述矩阵、错误分类、生命周期、包内测试接缝；保留现有公开类型。
- 拆分 `command_modes.go` 为 Linux factories 与非 Linux build-tag stub，避免与新 runner 重复定义；移除“R1 暂停外部适配”作为长期理由，改为准确的平台/地址族不可用原因。`command_modes_test.go` 改为平台/能力边界测试，Linux 协议测试由对应 native runner 测试接管。
- 先准备 stub 和编码/匹配测试，不提前开启缺少实现的模式。S3 接通原生 TCP 时同步扩展端口预校验。
- 验证六目标编译和 R1/R2 兼容测试；不要覆盖工作区中尚未提交的 R1/R2 改动。

### S2：双栈原生 ICMP

- 接入 Linux/macOS backend，删除外部 ping 依赖。
- 覆盖 ID 重写、nonce、IPv4 头兼容、能力切换、deadline 与取消关闭。
- Linux/macOS 授权环境分别验证 IPv4/IPv6；未验证的组合记录为待验收，不假装支持已验证。

### S3：Linux IPv4 SYN / ACK

- 实现 raw IP 会话、源端口保留、编码/严格关联、8 端口窗口及 RST 清理；接通 factories 和共享选项校验。
- 授权环境验证开放/关闭 TCP 端口、ACK→RST、无响应、取消及半开清理；验证实际发送的不是完整 TCP Connect。

### S4：Linux IPv4 ARP

- 实现最小 route 查询及 AF_PACKET 收发；对远端/隧道/未知路由安全拒绝。
- 授权直连以太网环境验证匹配、出接口和回收；跨网关目标不能通过探测网关被标记为目标存活。

### S5：R3 回归与交付

- 独立 SDK 与扫描前置分别走同一新实现，校验旧结果/事件/default/Disabled。
- 更新根 README、SDK README、roadmap：平台/地址族、权限、无外部命令、未验证项、显式模式示例；不切换默认自动模式。
- 留存每个平台/架构“编译”和“实际运行”的独立记录。所有本阶段声明支持的原生路径完成授权验证后，才标记 R3 验收完成；缺权限或环境就停在对应门禁报告阻塞。

## 8. 测试和验收清单

### 无权限、无外网的确定性测试

- ICMP：双栈报文；错误来源/type/code/ID/seq/nonce；Linux socket ID；macOS 有头/无头/短头；能力切换只发生在未发包阶段。
- TCP：出包校验和、完整匹配表、uint32 回绕、错端口/地址/seq/ack、冲突 flags、旧轮次/重复报文；共享收包只唤醒正确记录。
- ARP/route：直接/网关/local/隧道/多地址/不可确定路由；netlink 错序号、非内核来源、截断属性及 errno；ARP 所有关键字段和 AF_PACKET 来源不匹配。
- 控制：无关包洪泛也按期结束；准备失败不算无响应；资源错误不伪装为权限问题；Read/Write/Close 故障注入；FD/回调数归零。
- 取消：打开前零 socket/零发送，打开后发送前取消，接收等待中取消，多端口命中即停，新目标/新轮次不被旧回复命中。用 channel/受控时钟同步，不用 sleep 建立正确性。
- 边界：默认 32 目标不会绕过每目标 8 端口上限；显式模式不增协议/端口；IPv6 SYN/ACK/ARP 零发包且明确不可用；TCP Connect 的连接拒绝判活及正式端口扫描规则保持不变。
- SDK：`DiscoverHosts`、`Scan`、`ScanTargets` 的成功/无信号/不可用/失败/取消、顺序与部分结果回归。

### 实际网络验证（必须显式授权）

使用专用本地/隔离测试网络，不默认向公网发包，不重做 Nmap benchmark。

- Linux：原生 ICMP v4/v6；普通权限 ping socket；仅 CAP_NET_RAW 的 raw 能力；无相应权限；SYN 开/闭端口及 ACK；ARP 直连、经网关、无回应和接口不适用；并发目标互不串包。
- macOS：原生 ICMP v4/v6，特别验证 datagram ID/IPv4 头形态和无 root 的既有可用性。
- PATH 不含 ping/ping6/nping/arping 时仍能执行对应模式；检查引擎路径不调用这些程序。
- SYN+ACK 路径观察 RST 清理、不完成握手；取消后无新的业务探针派发、FD 和 goroutine 回到基线。
- 引擎不需要 CAP_NET_ADMIN；若测试采用 network namespace/veth，创建测试环境所需管理权限由测试操作者显式提供，不混同为运行依赖。
- 集成测试默认关闭，以 `GOMAP_HOSTDISCOVERY_INTEGRATION=1` 和明确目标配置启用；明确启用后缺目标/权限应失败，不以 skip 冒充验证完成。
- 若任一声明支持的 OS/架构无法实际验证，保留“编译通过、运行待验证”，不据此宣布整个支持矩阵验收完毕。

回归命令：

```sh
go test ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s
go test -race ./internal/hostdiscovery ./pkg/assetprobe ./cmd -count=1 -timeout=120s
go vet ./internal/hostdiscovery ./pkg/assetprobe ./cmd
git diff --check
```

此外逐个编译 Linux/macOS/Windows × amd64/arm64 的上述包测试二进制（CGO_ENABLED=0），对新增收发/取消/窗口测试重复运行；**编译不替代平台运行**。

## 9. 主要改动落点与参考依据

主要落点（文件可按现有风格拆分，不扩展职责）：

- `internal/hostdiscovery/icmp_echo.go`：改为原生 Echo runner，按平台提供 backend。
- `internal/hostdiscovery/tcp_raw_linux.go`、`tcp_packet.go`：原生 TCP 会话与纯报文编码/匹配。
- `internal/hostdiscovery/arp_linux.go`、`route_linux.go`、`packet_linux.go`：ARP、最小 route 查询与非阻塞 FD 收发。
- `internal/hostdiscovery/native_unsupported.go`、错误分类辅助文件：不支持的平台/地址族和可解释错误。
- `internal/hostdiscovery/runner.go`：仅接通 factories 与扩展 TCP 端口校验，保留聚合规则。
- 对应 `_test.go`、原生集成测试、SDK 共享路径回归；不重写 R2 目标管理。

一手依据（访问日期 2026-09-22；只借鉴已核实行为，实际依赖以 go.mod 固定版本为准）：

1. [Go x/net v0.50.0 icmp.ListenPacket](https://github.com/golang/net/blob/v0.50.0/icmp/listen_posix.go)：Linux/macOS 非特权 ICMP 与原始 ICMP。
2. [Go x/net v0.50.0 Message.Marshal](https://github.com/golang/net/blob/v0.50.0/icmp/message.go)：双栈校验和处理。
3. [Go x/net v0.50.0 ipv4.RawConn](https://github.com/golang/net/blob/v0.50.0/ipv4/packet.go)：IP header、收发及平台范围。
4. [pro-bing Linux matchID](https://github.com/prometheus-community/pro-bing/blob/main/utils_linux.go)、[processPacket / stripIPv4Header](https://github.com/prometheus-community/pro-bing/blob/main/ping.go)：Linux ID 差异、nonce/sequence 关联与 macOS 头兼容；GoMap 不照搬其放弃非特权 ID 比较的做法。
5. [Linux ping_bind / ping_v4_sendmsg](https://github.com/torvalds/linux/blob/master/net/ipv4/ping.c)、[ping_v6_sendmsg](https://github.com/torvalds/linux/blob/master/net/ipv6/ping.c)：端口分配与 identifier 重写。
6. [原生探测研究记录](../../research/r3-native-host-discovery-references.md)：ARP、netlink、TCP RST 规则、权限及参考库边界。
