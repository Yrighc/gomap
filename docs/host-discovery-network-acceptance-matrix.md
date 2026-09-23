# Host Discovery 实网验收矩阵

状态：**授权 Linux/PVE 与临时隔离网络的 R3/R4 验收已完成；无路由缺陷已在本地 Docker Linux/arm64 和原 Debian 13/amd64 隔离 netns 中使用修复后版本实测通过**。受控单测、交叉编译或集成测试用例存在均不能替代这里的实测证据。

执行前提：得到目标、原始报文权限、抓包/资源观察方式的明确授权。不得用本机 loopback、模拟 runner 或模式返回值替代发包、RST 清理和取消回收证据。

| 场景 | 平台 / 架构 | 运行身份 / capability | 目标与路由前提 | 命令 | 预期 | 实际结果 / 证据 | 状态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 直连 IPv4 ARP | Debian 13 / amd64 | root | `.1/.100/.102/.110`，同一 `/22` | `...TestNativeLinux(ARP|AutomaticARP)Integration...` | ARP 命中；自动策略不追加 IP 探针 | 四个运行节点的显式及自动 ARP 均 PASS；CLI 自动发现四个节点 | 通过 |
| 经网关 IPv4 | Debian 13 / amd64 | root | 三个隔离 netns；目标经中间路由 namespace 可达 | `...TestNativeLinuxAutomaticRemoteIntegration...` 及 CLI | 自动进入 IP 计划；合法 lane 任一命中 | `ip route get` 显示经 `10.251.1.1`；集成测试 PASS，CLI 由 `tcp-syn` 命中并确认 2222 开放 | 通过 |
| 多网卡 | Debian 13 / amd64 | root | 非默认 `docker0`，目标 `172.17.0.2` | 同上 ARP/ICMP 集成用例 | 正确接口 / 源地址；不把网关 MAC 当目标 | `ip route get` 选择 `docker0` / `172.17.0.1`；ICMP、显式 ARP、自动 ARP 均 PASS | 通过 |
| 隧道 / 非以太网 | Debian 13 / amd64 | root | 两个隔离 netns 间的 `POINTOPOINT,NOARP` IPIP | 同上自动远端集成用例及 CLI | ARP 明确不可用并进入 IP 计划 | 路由选择 `tunhd0`；集成测试 PASS，CLI 由 `tcp-syn` 命中并确认 2222 开放 | 通过 |
| 无原始报文权限 | Debian 13 / amd64 | nobody | 隔离 veth 目标；ICMP 静默，2222 可连接 | `...TestNativeLinuxAutomaticConnectFallbackIntegration...` | SYN/ICMP 不可用后 Connect 命中 | 集成测试以普通用户运行并 PASS | 通过 |
| 跨调用权限恢复 | Debian 13 / amd64 | 同一进程 euid 65534→0 | `.1:22` | `permission-check 192.168.110.1 22` | 新调用重新检查能力并可使用原生模式 | 无权限 Connect 命中；恢复 root 后下一调用由原生 SYN 命中 | 通过 |
| 路由查询失败（原始复现） | Debian 13 / amd64 | root | 只有 loopback、无任何路由的隔离 netns | CLI 及自动远端集成用例，目标 `198.51.100.1` | ARP 不可用；不能把本地无路由归为目标无响应 | 修复前 `Run` 返回 `Matched=false, error=nil`，CLI 输出“未发现主机存活信号”；此行仅保留修复前的缺陷证据，修复后同环境结果见下方记录 | **历史失败，已完成复验** |
| 路由查询失败（修复后） | Docker Linux / arm64 | root，容器独立 network namespace | `--network none`，无对外路由；TEST-NET-2 `198.51.100.1` | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/hostdiscovery`；容器内 `GOMAP_HOSTDISCOVERY_NO_ROUTE_INTEGRATION=1 ... -test.run '^TestNativeLinuxNoRouteIntegration$'` | 全部无有效探针时经现有 error 返回路由原因，不向外部发包 | 自动、ICMP、SYN、Connect 均 `PASS`：`Matched=false`，错误链包含 `ErrProbeFailed`、`ENETUNREACH`；隔离测试二进制运行后清理 | **通过（Linux/arm64）** |
| 路由查询失败（修复后同环境复验） | Debian 13 / amd64，kernel 6.12 | root | 独立 netns，仅 `lo` UP、内核自动生成的 `tunl0` DOWN，无 IPv4 路由；目标 TEST-NET-2 `198.51.100.1` | 上传当前 Linux/amd64 测试二进制并校验 SHA256；`ip netns exec` 下启用 `GOMAP_HOSTDISCOVERY_NO_ROUTE_INTEGRATION=1`，运行 `TestNativeLinuxNoRouteIntegration` | 全部探针未能有效执行时通过现有 error 返回本地路由原因；不从宿主发包 | 自动、显式 ICMP/SYN/Connect 四项均 PASS；错误链校验 `ErrProbeFailed` 与 `ENETUNREACH`；同批分类与隔离保护测试均 PASS，namespace 与临时二进制已删除 | **通过（Debian 13/amd64）** |
| 无外部命令 | Debian 13 / amd64 | root | `PATH=/nonexistent` | 原生 ICMP/SYN/ACK/ARP 集成用例 | 原生模式不启动外部命令 | 四种原生模式均 PASS | 通过 |
| SYN 半开清理 | Debian 13 / amd64 | root | `.1:22` | SYN 集成用例，同时在 PVE `vmbr0` 抓包 | 命中后发送有界 RST；抓包无遗留半开会话 | pcap 顺序为 SYN → SYN/ACK → RST，地址、端口与序号关联正确 | 通过 |
| 取消后发包与资源回收 | Debian 13 / amd64 | root | 停止 VM `.103` 及 ICMP 静默隔离 veth 目标 | 资源 helper；3 轮 ICMP 配置下 100ms 取消；目标 netns nft 计数 | 取消后不开始新探针；socket / goroutine 回收 | 100 次取消后 FD `6→6`、goroutine `1→1`；隔离目标取消返回后计数 `1`，600ms 后仍为 `1`，未启动后续轮次 | 通过 |
| 无响应 | Debian 13 / amd64 | root | 停止 VM `.103` | `...TestNativeLinuxNoReplyIntegration...` | 正常未命中，不把无响应当错误或命中 | ICMP/SYN 各等待 2 秒并正常未命中 | 通过 |
| SYN 关闭端口 | Debian 13 / amd64 | root | `.1:65000`，PVE `ss` 确认无监听 | `...TestNativeLinuxSYNMatchesOpenAndClosedPortIntegration...` | RST 确认主机存活；不等同于正式端口开放 | 开放 22 与关闭 65000 均确认主机存活；CLI 只报告 22 开放 | 通过 |

## 已执行记录

| 日期 | 平台 / 架构 | 身份 | 目标 | 命令 | 实际结果 | 覆盖与限制 |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-09-22 | macOS / arm64 | `yrighc`（uid 501，未提权） | `127.0.0.1`、`::1` loopback | `GOMAP_HOSTDISCOVERY_INTEGRATION=1 GOMAP_HOSTDISCOVERY_ICMP4_TARGET=127.0.0.1 GOMAP_HOSTDISCOVERY_ICMP6_TARGET=::1 go test -v ./internal/hostdiscovery -run '^TestNativeICMPIntegration$' -count=1 -timeout=30s` | PASS：IPv4、IPv6 原生 ICMP Echo 均命中 | 只证明 macOS loopback 的原生 ICMP 收发；不提供 ARP、SYN/ACK、路由/多网卡、无权限降级、RST 清理或取消后发包证据。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | PVE `.1`，运行 VM `.100/.102/.110`，停止 VM `.103` | 上传当前工作区交叉编译的 `hostdiscovery.test` 与 `gomap`；运行表中集成测试和 `gomap port -ips ... -ports 22 -v -jl` | PASS：原生 ICMP/SYN/ACK/ARP、自动直连 ARP、无响应、关闭端口判活、CLI 前置发现及 SSH 服务识别 | 二进制 SHA 已在远端校验；物理 PVE 集群只有一个节点，另含三个运行测试 VM。未修改 PVE 配置、路由、防火墙或 VM 状态。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | euid 65534→0 | PVE `.1:22` | 临时验收 helper：同进程先无权限执行 SYN/Connect，再恢复 root 执行 SYN | PASS：raw SYN/ARP 权限错误分类明确；Connect 可用；恢复权限后原生 SYN 可再次使用 | 自动降级所需的“ICMP 静默 + Connect 可达”环境不存在，因此只证明显式降级和跨调用能力恢复。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | PVE `.1:22` | PVE `vmbr0` 上 `tcpdump`，同时执行 SYN 集成用例 | PASS：抓到 `.101 → .1` SYN、`.1 → .101` SYN/ACK、`.101 → .1` RST | 首次宽过滤抓到管理 SSH，已作废；本记录只采用收紧到 `.101 ↔ .1` 的三报文证据。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | 停止 VM `.103` | 临时验收 helper 连续执行 100 次 25ms 在途取消 | PASS：最大约 26ms；预热后 FD `6→6`、goroutine `1→1` | 证明 socket/goroutine 回收。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | 临时 netns：经网关 `10.251.2.2:2222`、IPIP `10.253.0.2:2222` | 自动远端集成用例及 CLI | PASS：经网关和 `POINTOPOINT,NOARP` IPIP 均由 `tcp-syn` 命中，端口扫描成功 | 全部 namespace、veth、IPIP 和 listener 已由 trap 删除；未改宿主路由、防火墙或 sysctl。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | nobody | 临时 veth `10.254.0.2:2222`，目标 namespace 忽略 ICMP Echo | 自动 Connect 降级集成用例 | PASS：ICMP 静默、raw 不可用时由 TCP Connect 命中 | 临时 namespace 和 listener 已删除。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | 临时 veth `10.250.0.2`，目标 namespace 忽略 ICMP Echo | 3 轮 ICMP 配置，100ms 取消；目标 namespace nft 统计 Echo 请求 | PASS：返回 `context canceled`；取消返回时 1 个请求，600ms 后仍为 1 | 与既有 FD/goroutine 证据合并，确认不启动后续轮次且资源回收。临时 nft table 随 namespace 删除。 |
| 2026-09-22 | Debian 13 / amd64，kernel 6.12 | root | 仅 loopback、无路由的临时 netns；TEST-NET-2 `198.51.100.1` | CLI 及自动远端集成用例（修复前） | FAIL：内部 `Run` 正常未命中且无错误，CLI 报“未发现存活信号” | 历史缺陷证据；未发送外部流量，修复后的 Debian 实测仍待重跑。 |
| 2026-09-22 | 本地 Docker Linux / arm64 | root（容器独立 netns） | `--network none`；TEST-NET-2 `198.51.100.1` | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c ./internal/hostdiscovery`，`docker run --rm --network none --user 0:0 --read-only -e GOMAP_HOSTDISCOVERY_NO_ROUTE_INTEGRATION=1 -v <test-binary-dir>:/data:ro --entrypoint /data/hostdiscovery.test postgres:16-alpine -test.v -test.run '^TestNativeLinuxNoRouteIntegration$'` | PASS：自动、显式 ICMP/SYN/Connect 四个子测试均经现有错误通道返回 `ErrProbeFailed` 和 `ENETUNREACH` | 集成测试先核对当前 namespace 只有 loopback 接口处于启用状态（允许 DOWN 的接口），且 `/proc/net/route` 无非 loopback IPv4 路由；在 `--network bridge` 下另验证会在探测前拒绝运行。该验证不等价于原 Debian/amd64 远端同环境复验；二进制已清理。 |

| 2026-09-23 | Debian 13 / amd64，kernel 6.12.86+deb13-amd64 | root | 临时 netns 中 TEST-NET-2 `198.51.100.1`（`lo` UP，`tunl0@NONE` DOWN，无 IPv4 路由） | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/hostdiscovery`；上传 SHA256 为 `d4ac607fc78c4f151d619af76332c36814889a70b62136773309c3d99731ed21` 的测试二进制；`ip netns exec <ns> env -i PATH=/usr/sbin:/usr/bin:/bin GOMAP_HOSTDISCOVERY_NO_ROUTE_INTEGRATION=1 <binary> -test.v -test.run '^TestNativeLinuxNoRouteIntegration$' -test.count=1 -test.timeout=20s` | PASS：自动、显式 ICMP、SYN、Connect 四个子用例均验证 `ErrProbeFailed` 与 `ENETUNREACH`；发送前 `EHOSTUNREACH`、TCP 读取后不可达无信号及隔离保护回归也在同一二进制下通过 | 首轮发现 Debian 新 netns 自动生成 DOWN 的 `tunl0`，过严接口检查在发包前拒绝；改为禁止启用中的非 loopback 接口，本地 Docker bridge 仍在探测前被拒绝。复跑同一 Debian 环境通过；测试 netns、临时二进制均已清理，未修改宿主路由、防火墙或 PVE 配置。 |

记录时补充完整命令、环境变量、目标所有权/路由说明、运行身份与 capability，以及必要的 pcap、socket/FD 观察或系统日志位置。缺少任一实际证据时保持“待授权”。
