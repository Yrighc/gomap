# R3 原生主机发现：源码依据

范围：Linux ICMP/SYN/ACK/ARP（TCP 探针仅 IPv4）；macOS 原生双栈 ICMP；其他平台 TCP Connect/不可用 stub。保留结果与 mode，R4 自动策略另做。本文只研究；未改 Go/go.mod、安装依赖、发探针或提权。ICMP 已由主审核实，不重复展开。

## 1. ARP：纯 Go 可行，但库的 Resolve 不是完整关联校验

[mdlayher/arp `Client.Dial/Request/WriteTo/Resolve`][arp]：经 `packet.Listen(interface, Raw, 0x0806, nil)`，自行编码 Ethernet+ARP；[packet `listen/bind/readFrom/writeTo`][packet] 使用 Linux `AF_PACKET/SOCK_RAW`、`SockaddrLinklayer`、`recvfrom/sendto`，不经过 libpcap/CGO，也不要求额外抓包驱动。[packet(7)][packetman] 明确链路头由调用方提供，创建需 `CAP_NET_RAW`；protocol 用网络字节序，ifindex 绑定出接口，`PACKET_OUTGOING` 表示本机发送副本。

**不能直接照搬**：`Resolve` 仅检查 Reply 与 SenderIP；`New` 取接口第一个 IPv4，并不查询目标路由。根据源码接口与协议字段，完整关联应核对：EtherType、Ethernet/IPv4 ARP 类型及长度、Reply、SenderIP=目标、TargetIP=本次源IP、TargetHardwareAddr=本机MAC、Ethernet 源MAC=ARP SenderMAC、目的MAC=本机MAC，并排除无效/组播 sender MAC、本机发送副本。这是研究推导的校验清单，不是该库已有保证。

发送前应按目标查询实际路由，核对单播、有效以太网出接口/源地址和**无 gateway/via**；不能只凭目标落在接口网段。若路由经 gateway，解析 gateway 的 MAC 只证明下一跳，不能判原目标存活。即使上述全部成立，[arp(7)][arpman] 的 proxy ARP 仍可代答；ARP 本身不能证明回答者一定是目标实体。

## 2. RTM_GETROUTE：可做最小查询，不等于省略协议处理

[netlink `Handle.RouteGetWithOptions`][route] 发送 type=`RTM_GETROUTE`、flags=`NLM_F_REQUEST`（不是 dump），内容为 `rtmsg{Family, Dst_len=32/128, Flags=RTM_F_LOOKUP_TABLE}` 与 `RTA_DST`；可选源地址、OIF、mark、UID。接收 `RTM_NEWROUTE`，`deserializeRoute` 提取 OIF、PREFSRC、GATEWAY、VIA、Type 等。[rtnetlink(7)][rtnlman] 给出消息/属性格式。因此已有 x/sys 足以支撑最小只读请求，不必为一次查询实现或引入整套路由管理；但复杂多路径/封装不能忽略后误判直连。

[nl `NewNetlinkRequest/executeIter/Receive/getNetlinkSocket`][nl] 可定位：递增 Seq，检查来源 sockaddr PID=内核0、响应 Seq=请求 Seq、消息头 PID=本地 port ID（不是一律0），处理 ERROR/DONE/MULTI；独占 socket 序号错即报错，共享时跳过。自行实现仍需长度、对齐、截断、errno 检查。

该版本使用非阻塞 FD + `os.File.SyscallConn`/Go poller，`Receive` 设置 deadline，兼容映射超时为 EAGAIN；不是旧版阻塞 `SO_RCVTIMEO` 实现。`Handle.SetSocketTimeout` 可设置时限，但 RouteGet **不接收 context**，且每次 Receive 重新起算。若自行最小实现，取消须连接到 pollable FD 的 Close/提前 deadline，总截止时间不能因无关报文重置；仅 select ctx 后遗留阻塞读取并不算取消。不要为一次取消关闭他人共享 Handle。

## 3. TCP：核实主审拟议做法及限制

**未发现系统禁止“每目标每轮私有 raw socket + 仅 bind 的 TCP 端口保留 socket”。**这是源码核实，不是运行验收，也不意味着成熟扫描器都采用同样布局。

- [Go1.24.6 `sysDialer.dialIP`][godialip] 对 `DialContext("ip4:tcp", target)` 创建 `SOCK_RAW`，不是 TCP Connect。[Linux `raw_prot.connect`][linuxraw] 指向 [`ip4_datagram_connect`][linuxdatagram]：查询路由并设置源地址，不发三次握手；可从 LocalAddr 取源IP。但这不是按最终 TCP 源/目的端口完成的四元组策略路由查询。
- [x/net v0.50.0 `NewRawConn`][rawendpoint]、[`packetHandler.WriteTo/ReadFrom`][rawconn] 使用 IP_HDRINCL 和内部 SendMsg/RecvMsg。[内部 `sendMsg`][sendmsg] 直接访问 FD，绕过标准库 connected `IPConn.WriteTo/WriteMsgIP` 的 `ErrWriteToConnected` 限制；Linux `raw_sendmsg` 支持指定目标地址。因此 **RawConn 路径不能与 IPConn.WriteTo 混为一谈**。发送需构造 IPv4/TCP 头及 TCP 伪首部校验和；内核补 IPv4 校验和，不代算 TCP 校验和。IP_HDRINCL 报文受 MTU 限制、不自动分片。[raw(7)][rawman]
- raw socket 不保留 TCP 端口。普通 `SOCK_STREAM` 在选定本地IP上 `bind(:0)`，保持 FD、不 listen/connect，可由 [`inet_csk_get_port/inet_csk_bind_conflict`][bindport] 分配并占用端口；不要开启端口复用或 `IP_BIND_ADDRESS_NO_PORT`。占位不构成已建立连接，也不阻止内核对未建立连接的 SYN+ACK 自动 RST；[`tcp_v4_rcv/no_tcp_socket`、`tcp_v4_send_reset`][linuxtcp] 明确此行为。它避免正常 socket 端口冲突，但消耗 FD/临时端口，释放后仍须防迟到响应串轮。
- `raw_v4_match/raw_v4_input` 按协议、地址/接口过滤并向每个匹配 socket 复制，**不按 TCP 端口分流**；私有 socket 仍须核对双向地址、端口、flags、序号和长度边界；不能无条件要求入包 TCP checksum 软件验算通过（见下）。同目标并行 socket 可各收同一报文。[linuxraw]
- [DialContext 文档][godial] 明确连接成功后 ctx 失效不影响连接；后续收发必须另接 deadline/取消 Close，不能只依赖 DialContext。

### 入包 checksum：不能把 raw socket 等同于已验算的 TCP socket

**有一手证据支持误丢风险，不只是 pcap 抓发送包的现象。**Linux v6.12 [`skbuff.h` 的“skb checksums”][skbuff] 明文允许接收路径存在 `CHECKSUM_PARTIAL`（虚拟化、GRO、remote offload），由 skb 元数据表示校验状态；普通物理网卡 RX offload 则不得改写包内校验和，二者不能混称。

[`loopback_xmit/gen_lo_setup`][loopback] 宣告 `NETIF_F_HW_CSUM`，原 skb 回注接收队列，不补全 TCP checksum；[`tcp_init_nondata_skb`][tcpoutput] 设置 PARTIAL，`__tcp_v4_send_check` 写入待完成的伪首部值。随后 `raw_v4_input` 克隆报文，`raw_recvmsg` 直接 `skb_copy_datagram_msg`，没有 TCP 校验和补全。[`skb_copy_datagram_iter`][datagram] 也只是复制。这条源码链说明：raw socket 用户缓冲区可能保留部分校验和；不能因标准 TCP 栈接受了报文，就断言原字节一定能通过完整软件验算。未做实际内核/回环发包验收，不扩称所有回包或所有内核均如此。

成熟参考：[Nmap `validatepkt/validateTCPhdr`][nmapvalidate] 校验长度、头部和选项，没有把 TCP checksum 软件验算作为入包必要条件；`get_ping_pcap_result` 再关联目标/端口/序号。未找到它专为 raw socket offload 设置例外的证据，其接收本就走 pcap。故现方案“出包 checksum 正确，入包地址/端口/flags/序号/边界严格关联”没有被这些源码否定；不需要据此引入全局 pcap，也不能宣称已获得入包完整性验证。

## 4. 回包规则与成熟参考的分界

[RFC9293 §3.5.2、§3.10.7.1][rfc]：无负载 SYN 的 seq=S，正常 SYN+ACK 或关闭端口 RST+ACK 的 ack 应为 S+1（模2³²）；ACK 探针的 ack=A，关闭/监听状态产生的 RST 取 seq=A，不能要求回包必须带 ACK，也不能拿探针 seq 去匹配它。SYN/FIN 消耗序号。内核自动 RST 是另一条方向，不能当远端证据。

[Nmap `sendIPScanProbe/seq32_encode/tcp_probe_match/get_ping_pcap_result`][nmap] 将轮次编码进 SYN.seq 或 ACK.ack，并核对目标、端口、探针类型；SYN+ACK 不能匹配 ACK 探针。其现实兼容分支会尝试 ack−1、ack、seq 三种解码，明确注释部分系统不守标准：**严格 RFC 匹配可能漏判，但不构成任意 RST 即存活的依据**。Nmap 接收经 `readip_pcap`，不能当纯 Go 无 pcap 实现照搬；本次只借鉴关联逻辑。

## 5. 依赖与许可：参考不等于建议引入

|参考基线|维护/Go/许可与本地依赖|
|---|---|
|arp `93566ba`（2026-05-28）|[go.mod](https://github.com/mdlayher/arp/blob/93566ba168e90a5c2c007a4128359cff4997d654/go.mod)：go1.23.0，MIT（部分 Go BSD 归属）；依赖 packet v1.1.2；可借鉴编码，不直接信任 Resolve|
|packet v1.1.2|[go.mod](https://github.com/mdlayher/packet/blob/v1.1.2/go.mod)：go1.20，MIT；socket v0.4.1+x/sys，Linux 原生 socket，无 pcap/额外驱动|
|packet `4b4d680` / v1.2.0|[CHANGELOG][packetchange] 明确 Go1.26+、仅维护最近两代 Go；不能在 Go1.24.6 上无脑选 latest|
|netlink `dcee557`（2026-08-31）|[go.mod](https://github.com/vishvananda/netlink/blob/dcee5577542ae957dfd1014a29b8ce338abccc46/go.mod)：go1.23，Apache-2.0；依赖 netns/x/sys，原生 syscall；有持续提交，但能力远超只读 RouteGet|
|Nmap `e135983`（2026-09-19）|C/C++、libpcap 路径；[NPSL0.95][nmaplicense]，不是 MIT/Apache，不应未经许可审查复制源码|

以上日期是核实快照最后提交，不代表维护承诺。GoMap 已有 x/net v0.50.0、x/sys v0.41.0；纯 Go 方式与 CGO_ENABLED=0 约束相容，但本次未交叉编译六目标，未证明依赖组合可直接发布。建议优先将以上作为实现/审查依据；是否引入 packet 或完整 netlink 由主审决定，本文不新增依赖、不改架构。

[arp]: https://github.com/mdlayher/arp/blob/93566ba168e90a5c2c007a4128359cff4997d654/client.go
[packet]: https://github.com/mdlayher/packet/blob/v1.1.2/packet_linux.go
[packetman]: https://man7.org/linux/man-pages/man7/packet.7.html
[arpman]: https://man7.org/linux/man-pages/man7/arp.7.html
[route]: https://github.com/vishvananda/netlink/blob/dcee5577542ae957dfd1014a29b8ce338abccc46/route_linux.go#L1641-L1792
[nl]: https://github.com/vishvananda/netlink/blob/dcee5577542ae957dfd1014a29b8ce338abccc46/nl/nl_linux.go#L568-L1000
[rtnlman]: https://man7.org/linux/man-pages/man7/rtnetlink.7.html
[godialip]: https://github.com/golang/go/blob/go1.24.6/src/net/iprawsock_posix.go
[godial]: https://github.com/golang/go/blob/go1.24.6/src/net/dial.go
[rawendpoint]: https://github.com/golang/net/blob/v0.50.0/ipv4/endpoint.go
[rawconn]: https://github.com/golang/net/blob/v0.50.0/ipv4/packet.go
[skbuff]: https://github.com/torvalds/linux/blob/v6.12/include/linux/skbuff.h
[loopback]: https://github.com/torvalds/linux/blob/v6.12/drivers/net/loopback.c
[tcpoutput]: https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_output.c
[datagram]: https://github.com/torvalds/linux/blob/v6.12/net/core/datagram.c
[nmapvalidate]: https://github.com/nmap/nmap/blob/e135983b218d866214ffdd82a0fbe0d32e378843/tcpip.cc#L1101-L1280
[sendmsg]: https://github.com/golang/net/blob/v0.50.0/internal/socket/rawconn_msg.go
[linuxraw]: https://github.com/torvalds/linux/blob/v6.12/net/ipv4/raw.c
[linuxdatagram]: https://github.com/torvalds/linux/blob/v6.12/net/ipv4/datagram.c
[bindport]: https://github.com/torvalds/linux/blob/v6.12/net/ipv4/inet_connection_sock.c
[linuxtcp]: https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_ipv4.c
[rawman]: https://man7.org/linux/man-pages/man7/raw.7.html
[rfc]: https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.2
[nmap]: https://github.com/nmap/nmap/blob/e135983b218d866214ffdd82a0fbe0d32e378843/scan_engine_raw.cc#L225-L390
[packetchange]: https://github.com/mdlayher/packet/blob/4b4d6808e0c89ab49f26a98192f65952cc7e8784/CHANGELOG.md
[nmaplicense]: https://github.com/nmap/nmap/blob/e135983b218d866214ffdd82a0fbe0d32e378843/LICENSE
