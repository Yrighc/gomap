# assetprobe

`assetprobe` 是 GoMap 导出的资产探测库，可被其他 Go 项目直接 `go get` 后 `import` 调用。

## 能力范围

- TCP/UDP 端口扫描
- TCP 服务识别与连接探测
- 首页识别（标题、状态码、hash、favicon hash）
- 可选目录爆破（简单/一般/复杂字典）

## 快速使用

```go
import "github.com/yrighc/gomap/pkg/assetprobe"

scanner, err := assetprobe.NewScanner(assetprobe.Options{
    PortConcurrency: 300,
    PortRateLimit:   3000,
    Timeout:         2 * time.Second,
})
if err != nil {
    panic(err)
}

// 端口扫描
res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
    Target:          "example.com",
    PortSpec:        "80,443,1-1024",
    Protocol:        assetprobe.ProtocolTCP,
    PortConcurrency: 100,
    PortRateLimit:   1000,
    // Empty Modes selects target-aware automatic discovery. Set an explicit
    // ordered Modes slice only when overriding that policy.
    HostDiscovery: assetprobe.HostDiscoveryOptions{
        Timeout: 1 * time.Second,
        Retries: 1,
        Ports:   []int{80, 443, 22, 445, 3389, 8080, 3306, 6379},
    },
})
if err != nil {
    panic(err)
}

// 多目标端口扫描
batch, err := scanner.ScanTargets(context.Background(), []string{
    "192.168.1.10",
    "192.168.1.0/30",
    "example.com",
}, assetprobe.ScanCommonOptions{
    PortSpec:        "80,443,1-1024",
    Protocol:        assetprobe.ProtocolTCP,
    PortConcurrency: 300, // 多目标时表示全局总并发
    HostDiscovery: assetprobe.HostDiscoveryOptions{
        Timeout: 1 * time.Second,
        Retries: 1,
        Ports:   []int{80, 443, 22, 445, 3389, 8080, 3306, 6379},
    },
})
if err != nil {
    panic(err)
}

// ScanTargets 支持在批量目标里混合传入 IP、域名和 CIDR，
// CIDR 会在入口处展开为具体 IP 后再继续后续扫描流程。

// 独立 Host Discovery：只接受 IP/CIDR，不触发端口扫描、服务识别或页面获取。
// 零值 Scanner 同样可用；Disabled 不会跳过显式的 DiscoverHosts 调用。
// 空 Modes 使用自动策略：Linux 直连以太网 IPv4 为 ARP-only；Linux 远端 IPv4
// 使用 ICMP + SYN，SYN 不可用时降级 Connect；Linux IPv6 和 macOS 使用 ICMP + Connect，
// Windows 使用 Connect。若需旧策略，显式传入
// Modes: []assetprobe.HostDiscoveryMode{assetprobe.HostDiscoveryICMPEcho, assetprobe.HostDiscoveryTCPConnect}；
// nil 覆盖继承 Scanner 配置，非 nil 空切片明确选择自动策略。
// 原生模式不调用 ping/nping/arping，权限不足会在同轮降级或返回目标级能力错误。
// 已通过受控测试、授权 Debian/PVE 网络验收与跨平台编译；其他平台限制见验收矩阵。
var discoveryScanner assetprobe.Scanner
discovery, err := discoveryScanner.DiscoverHosts(context.Background(), []string{
    "192.168.1.10",
    "192.168.1.0/30",
}, assetprobe.DiscoverHostsOptions{
    Concurrency: 32, // <= 0 默认 32
    // MaxTargets <= 0 默认 65,536；超限在探测前报错且不截断。
    HostDiscovery: assetprobe.HostDiscoveryOptions{
        Ports: []int{80, 443, 22, 445, 3389, 8080, 3306, 6379},
    },
})
if err != nil && !errors.Is(err, context.Canceled) {
    panic(err)
}
// 展开完成前取消时 discovery 为 nil；探测阶段取消时保留完整结果列表和部分结果。
if discovery != nil {
    for _, item := range discovery.Results {
        // Matched=false 且 Error="" 代表未确认，不代表目标离线。
        fmt.Println(item.Target, item.ResolvedIP, item.Matched, item.Method, item.Error)
    }
}

// 首页识别
web, err := scanner.DetectHomepageWithOptions(context.Background(), "https://example.com", assetprobe.HomepageOptions{
    IncludeHeaders: true,
    MaxBodyBytes:   4096,
})
if err != nil {
    panic(err)
}

// 目录爆破
dirs, err := scanner.ScanDirectories(context.Background(), "https://example.com", assetprobe.DirBruteOptions{
    Enable:   true,
    Level:    assetprobe.DirBruteSimple,
    MaxPaths: 200,
})
if err != nil {
    panic(err)
}

_, _, _, _ = res, batch, web, dirs
```

示例代码见：`examples/library/main.go`

## 首页探测超时与错误

`DetectHomepage` / `DetectHomepageWithOptions` 保留底层错误链，可用 `errors.Is` / `errors.As` 识别 `context.Canceled`、`context.DeadlineExceeded`、`*net.DNSError`、`*net.OpError`、`*url.Error` 等；正文读取失败保留 `Op: "read"` 和原始读取错误。具体客户文案由调用方统一映射，不应直接展示错误字符串（可能包含请求 URL）。旧的无详细原因结果仍可能返回 `homepage not reachable`，调用方需提供未知原因兜底。

首页默认使用 **10 秒整体时限**，覆盖 DNS、TCP、TLS、重定向、正文、兼容重试及 favicon。只需通过传入 context 的 deadline 覆盖整体时限（可短于或长于 10 秒）；未设置 deadline 时自动使用默认值。请求使用同一 context，中途取消会中断实际网络请求，不再分别写死连接 3 秒、单次请求 5 秒或正文 4 秒。

favicon 作为附属信息仍最多使用 3 秒，且不能超过整体剩余时间；独立获取失败保留主页面，但调用方整体 deadline 到期或取消仍按调用失败处理。`Options.Timeout` 继续用于基础网络/端口探测，不控制首页；不增加各阶段超时配置，不改变兼容重试条件或空正文判定。
