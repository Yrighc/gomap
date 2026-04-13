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
})
if err != nil {
    panic(err)
}

// 多目标端口扫描
batch, err := scanner.ScanTargets(context.Background(), []string{
    "192.168.1.10",
    "192.168.1.11",
    "example.com",
}, assetprobe.ScanCommonOptions{
    PortSpec:        "80,443,1-1024",
    Protocol:        assetprobe.ProtocolTCP,
    PortConcurrency: 300, // 多目标时表示全局总并发
})
if err != nil {
    panic(err)
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
