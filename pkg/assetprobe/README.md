# assetprobe

`assetprobe` 是 GoMap 导出的资产探测库，可被其他 Go 项目直接 `go get` 后 `import` 调用。

## 能力范围

- TCP/UDP 端口扫描
- TCP 服务识别与连接探测
- 首页识别（标题、状态码、hash、favicon hash）
- 可选目录爆破（简单/一般/复杂字典）

## 快速使用

```go
import "gomap/pkg/assetprobe"

scanner, err := assetprobe.NewScanner(assetprobe.Options{
    Concurrency:    300,
    Timeout:        2 * time.Second,
    DetectHomepage: true,
})
if err != nil {
    panic(err)
}

res, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
    Target:   "example.com",
    PortSpec: "80,443,1-1024",
    Protocol: assetprobe.ProtocolTCP,
    DirBrute: &assetprobe.DirBruteOptions{
        Enable:   true,
        Level:    assetprobe.DirBruteSimple,
        MaxPaths: 200,
    },
})
if err != nil {
    panic(err)
}
```

示例代码见：`examples/library/main.go`
