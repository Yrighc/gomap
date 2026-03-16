# GoMap（精简版资产探测）

[![CI](https://github.com/Yrighc/gomap/actions/workflows/ci.yml/badge.svg)](https://github.com/Yrighc/gomap/actions/workflows/ci.yml)
[![CD Release](https://github.com/Yrighc/gomap/actions/workflows/release.yml/badge.svg)](https://github.com/Yrighc/gomap/actions/workflows/release.yml)

GoMap 是一个基于 Go 实现的资产探测工具库与 CLI。

当前仓库已聚焦在资产探测主链路，保留以下能力：
- TCP/UDP 端口扫描
- 服务识别（基于 nmap probes 规则增强）
- 首页识别（标题、状态码、响应特征、favicon hash）
- 可选目录爆破（简单/一般/复杂字典）

## 1. 项目定位

适用于以下目标：
- 作为独立扫描 CLI 直接执行
- 作为其他 Go 项目的依赖库，按方法调用
- 作为资产采集阶段的探测引擎，输出结构化结果供后续系统处理

## 2. 目录结构

```text
.
├── app/
│   ├── gomap-service-probes      # 服务识别探针规则
│   ├── gomap-services            # 端口服务映射
│   ├── 简单.txt                   # 目录爆破字典（simple）
│   ├── 一般.txt                   # 目录爆破字典（normal）
│   └── 复杂.txt                   # 目录爆破字典（diff）
├── cmd/
│   ├── main.go                   # 主 CLI（支持多目标）
│   └── assetprobe/main.go        # 轻量 CLI（单目标）
├── pkg/assetprobe/
│   ├── types.go                  # 对外类型定义
│   ├── scanner.go                # 主流程与核心算法
│   └── json.go                   # JSON 序列化辅助
├── internal/
│   ├── tcpservices/              # TCP 服务识别
│   ├── updservices/              # UDP 服务识别
│   ├── crawlweb/                 # 首页识别
│   ├── connect/                  # 协议连接与匹配辅助
│   ├── separate/                 # 各协议特定探测
│   └── achieve/                  # 通用工具函数
└── examples/library/main.go      # 依赖调用示例
```

## 3. 核心功能逻辑

### 3.1 扫描主流程（`pkg/assetprobe.Scanner.Scan`）

1. 解析请求参数：目标、端口、协议、超时、并发、是否首页识别、目录爆破配置
2. 目标解析：域名 -> IP（优先 IPv4）
3. 端口归一化：支持 `80,443,1-1024` 形式，过滤非法值并去重
4. 并发扫描：基于 worker pool 对每个端口执行探测
5. TCP 分支：连接建立 -> 服务识别 -> （可选）首页识别 -> （可选）目录爆破
6. UDP 分支：UDP 探针发送与规则匹配识别
7. 汇总结果：按端口排序后返回结构化 `ScanResult`

### 3.2 服务识别策略

- 结合 `app/gomap-service-probes` 规则进行协议探测与匹配
- 结合 `app/gomap-services` 做端口服务兜底映射
- 支持常见 TLS/明文服务识别

### 3.3 首页识别与目录爆破

- 首页识别仅在 HTTP 类服务/端口触发
- 目录爆破默认关闭，开启后使用字典并发请求路径
- 爆破结果输出为 `Homepage.Paths[]`

## 4. 整体架构

```text
                  +-------------------+
                  |   调用方/业务系统   |
                  +---------+---------+
                            |
                            | 方法调用（Go import）
                            v
                  +-------------------+
                  | pkg/assetprobe    |
                  | Scanner / Types   |
                  +----+---------+----+
                       |         |
              TCP/UDP探测|         |首页识别/目录爆破
                       v         v
              +--------+--+   +--+-----------+
              | tcpservices |   |  crawlweb   |
              | updservices |   +-------------+
              +-----+-------+
                    |
                    v
         +---------------------------+
         | app/gomap-service-probes |
         | app/gomap-services       |
         | app/简单|一般|复杂.txt      |
         +---------------------------+
```

## 5. CLI 使用

### 5.1 主 CLI（多目标）

```bash
go run ./cmd \
  -target example.com \
  -ips 1.1.1.1,8.8.8.8 \
  -ports 80,443,1-1024 \
  -proto tcp \
  -rate 200 \
  -timeout 2 \
  -homepage=true
```

### 5.2 启用目录爆破

```bash
go run ./cmd \
  -target example.com \
  -ports 80,443 \
  -dirbrute=true \
  -dict=simple \
  -dict-max=500 \
  -dict-concurrency=50
```

参数说明：
- `-proto`: `tcp` 或 `udp`
- `-dict`: `simple|normal|diff`
- `-dict-file`: 自定义字典文件路径
- `-dict-max`: 最大加载字典行数，`0` 表示不限制

## 6. 依赖形式调用（推荐）

> 当前 `go.mod` 模块名为 `gomap`。如果你在私有仓库发布，请将模块名改为你的仓库地址（如 `github.com/your-org/gomap`），然后在业务项目 `go get` 使用。

### 6.1 基础调用

```go
package main

import (
    "context"
    "fmt"
    "time"

    "gomap/pkg/assetprobe"
)

func main() {
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
    })
    if err != nil {
        panic(err)
    }

    fmt.Println(res.Target, res.ResolvedIP, len(res.Ports))
}
```

### 6.2 依赖注入（DI）集成示例

适合在你的业务服务中抽象接口，便于测试替换：

```go
package probe

import (
    "context"
    "gomap/pkg/assetprobe"
)

type Scanner interface {
    Scan(ctx context.Context, req assetprobe.ScanRequest) (*assetprobe.ScanResult, error)
}

type Service struct {
    scanner Scanner
}

func NewService(scanner Scanner) *Service {
    return &Service{scanner: scanner}
}

func (s *Service) Run(ctx context.Context, target string) (*assetprobe.ScanResult, error) {
    return s.scanner.Scan(ctx, assetprobe.ScanRequest{
        Target:   target,
        PortSpec: "80,443",
        Protocol: assetprobe.ProtocolTCP,
    })
}
```

## 7. 返回结果与 JSON 建议

库调用时建议：
- 内部流程：优先使用结构体 `ScanResult`（类型安全、易扩展）
- 对外输出：在边界层转 JSON（HTTP/Kafka/落库）

已提供便捷方法：

```go
b, err := res.ToJSON(true) // pretty=true 输出格式化 JSON
```

## 8. 应用场景建议

- 场景 A：资产发现平台
  - 对网段/域名做周期探测，结果入库后做资产画像
- 场景 B：攻防演练前置探测
  - 快速识别暴露端口、协议与 Web 首页特征
- 场景 C：合规检查
  - 对重点 IP 列表做端口开放面基线核查
- 场景 D：研发环境自检
  - CI/CD 或发布后探测关键端口和页面可达性

## 9. 运行与开发

```bash
# 运行测试
go test ./...

# 运行示例
go run ./examples/library

# 主 CLI
go run ./cmd -target example.com -ports 80,443
```

## 10. 版本发布与 Changelog

- 提交规范：Conventional Commits（`feat/fix/docs/refactor/...`）
- 自动检查：
  - PR 标题语义检查：`.github/workflows/commitlint.yml`
  - 本地提交钩子：`husky + commitlint`
- 自动版本与变更日志：
  - `release-please` 工作流：`.github/workflows/release-please.yml`
  - 自动生成/更新 `CHANGELOG.md`
  - 自动创建 release PR 并管理版本 tag

本地启用提交钩子：

```bash
npm install
```

## 11. 注意事项

- 仅在授权范围内进行探测
- 高并发与大字典爆破会显著增加目标压力，建议控制 `rate/dict-concurrency`
- 字典文件属于可选资源，可按你的场景裁剪或替换
