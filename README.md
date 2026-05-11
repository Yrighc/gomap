# GoMap（精简版资产探测）

[![CI](https://github.com/Yrighc/gomap/actions/workflows/ci.yml/badge.svg)](https://github.com/Yrighc/gomap/actions/workflows/ci.yml)
[![CD Release](https://github.com/Yrighc/gomap/actions/workflows/release.yml/badge.svg)](https://github.com/Yrighc/gomap/actions/workflows/release.yml)

GoMap 是一个基于 Go 实现的资产探测工具库与 CLI。

当前仓库已聚焦在资产探测主链路，保留以下能力：
- TCP/UDP 端口扫描
- 服务识别（基于 nmap probes 规则增强）
- 首页识别（标题、状态码、响应特征、favicon hash）
- 可选目录爆破（简单/一般/复杂字典）
- 可选协议账号口令探测（`weak` / `port -weak`）

## 1. 项目定位

适用于以下目标：
- 作为独立扫描 CLI 直接执行
- 作为其他 Go 项目的依赖库，按方法调用
- 作为资产采集阶段的探测引擎，输出结构化结果供后续系统处理

## 2. 目录结构

```text
.
├── app/
│   ├── assetprobe/
│   │   ├── probes/
│   │   │   └── gomap-service-probes  # 服务识别探针规则
│   │   ├── services/
│   │   │   └── gomap-services        # 端口服务映射
│   │   └── dicts/
│   │       ├── simple.txt            # 目录爆破字典（simple）
│   │       ├── normal.txt            # 目录爆破字典（normal）
│   │       └── diff.txt              # 目录爆破字典（diff）
│   └── secprobe/
│       └── dicts/
│           └── *.txt                 # 内置协议口令字典
├── cmd/
│   └── main.go                   # 主 CLI（port/web/dir/weak 子命令）
├── pkg/assetprobe/
│   ├── types.go                  # 对外类型定义
│   ├── scanner.go                # 主流程与核心算法
│   └── json.go                   # JSON 序列化辅助
├── pkg/secprobe/
│   ├── types.go                  # 协议安全探测对外类型
│   ├── run.go                    # 协议账号口令探测执行入口
│   ├── candidates.go             # 资产结果转安全探测候选
│   ├── default_registry.go       # 内置协议 prober 注册入口
│   ├── protocol_catalog.go       # 协议元数据目录
│   └── enrichment_router.go      # 命中后补采路由入口
├── internal/
│   ├── tcpservices/              # TCP 服务识别
│   ├── updservices/              # UDP 服务识别
│   ├── crawlweb/                 # 首页识别
│   ├── connect/                  # 协议连接与匹配辅助
│   ├── secprobe/                 # secprobe 协议实现（按协议分目录）
│   ├── separate/                 # 其他协议特定探测
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

- 结合 `app/assetprobe/probes/gomap-service-probes` 规则进行协议探测与匹配
- 结合 `app/assetprobe/services/gomap-services` 做端口服务兜底映射
- 支持常见 TLS/明文服务识别

### 3.3 首页识别与目录爆破

- 首页识别仅在 HTTP 类服务/端口触发
- 目录爆破默认关闭，开启后使用字典并发请求路径
- 目录爆破结果通过独立结果模型返回，不再挂载到端口扫描结果中

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
         | app/assetprobe/probes/   |
         |   gomap-service-probes   |
         | app/assetprobe/services/ |
         |   gomap-services         |
         | app/assetprobe/dicts/*.txt |
         | app/secprobe/dicts/passwords/global.txt |
         +---------------------------+
```

## 5. CLI 使用

### 5.1 端口扫描（port）

```bash
go run ./cmd \
  port \
  -target example.com \
  -ports 80,443,1-1024 \
  -proto tcp \
  -c 200 \
  -rate 3000 \
  -timeout 2 \
  -max-fp 50
```

### 5.2 首页识别（web）

```bash
go run ./cmd web -url https://example.com -include-headers -max-body 4096
```

如果你要验证 `RedirectChain`，可以先启动本地测试服务：

```bash
go run ./examples/redirect_server
```

再执行：

```bash
go run ./cmd web -url http://127.0.0.1:18080 -include-headers
```

预期返回结果中的 `Response.Header.RedirectChain` 会包含：

```json
[
  "http://127.0.0.1:18080/login",
  "http://127.0.0.1:18080/home"
]
```

### 5.3 目录爆破（dir）

```bash
go run ./cmd \
  dir \
  -url https://example.com \
  -dict=simple \
  -dict-max=500 \
  -dict-concurrency=50
```

### 5.4 协议账号口令探测（weak）

```bash
gomap weak -target example.com -ports 21,22,3306,5432,6379
```

启用未授权探测与补采示例：

```bash
gomap weak -target example.com -ports 6379,27017,11211,2181 -enable-unauth -enable-enrichment
```

常用参数：
- `-target` / `-ips`: 单目标或多目标输入
- `-ports`: 探测端口范围，默认 `21,22,23,3306,5432,6379`
- `-protocols`: 限定 secprobe 协议，逗号分隔，例如 `ssh,redis,mssql,rdp,vnc,smb,smtp,amqp,oracle,snmp`
- `-timeout`: 资产发现与 secprobe 共用超时秒数
- `-weak-concurrency`: secprobe 并发数
- `-up`: 内联凭证，格式 `admin : admin,root : root`
- `-upf`: 凭证文件，一行一个 `username : password`
- `-stop-on-success`: 单目标命中后停止继续尝试
- `-enable-unauth`: 启用 `redis` / `mongodb` / `memcached` / `zookeeper` 未授权访问探测
- `-enable-enrichment`: 对成功 finding 追加详情补采
- `-v`: 同时输出控制台日志

说明：
- 默认仍只执行 credential 探测
- 当前内置 `credential` 协议列表：`ftp, ssh, telnet, smtp, mysql, postgresql, redis, mssql, oracle, amqp, snmp, rdp, vnc, smb, imap, pop3, ldap, kafka`
- `snmp` 第一版按 `v2c community` 接入，内置字典使用兼容现有解析器的 `: community` 行格式
- `weak` 子命令当前发现阶段固定使用 `TCP`，上述 `snmp` 能力不等价于已覆盖常规 `UDP/161` SNMP 发现
- `-enable-enrichment` 仅对成功 finding 生效，补采失败不会改变主 finding 成败
- `v1.3` 已增强内部执行状态与失败分类，但 CLI / JSON 仍保持兼容，不额外暴露 `Stage`、`FailureReason`、`Capabilities` 等内部字段
- `v1.3` 继续保持默认保守策略，不新增额外显示控制参数

### 5.4.1 secprobe v1.4 扩展模式说明

- `secprobe` 当前采用“代码驱动协议执行 + metadata 驱动静态声明”的扩展模式，主链路为 `metadata -> planner -> engine -> provider`。
- 弱口令候选生成已进一步收口为 `metadata.dictionary -> credential profile -> generator -> engine`，默认不再把“前 N 条口令”当成隐藏扫描档位。
- 协议握手、认证、未授权确认、补采等交互逻辑继续落在协议实现代码中；协议名、别名、默认端口、能力、默认用户、共享密码源与模板引用等静态信息集中收敛在 `app/secprobe/protocols/*.yaml`。
- 内置弱口令默认只维护一份共享密码池 `app/secprobe/dicts/passwords/global.txt`；当前密码项参考 fscan `DefaultPasswords` 扩充，协议差异通过 `default_users`、`extra_passwords`、`default_pairs` 表达。
- 新增协议不建议只改配置文件；仅补 metadata / 字典 / 模板并不能让协议自动可用，新增协议至少需要补充 `internal/secprobe/<protocol>/` 下的 atomic provider，并完成默认 registry 注册。
- `memcached` 与 `zookeeper` 第一版按 `unauthorized` 协议接入，使用只读确认动作，不依赖凭证字典。
- `memcached` / `zookeeper` 默认端口不在 `weak` 的默认端口列表中，使用时需要显式通过 `-ports` 指定。
- 当前公开 `Run` / `RunWithRegistry` / `Scan` 主链路固定使用 `default` 档位；内部虽然已有 `fast/default/full` 抽象，但尚未作为 public 参数开放。
- 自定义默认字典目录入口已移除；三方调用方如需完全指定候选，请通过 `Credentials`、`-up` 或 `-upf` 显式传入。
- `activemq` 第一版按原子 `credential` 协议接入，使用 STOMP 单次认证模型。
- `zabbix`、`neo4j` 第一版按 HTTP/API 登录型 `credential` 接入，复用 `internal/secprobe/httpauth`。
- `httpauth` 是 provider 层 HTTP 传输复用助手，不是新的 capability，也不是 YAML DSL。
- `rsync` 本轮只完成边界评估，不并入当前实现批次。
- 协议扩展约束、接入步骤与结果语义请参考 [docs/secprobe-protocol-extension-guide.md](docs/secprobe-protocol-extension-guide.md)。
- 三方库调用与历史扩展升级方式请参考 [docs/secprobe-third-party-migration-guide.md](docs/secprobe-third-party-migration-guide.md)。

### 5.4.2 secprobe engine phase 1

- 协议元数据开始从硬编码 catalog 条目逐步收敛到 `app/secprobe/protocols/*.yaml`
- `Run` / `RunWithRegistry` 会先把协议元数据与运行时参数编译成 `Plan`，再交给统一 engine 执行
- 当前所有内置 `credential` 协议都已通过 atomic `AuthenticateOnce` 执行，默认 registry 不再直接依赖对应的 legacy credential core prober
- builtin `credential` 能力仅通过 `lookupAtomicCredential(...)` / capability 路径表达，不再经由默认 registry 的 `Lookup(..., ProbeKindCredential)` 暴露成 batch prober
- `credential` loop、`stop-on-success` 与 terminal-error 判定统一由 `pkg/secprobe/engine` 控制
- 新增的 `imap` / `pop3` / `ldap` / `kafka` 已按同一模型接入：metadata 声明协议事实，provider 只做单次认证，registry 负责默认装配
- `imap` / `pop3` / `ldap` 额外覆盖了显式 TLS 端口语义；`kafka` 第一版聚焦 `SASL/PLAIN` 用户名密码认证，支持 `9092` 明文与 `9093` TLS 常见部署
- public-prober compatibility 仍暂时保留给外部扩展注册，以及当前仍需 code-backed 的 `zookeeper unauthorized` 默认路径
- phase 2 已将历史内置协议目录迁移到 `app/secprobe/protocols/*.yaml`，保持既有 public API 与结果契约

### 5.4.3 secprobe engine phase 4

- `memcached` 的未授权确认已改为 declarative simple-template executor 执行
- 当前模板执行器严格收边为：一个 transport、一次请求、一次响应读取、基于 matcher 的确认
- `zookeeper` 仍保持 code-backed 路径，因为它依赖真实 session client，不属于简单 request/response 协议

### 5.4.4 secprobe engine phase 5

- 内置协议当前通过 metadata + provider registration 决定是否可执行，而不是依赖隐式 legacy core-prober 存在性
- public `Registry.Register(...)` 兼容能力仍然保留，但已经被显式收口到 public-prober adapter 路径
- builtin 默认热路径已经稳定为 `planner -> engine -> provider`，兼容逻辑不再混在默认执行主链路中

### 5.5 端口扫描后附加弱口令探测

```bash
gomap port -target example.com -ports 21,22,3306,5432,6379 -weak
```

启用未授权探测与补采示例：

```bash
gomap port -target example.com -ports 6379,27017,11211,2181 -weak -weak-enable-unauth -weak-enable-enrichment
```

说明：
- `port -weak` 仅支持 `tcp`，不支持 `udp`
- 输出保持最小包裹结构：`{"asset": ..., "security": ...}`

参数说明：
- `-proto`: `tcp` 或 `udp`
- `-ips`: 多目标，逗号分隔（与 `-target` 二选一）
- `-c`, `-concurrency`: 端口扫描并发数
- `-rate`, `-ratelimit`: 端口扫描全局速率限制（每秒）
- `-include-headers`: `web` 模式返回响应头
- `-max-body`: `web` 模式返回体最大字节数，`0` 表示完整 body
- `-max-fp`: 最多做服务识别的开放端口数（默认 `50`，也支持 `-max-fingerprint-ports`）
- `-honeypot-open-threshold`: 疑似蜜罐判定最小开放端口数（默认 `100`）
- `-honeypot-open-ratio`: 疑似蜜罐判定开放占比阈值（默认 `0.85`，范围 `0~1`）
- `-csv`: 是否写入 CSV 结果文件（默认关闭）
- `-csv-mode`: CSV 写入模式，`append|overwrite`（默认 `append`）
- `-weak`: `port` 模式下附加协议账号口令探测
- `-weak-protocols`: `port` 模式下仅探测指定协议，逗号分隔
- `-weak-concurrency`: `port` 模式下 secprobe 并发数
- `-weak-stop-on-success`: `port` 模式下单目标命中后停止继续尝试
- `-weak-enable-unauth`: `port -weak` 模式下启用未授权访问探测
- `-weak-enable-enrichment`: `port -weak` 模式下对成功 finding 追加详情补采
- `-dict`: `simple|normal|diff`
- `-dict-file`: 自定义字典文件路径
- `-dict-max`: 最大加载字典行数，`0` 表示不限制

兼容说明：
- 旧用法 `go run ./cmd -target ...` 仍可用（自动按 `port` 模式执行）
- 建议逐步迁移到子命令模式（`port/web/dir/weak`）

## 6. 依赖形式调用（推荐）

> 当前 `go.mod` 模块名为 `gomap`。如果你在私有仓库发布，请将模块名改为你的仓库地址（如 `github.com/your-org/gomap`），然后在业务项目 `go get` 使用。

### 6.1 端口扫描调用

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/yrighc/gomap/pkg/assetprobe"
)

func main() {
    scanner, err := assetprobe.NewScanner(assetprobe.Options{
        PortConcurrency: 300,
        PortRateLimit:   3000,
        Timeout:         2 * time.Second,
    })
    if err != nil {
        panic(err)
    }

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

    fmt.Println(res.Target, res.ResolvedIP, res.Meta.OpenPorts)
}
```

### 6.2 多目标端口扫描调用

```go
batch, err := scanner.ScanTargets(context.Background(), []string{
    "192.168.1.10",
    "192.168.1.11",
    "example.com",
}, assetprobe.ScanCommonOptions{
    PortSpec:        "80,443",
    Protocol:        assetprobe.ProtocolTCP,
    PortConcurrency: 300, // 多目标时表示全局总并发
})
if err != nil {
    panic(err)
}

for _, item := range batch.Results {
    if item.Error != "" {
        fmt.Println(item.Target, "scan failed:", item.Error)
        continue
    }
    fmt.Println(item.Result.Target, item.Result.Meta.OpenPorts)
}
```

### 6.3 首页识别调用

```go
page, err := scanner.DetectHomepageWithOptions(context.Background(), "https://example.com", assetprobe.HomepageOptions{
    IncludeHeaders: true,
    MaxBodyBytes:   4096,
})
if err != nil {
    panic(err)
}

fmt.Println(page.Title, page.Response.Header.StatusCode, page.Response.Header.Server, len(page.Response.Body))
```

### 6.4 目录爆破调用

```go
dirs, err := scanner.ScanDirectories(context.Background(), "https://example.com", assetprobe.DirBruteOptions{
    Enable:   true,
    Level:    assetprobe.DirBruteSimple,
    MaxPaths: 200,
})
if err != nil {
    panic(err)
}

fmt.Println(dirs.Target, dirs.Port, len(dirs.Paths))
```

### 6.5 协议账号口令探测调用

```go
scanResult, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
    Target:   "127.0.0.1",
    PortSpec: "21,22,3306,5432,6379",
    Protocol: assetprobe.ProtocolTCP,
})
if err != nil {
    panic(err)
}

security := secprobe.Run(
    context.Background(),
    secprobe.BuildCandidates(scanResult, secprobe.CredentialProbeOptions{}),
    secprobe.CredentialProbeOptions{},
)

// v1.3 新增的 Stage / FailureReason / Capabilities 仅用于内部执行与测试，
// 这里继续通过 ToJSON 输出兼容的公开结果结构。
out, _ := security.ToJSON(true)
fmt.Println(string(out))
```

### 6.6 依赖注入（DI）集成示例

适合在你的业务服务中抽象接口，便于测试替换：

```go
package probe

import (
    "context"
    "github.com/yrighc/gomap/pkg/assetprobe"
)

type PortScanner interface {
    Scan(ctx context.Context, req assetprobe.ScanRequest) (*assetprobe.ScanResult, error)
}

type Service struct {
    scanner PortScanner
}

func NewService(scanner PortScanner) *Service {
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

针对“全端口伪开放/蜜罐”类目标，扫描器默认策略：
- 当开放端口非常多时，仅对前 `50` 个开放端口做服务指纹识别，其余端口仍标记为 `open`
- 当满足 `开放端口数 >= 100` 且 `开放占比 >= 85%` 时，结果中会标记 `Meta.SuspectedHoneypot=true`
- `concurrency` 控制同时运行多少个端口探测任务
- `ratelimit` 控制整个进程内端口探测的起始速率上限

CSV 输出说明：
- `gomap port -csv` -> `logs/port.csv`
- `gomap web -csv` -> `logs/web.csv`
- `gomap dir -csv` -> `logs/dir.csv`

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
go run ./cmd port -target example.com -ports 80,443 -c 200 -rate 3000
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

CD 发布说明（`.github/workflows/release.yml`）：
- 触发条件：推送标签 `v*`（如 `v1.0.0`）
- 自动构建平台：
  - Linux: `amd64` / `386` / `arm64` / `armv7`
  - macOS: `amd64` / `arm64`
  - Windows: `amd64` / `386` / `arm64`
- 自动发布：将二进制与 `checksums.txt` 上传到 GitHub Release

## 11. 注意事项

- 仅在授权范围内进行探测
- 高并发与高探测速率会显著增加目标压力，建议控制 `c/rate/dict-concurrency`
- 字典文件属于可选资源，可按你的场景裁剪或替换
