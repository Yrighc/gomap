# 升级说明

本文档面向通过 `go get` 方式集成 `github.com/yrighc/gomap/pkg/assetprobe` 的调用方，说明当前版本相对 `v0.4.0` 的主要变更、影响范围和适配方式。

本次升级对应的关键提交：

- `a76e4d5` `fix(assetprobe): 内置探针与服务资源支持依赖模式运行`
- `83d73b3` `feat(scanner): 增强Kafka SSL端口识别与服务映射`
- `34d6d0a` `refactor(assetprobe): 统一多目标端口扫描任务池与调度模型`

## 1. 变更摘要

本次升级重点覆盖三类问题：

- 修复 `gomap` 作为依赖在容器/多阶段构建场景下运行失败的问题
- 增强 Kafka SSL 端口识别，修正 9093/9094 服务映射
- 重构多目标扫描调度模型，统一为“全局任务池 + 全局并发/速率限制”

如果你已经完成上一轮结果结构适配，这次需要重点关注：

- 依赖模式下资源加载行为
- `ScanTargets()` 的并发语义变化
- CLI `-ips` 的执行模型变化

## 2. 关键变更

### 2.1 依赖模式不再依赖模块源码目录中的 `app/*` 文件

旧版本在运行时会尝试从模块源码目录读取：

- `app/assetprobe/probes/gomap-service-probes`
- `app/assetprobe/services/gomap-services`
- `app/assetprobe/dicts/simple.txt`
- `app/assetprobe/dicts/normal.txt`
- `app/assetprobe/dicts/diff.txt`

这在以下场景会失败：

- 多阶段构建只拷贝业务二进制到运行镜像
- 运行容器内不存在 `go/pkg/mod/...` 模块源码缓存
- 业务进程不是在 `gomap` 源码目录下运行

典型报错：

```text
load probes failed: open /home/runner/go/pkg/mod/github.com/yrighc/gomap@.../app/assetprobe/probes/gomap-service-probes: no such file or directory
```

新版本行为：

- 优先使用调用方显式传入的 `ProbesFile` / `ServicesFile`
- 未传入时，自动回退到库内置的 embed 资源
- 目录爆破默认字典也会自动回退到内置资源

适配方式：

```go
scanner, err := assetprobe.NewScanner(assetprobe.Options{
    PortConcurrency: 200,
    Timeout:         2 * time.Second,
})
if err != nil {
    panic(err)
}
```

这意味着：

- 默认情况下不再需要额外挂载 `app/assetprobe/probes/gomap-service-probes`
- 默认情况下不再需要额外挂载 `app/assetprobe/services/gomap-services`
- 默认情况下不再需要额外挂载 `app/assetprobe/dicts/*.txt`

如果你确实有自定义探针/服务映射，仍然可以继续覆盖：

```go
scanner, err := assetprobe.NewScanner(assetprobe.Options{
    ProbesFile:   "/data/gomap-service-probes",
    ServicesFile: "/data/gomap-services",
})
```

### 2.2 Kafka SSL 端口识别增强

本次修复了 Kafka 相关的两个问题：

- `9093/tcp` 的服务映射从错误的 `copycat` 修正为 `kafka`
- `9093` 会被优先按 TLS 端口处理，识别链路更适合 Kafka over TLS 场景

影响：

- 旧版本中，`9093` 即使开放，也可能落成 `unknown` 或错误服务名
- 新版本中，Kafka SSL 端口更容易被识别为 `kafka/ssl` 或 `kafka/ssl?`

适配说明：

- 调用方无需修改代码
- 重新构建并升级依赖版本即可生效

### 2.3 多目标扫描改为统一任务池模型

旧版本 `ScanTargets()` 和 CLI `-ips` 的模型是：

- 以目标为单位并发调多个 `Scan()`
- 容易形成“目标并发 * 端口并发”的总压力放大

新版本统一为：

- 把所有 `(target, port)` 任务展开到同一个全局任务池
- `PortConcurrency` 表示全局总并发
- `PortRateLimit` 表示全局总速率限制
- 多目标任务默认会打乱执行顺序，以降低规则化访问特征
- 返回结果仍按输入顺序组织

影响：

- `ScanTargets()` 中 `PortConcurrency` 的语义发生变化
- CLI 的 `-ips` 现在也走同一套统一任务池模型

适配方式：

```go
batch, err := scanner.ScanTargets(context.Background(), []string{
    "192.168.1.10",
    "192.168.1.11",
    "example.com",
}, assetprobe.ScanCommonOptions{
    PortSpec:        "80,443,1-1024",
    Protocol:        assetprobe.ProtocolTCP,
    PortConcurrency: 300,  // 多目标模式下表示全局总并发
    PortRateLimit:   3000, // 多目标模式下表示全局总速率
})
if err != nil {
    panic(err)
}
```

### 2.4 `ScanCommonOptions.TargetConcurrency` 已移除

旧版本曾短暂暴露：

- `ScanCommonOptions.TargetConcurrency`
- CLI `-target-concurrency`

当前版本已移除。

原因：

- 两层并发模型不利于总压力评估
- 调用方很难准确判断总任务量
- 与统一任务池模型冲突

适配方式：

- 删除业务代码中的 `TargetConcurrency`
- 统一使用 `PortConcurrency` 控制多目标批量扫描总并发

## 3. CLI 变化

### 3.1 `port -ips` 调度模型变化

当前 CLI 行为：

- `-target` 和 `-ips` 会统一收集为目标列表
- 多目标下走 `ScanTargets()`
- 默认打乱任务执行顺序
- JSON 输出和 CSV 写入仍按输入目标顺序输出

### 3.2 已移除参数

以下参数不再提供：

- `-target-concurrency`

当前保留：

- `-c`, `-concurrency`：总并发
- `-rate`, `-ratelimit`：总速率限制

示例：

```bash
./gomap port -ips 1.1.1.1,8.8.8.8,example.com -ports 80,443 -c 300 -rate 3000
```

说明：

- 在多目标模式下，`-c` 表示所有目标共享的总并发
- 在单目标模式下，`-c` 仍表示单目标内部端口并发

## 4. 结果与接口兼容性

### 4.1 多目标结果结构不变

`BatchScanResult` / `TargetScanResult` 结构保持不变：

```go
type BatchScanResult struct {
    Results []TargetScanResult
}

type TargetScanResult struct {
    Target string
    Result *ScanResult
    Error  string
}
```

兼容性说明：

- 返回顺序仍按输入顺序组织
- 单目标失败仍通过 `Error` 表达
- 不按完成顺序返回

### 4.2 单目标 `Scan()` 语义不变

本次只重构多目标批量扫描路径。

`Scan(ctx, ScanRequest)` 仍然保持：

- `PortConcurrency` = 单目标端口扫描并发
- `PortRateLimit` = 单目标扫描总速率限制

## 5. 最小迁移清单

如果你已经使用 `v0.4.0`，建议按以下顺序适配：

1. 升级依赖版本并重新构建业务程序
2. 删除运行环境中对 `app/assetprobe/probes/gomap-service-probes`、`app/assetprobe/services/gomap-services`、`app/assetprobe/dicts/*.txt` 的强依赖
3. 如果业务里使用了 `ScanTargets()`，删除 `TargetConcurrency`
4. 将多目标并发控制统一收敛到 `PortConcurrency`
5. 如果 CLI 使用了 `-target-concurrency`，移除该参数

## 6. 建议

这次升级建议视为一次“运行时兼容性 + 批量扫描语义”双修复版本。

对调用方最重要的收益是：

- 依赖模式在容器和多阶段构建中更稳定
- 多目标扫描的总并发与总速率更容易控制
- Kafka SSL 端口识别更符合实际资产场景

如果你的业务依赖 `ScanTargets()` 做大规模资产探测，建议在升级后重新核对你们的并发配置，因为它现在代表的是“全局总并发”，不再是旧的两层并发模型。
