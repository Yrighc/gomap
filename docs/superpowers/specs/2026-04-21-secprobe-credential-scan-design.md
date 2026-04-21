# GoMap 协议账号口令探测设计

日期：2026-04-21

## 1. 背景

当前仓库已经收敛为以 `pkg/assetprobe` 为核心的资产探测引擎，主链路聚焦于：

- TCP/UDP 端口扫描
- 服务识别
- 首页识别
- 目录爆破

历史版本曾在端口扫描流程中混入弱口令探测，但最近几次重构已经把首页识别、目录爆破等能力从 `PortResult` 中拆离。当前代码中仍残留弱口令相关钩子，例如 `DisableWeakPassword`、`UsePwd`、`ServiceBlasts`，但：

- `ServiceBlasts` 当前为空
- 默认参数会强制关闭弱口令逻辑
- 对外结果模型已不再暴露弱口令字段

这说明当前项目的真实工作模式已经是“资产发现”优先，而不是“大一统扫描器”。

本设计的目标是在不破坏现有 `assetprobe` 职责边界的前提下，重新引入协议账号口令探测能力，并为后续的未授权访问探测预留扩展位。

## 2. 目标与非目标

### 2.1 目标

- 新增独立的协议安全探测能力层
- `v1` 只支持基于账号口令的认证尝试
- 提供独立 CLI：`gomap weak`
- 允许 `gomap port` 在显式开启时串联安全探测
- `v1` 支持协议：`ssh`、`ftp`、`mysql`、`postgresql`、`redis`、`telnet`
- 为后续 `redis`/`mongodb` 未授权访问探测保留统一扩展模型

### 2.2 非目标

- `v1` 不恢复历史上的“端口扫描自动顺手爆破”模式
- `v1` 不把账号口令结果重新塞回 `assetprobe.PortResult`
- `v1` 不支持 `smb`、`rdp`、`oracle`、`mssql`
- `v1` 不实现复杂字典 DSL 或高级密码喷洒策略
- `v1` 不提供完整审计日志体系

## 3. 方案对比

### 方案 A：新增独立 `secprobe` 能力层并与 `port` 可选串联

做法：

- 新增 `pkg/secprobe`
- `assetprobe` 继续只负责开放端口和服务识别
- `secprobe` 只消费候选资产并执行协议认证尝试
- `cmd` 新增 `weak` 子命令
- `port` 子命令通过显式参数选择是否串联 `secprobe`

优点：

- 符合当前仓库已经形成的拆分方向
- 不污染 `assetprobe` 的结果模型
- 后续扩到未授权访问时可以自然演进为“协议安全探测”

缺点：

- 需要补一套新的请求、结果、调度和 CLI 映射

### 方案 B：把弱口令逻辑接回 `assetprobe` 主链路

做法：

- 复用残留的 `DisableWeakPassword`、`UsePwd`、`ServiceBlasts`
- 在 `scanTCPPort` 中重新接回账号口令尝试
- 在 `PortResult` 中恢复弱口令字段

优点：

- 改动路径短
- 能快速恢复历史体验

缺点：

- 与当前项目最近的职责拆分方向相冲突
- 会让 `assetprobe` 再次承担“发现资产 + 验证风险”双重职责
- 后续加入未授权访问后模型会进一步混乱

### 方案 C：直接引入 `dddd` 式 GoPoc 引擎

做法：

- 参考或复用 `dddd` 的协议扫描器、字典和调度体系
- GoMap 负责把端口识别结果喂给 GoPoc 层

优点：

- 协议覆盖面扩展较快
- 能较快对齐 `dddd` 的协议实现

缺点：

- 依赖与代码体积明显增大
- GoMap 当前定位是轻量资产探测库，不适合直接演化成通用 GoPoc 引擎
- 引入后长期维护成本偏高

### 结论

选择方案 A。

## 4. 总体设计

### 4.1 模块边界

新增 `pkg/secprobe`，代表“协议安全探测”能力层，而不是仅限定为“弱口令”。

职责划分：

- `pkg/assetprobe`：发现开放端口与服务
- `pkg/secprobe`：对候选服务执行协议安全探测
- `internal/secprobe/<protocol>`：各协议的具体实现
- `app/secprobe/*.txt`：内置协议字典

边界原则：

- `assetprobe` 不回写账号口令结果
- `secprobe` 不承担全量端口发现
- `port --weak` 是串联调用，不是职责回归

### 4.2 调用链

统一库层调用链：

1. `assetprobe.Scan` / `assetprobe.ScanTargets`
2. 从开放端口结果构造 `SecurityCandidate`
3. 归一化服务名
4. 交给 `secprobe.Run` / `secprobe.RunTargets`
5. 返回独立的 `SecurityResult`

CLI 调用链：

- `gomap weak`
  - 先调用 `assetprobe`
  - 再调用 `secprobe`
- `gomap port --weak`
  - 先输出资产结果
  - 再附加安全探测结果

## 5. 数据模型

建议新增以下核心模型：

```go
type SecurityCandidate struct {
    Target     string
    ResolvedIP string
    Port       int
    Service    string
    Version    string
    Banner     string
}

type Credential struct {
    Username string
    Password string
}

type CredentialProbeOptions struct {
    Protocols        []string
    Concurrency      int
    Timeout          time.Duration
    StopOnSuccess    bool
    DictDir          string
    Credentials      []Credential
}

type SecurityResult struct {
    Target      string
    ResolvedIP  string
    Port        int
    Service     string
    FindingType string
    Success     bool
    Username    string
    Password    string
    Evidence    string
    Error       string
}

type SecurityMeta struct {
    Candidates int
    Attempted  int
    Succeeded  int
    Failed     int
    Skipped    int
}
```

约束：

- `v1` 中 `FindingType` 固定为 `credential-valid`
- 后续新增未授权访问时，沿用同一结果模型，新增新的 `FindingType`
- `SecurityResult` 只保留必要证据，不保存全量尝试过程

## 6. 协议适配设计

`v1` 支持协议：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `telnet`

采用注册表式协议适配，而不是在主流程中硬编码 `switch`。

建议接口：

```go
type Prober interface {
    Name() string
    Match(candidate SecurityCandidate) bool
    Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}
```

注册表负责：

- 根据归一化后的服务名选择协议探测器
- 按需用默认端口做兜底匹配
- 在不支持的协议上直接跳过

服务匹配优先级：

1. 先看 `PortResult.Service`
2. 再根据默认端口兜底

例如：

- `mysql?` -> `mysql`
- `redis/ssl` -> `redis`
- `ssh?` -> `ssh`

## 7. 字典设计

建议新增内置字典目录：

```text
app/secprobe/ftp.txt
app/secprobe/mysql.txt
app/secprobe/postgresql.txt
app/secprobe/redis.txt
app/secprobe/ssh.txt
app/secprobe/telnet.txt
```

格式：

```text
admin : admin
root : 123456
redis : {{key}}
```

字典规则：

- 使用 `embed` 打包默认字典
- 支持 `-dict-dir` 整目录覆盖
- 支持 `-up` / `-upf` 提供临时凭证
- 加载后统一做去重、去空行和格式校验
- `v1` 只支持少量简单变量替换，不引入复杂 DSL

保守变量范围：

- `{{key}}`
- `{{username}}`
- 服务名兜底替换

## 8. 调度设计

调度分三层：

1. 资产发现
2. 候选构造
3. 协议认证尝试

并发粒度采用“候选目标级并发”：

- 每个 candidate 由一个 worker 顺序尝试字典
- 不对同一目标并行喷多组凭证

默认策略：

- `weak-concurrency` 默认 `10`
- 单次协议认证超时默认 `3~5s`
- 单 candidate 命中即停
- 网络错误可提前终止该 candidate
- 默认只打识别出的协议

为后续风控扩展预留字段：

- `MaxAttemptsPerTarget`
- `DelayBetweenAttempts`

`v1` 可以只保留内部结构，不必全部对外暴露。

## 9. CLI 设计

### 9.1 新增 `weak` 子命令

示例：

```bash
gomap weak -target 1.2.3.4 -ports 22,3306,6379
gomap weak -ips 1.1.1.1,2.2.2.2 -protocols ssh,mysql,redis
gomap weak -target demo.local -ports 1-10000 -weak-concurrency 10
```

建议参数：

- `-target`
- `-ips`
- `-ports`
- `-protocols`
- `-weak-concurrency`
- `-dict-dir`
- `-up`
- `-upf`
- `-stop-on-success`
- `-json`

### 9.2 扩展 `port` 子命令

新增参数：

- `-weak`
- `-weak-protocols`
- `-weak-concurrency`
- `-weak-stop-on-success`
- `-weak-dict-dir`

原则：

- 必须显式开启
- 串联结果单独输出，不污染原有资产结果模型

## 10. 输出设计

### 10.1 `gomap weak`

- 默认输出 `SecurityResult` 列表
- JSON 模式只输出安全探测结果与统计信息

### 10.2 `gomap port --weak`

建议输出组合结构：

```json
{
  "asset": {},
  "security": {
    "meta": {},
    "results": []
  }
}
```

收益：

- 兼容现有资产结果消费者
- 后续扩展未授权访问时无需重塑 `PortResult`

## 11. 错误处理与风控

错误分两类：

### 11.1 任务级错误

例如：

- 目标不可达
- 字典加载失败
- 协议探测器不存在

这类错误应进入任务级或结果级 `Error` 字段，表示该 candidate 未被正常执行。

### 11.2 尝试级失败

例如：

- 认证失败
- 超时
- 连接被拒绝
- 协议不兼容

这类失败不展开成全量明细，只收敛为最终状态。

风控边界：

- 只对已识别协议执行
- 默认低并发
- 默认顺序尝试
- 默认命中即停
- 不默认输出详细尝试日志
- `port --weak` 必须显式开启

## 12. 测试策略

### 12.1 单元测试

- 服务名归一化
- 字典解析与去重
- 变量替换
- registry 分发
- `StopOnSuccess`
- 错误收敛

### 12.2 协议级集成测试

优先覆盖：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`

`telnet` 可根据测试环境决定先做 mock 还是轻量服务集成。

### 12.3 CLI 测试

- `gomap weak`
- `gomap port --weak`
- JSON 输出结构
- 无命中场景
- 目标不可达场景
- 协议不支持场景

## 13. 里程碑

### 里程碑一：`v1`

- 新增 `pkg/secprobe`
- 新增 `gomap weak`
- 新增 `port --weak`
- 支持 `ssh`、`ftp`、`mysql`、`postgresql`、`redis`、`telnet`
- 仅支持账号口令探测

### 里程碑二：后续扩展

- 增加 `redis` 未授权访问
- 增加 `mongodb` 未授权访问
- 扩展 `FindingType`

## 14. 成功标准

实现完成后，以下条件应可验证：

1. 对现有 `assetprobe` 公共结果模型无破坏性变更
2. `gomap weak` 可对 `ssh/ftp/mysql/postgresql/redis/telnet` 执行账号口令探测
3. `gomap port --weak` 在显式开启时可返回资产结果与安全结果
4. 无命中时输出为空结果而不是失败
5. 单 candidate 命中后不再继续尝试后续凭证
6. 后续加入未授权访问时无需重塑主结果模型

## 15. Karpathy Guidelines 复审

按 `karpathy-guidelines` 复审本设计，结论如下：

### 15.1 Think Before Coding

- 假设已显式列出：`v1` 只做账号口令探测，未授权访问延后
- 多种实现路径已对比，未直接静默选择
- 当前最大不确定性不是架构，而是各协议的真实测试环境准备成本；该风险已留到实现计划与测试阶段处理

### 15.2 Simplicity First

- 选择了独立 `secprobe`，但没有一步到位做全协议 GoPoc 引擎
- 没有为 `v1` 引入复杂字典 DSL、复杂审计系统或高级喷洒策略
- 预留了未授权访问的扩展位，但没有在 `v1` 先实现

### 15.3 Surgical Changes

- 方案只新增独立能力层和 CLI 扩展
- 不要求重构现有 `assetprobe` 主链路
- 不恢复旧版 `PortResult` 的弱口令字段，避免大范围回滚既有设计

### 15.4 Goal-Driven Execution

后续实现应按以下目标推进：

1. 新增 `pkg/secprobe` 基础模型与 registry
   - 验证：单元测试通过
2. 接入 `gomap weak`
   - 验证：CLI 对样例目标可输出结构化结果
3. 接入 `gomap port --weak`
   - 验证：组合输出结构正确，现有 `port` 行为不受影响
4. 实现 6 个协议探测器
   - 验证：协议级集成测试通过

复审结论：

- 设计整体合理
- 当前不存在明显的过度抽象
- 实现阶段应继续约束范围，避免把 `secprobe` 过早演化成通用漏洞引擎
