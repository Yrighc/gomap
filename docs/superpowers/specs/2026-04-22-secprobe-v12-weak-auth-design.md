# GoMap secprobe v1.2 弱认证能力升级设计

日期：2026-04-22

## 1. 背景

GoMap 当前已经完成 `secprobe v1.0` 的第一阶段落地：

- `pkg/assetprobe` 继续负责资产发现
- `pkg/secprobe` 负责协议账号口令探测
- 提供 `gomap weak`
- 提供 `gomap port -weak`
- 当前支持协议：`ssh`、`ftp`、`mysql`、`postgresql`、`redis`、`telnet`

当前 `v1.0` 的能力本质上仍然是“账号口令尝试”，而不是更完整的“弱认证能力”：

- 还没有 `redis` / `mongodb` 未授权访问
- 还没有统一表达 `credential` 与 `unauthorized` 的结果模型
- 还没有探测命中后的可选详情补采

与此同时，`/Users/yrighc/work/hzyz/project/Chujiu_reload` 中已经存在两条值得借鉴的能力线：

- `plugin/servicebrute`
  - 负责账号口令爆破
  - 覆盖协议面更大
  - 支持成功后详情补采
- `plugin/hostdetection`
  - 负责未授权访问检测
  - 已有 `redis` / `mongodb` 未授权检测实现

但 `Chujiu_reload` 同时包含 Temporal、Redis 缓冲、统一任务编排等平台化能力，这些不适合直接迁入 GoMap。

本设计的目标不是复制 `Chujiu_reload`，而是只吸收它在“弱认证能力拆分”和“命中后补采”上的优点，把 GoMap 的 `secprobe` 从“口令探测层”升级成“统一弱认证探测层”。

## 2. 目标与非目标

### 2.1 目标

- 以 `pkg/secprobe` 为中心，规划 `v1.2` 的弱认证能力升级
- 同时支持两类能力：
  - 账号口令探测
  - 未授权访问检测
- 首批接入协议：
  - `redis` 未授权访问
  - `mongodb` 未授权访问
- 为成功 finding 增加可选详情补采能力
- 保持 `gomap weak` 与 `gomap port -weak` 作为统一 CLI 入口
- 保持 `pkg/assetprobe` 与 `pkg/secprobe` 的边界不回退

### 2.2 非目标

- 本次不把 GoMap 拆成 `servicebrute` / `hostdetection` 两个平行子系统
- 本次不接入 `x-crack` 这类外部大爆破引擎
- 本次不一次性扩展大量新协议
- 本次不引入 Temporal、Redis 缓冲、任务编排、平台 UI 适配
- 本次不恢复把安全结果写回 `assetprobe.PortResult`
- 本次不让详情补采成为主探测流程的强依赖

## 3. 方案对比

### 方案 A：继续沿用纯 `credential` 主线，未授权与补采塞进现有执行链

做法：

- 保持当前 `CredentialProbeOptions` / `Prober` 结构不变
- `redis` / `mongodb` 未授权访问作为“特殊 credential probe”接入
- 补采逻辑直接放进协议探测器

优点：

- 改动路径最短
- 短期实现速度最快

缺点：

- `credential` 与 `unauthorized` 语义会混在一起
- 未授权会被错误地表达成“空账号密码成功”
- probe 内部会越来越重，后续继续扩协议时容易失控

### 方案 B：保留统一 `secprobe` 入口，但在内部做能力分型

做法：

- 对外继续只有一个 `pkg/secprobe`
- 内部分成三层：
  - 候选生成与服务归一化
  - 探测执行层：`credential` / `unauthorized`
  - 成功后详情补采层：`enrichment`

优点：

- 可以吸收 `Chujiu_reload` 中 `servicebrute + hostdetection` 的能力分型思路
- 对外接口仍然保持 GoMap 当前的简洁结构
- 后续增加更多未授权协议或补采能力时更顺滑

缺点：

- 这次需要先把 `secprobe` 内部模型抽清楚
- 设计工作量比“直接加两个插件”更大

### 方案 C：显式拆出 GoMap 版 `servicebrute` / `hostdetection`

做法：

- 在 GoMap 中也拆成两个独立包
- CLI 负责统一编排

优点：

- 概念最直观
- 和 `Chujiu_reload` 的结构映射最像

缺点：

- 会让 GoMap 的模块边界变重
- CLI 与库层会出现两套平行入口
- 不符合 GoMap 目前已经收敛出的 `secprobe` 统一入口方向

### 结论

选择方案 B。

即：

- 借鉴 `Chujiu_reload` 的能力分型
- 不照搬它的平台层与模块拆法
- 保留 GoMap 当前 `secprobe` 作为统一入口

## 4. 总体设计

### 4.1 模块边界

模块职责继续保持：

- `pkg/assetprobe`
  - 开放端口发现
  - 服务识别
  - 生成资产结果
- `pkg/secprobe`
  - 统一弱认证探测入口
  - 消费候选资产
  - 执行 `credential` / `unauthorized` 探测
  - 可选执行命中后补采

边界原则：

- `assetprobe` 不承担安全验证
- `secprobe` 不承担全量端口发现
- `port -weak` 继续是显式串联，而不是职责回归

### 4.2 内部分层

`secprobe v1.2` 内部分为三层：

#### 第一层：候选层

负责：

- 从 `assetprobe.ScanResult` 构造标准候选
- 做服务归一化
- 做轻量服务别名映射

需要借鉴 `Chujiu_reload` 的地方：

- 它在服务爆破 activity 里维护了更完整的 service alias 映射

但 GoMap 只吸收“归一化思路”，不吸收其大而全的映射表风格。

首批建议兼容：

- `postgres`
- `pgsql`
- `mongo`
- `redis/tls`
- `redis/ssl`
- `mysql?`
- `ssh?`

#### 第二层：探测层

负责：

- 按探测类型选择对应探测器
- 统一生成 finding

内部引入 `ProbeKind`：

- `credential`
- `unauthorized`

这样 `redis` / `mongodb` 可同时拥有：

- 凭证探测器
- 未授权探测器

但对外仍统一由 `secprobe.Run(...)` 驱动。

#### 第三层：补采层

负责：

- 仅在 finding 命中后执行附加补采
- 生成简化详情
- 补采失败不影响 finding 的主结果

这部分借鉴 `Chujiu_reload` 的“成功后详情补采”思路，但不把补采逻辑放进主探测器内部。

### 4.3 数据流

统一数据流如下：

1. `assetprobe` 产出开放端口与服务结果
2. `secprobe.BuildCandidates` 产出标准候选
3. `secprobe.Run` 根据配置决定启用的探测类型
4. 选择匹配的 `credential` / `unauthorized` 探测器执行
5. 生成基础 finding
6. 若启用 enrichment，则对成功 finding 做二次补采
7. 返回统一 `RunResult`

## 5. 数据模型设计

### 5.1 总体原则

不新开第二套结果模型，而是在现有 `SecurityResult` 上做最小升级。

目标：

- 统一表达 `credential` finding
- 统一表达 `unauthorized` finding
- 给后续 enrichment 留位置

### 5.2 建议新增字段

建议在 `SecurityResult` 上增加：

```go
type ProbeKind string

const (
    ProbeKindCredential   ProbeKind = "credential"
    ProbeKindUnauthorized ProbeKind = "unauthorized"
)

type SecurityResult struct {
    Target      string
    ResolvedIP  string
    Port        int
    Service     string
    ProbeKind   ProbeKind
    FindingType string
    Success     bool
    Username    string
    Password    string
    Evidence    string
    Enrichment  map[string]any
    Error       string
}
```

说明：

- 账号口令命中时：
  - `ProbeKind=credential`
  - `Username` / `Password` 有值
- 未授权命中时：
  - `ProbeKind=unauthorized`
  - `Username` / `Password` 为空

### 5.3 `FindingType` 扩展

`v1.2` 至少需要支持：

- `credential-valid`
- `unauthorized-access`

为后续保留：

- `credential-invalid`
- `credential-error`
- `protocol-matched-but-skipped`

### 5.4 `Enrichment` 表达

不照搬 `Chujiu_reload` 的 `InfoLeft / InfoRight` 双栏结构。

GoMap 保持轻量表达：

- `Evidence`
  - 简短摘要
- `Enrichment`
  - 可选详情对象

例如：

- Redis unauth
  - `Evidence = "INFO returned redis_version"`
  - `Enrichment = {"info_excerpt": "..."}`
- Mongo unauth
  - `Evidence = "listDatabases succeeded"`
  - `Enrichment = {"databases": ["admin", "config"]}`

## 6. 协议与探测类型设计

### 6.1 `credential` 探测

`v1.2` 继续沿用 `v1.0` 已有能力：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `telnet`

本次不以扩协议面为目标。

### 6.2 `unauthorized` 探测

`v1.2` 首批新增：

- `redis` 未授权访问
- `mongodb` 未授权访问

### 6.3 借鉴 `Chujiu_reload` 的点

#### Redis

参考 `plugin/hostdetection/redis.go` 的思路：

- 建立 TCP 连接
- 发送 `info`
- 根据响应是否包含 `redis_version` 判断是否存在未授权

GoMap 中保留这个思路，但实现要求更偏稳定与测试友好：

- 尽量通过更明确的 RESP/客户端方式表达
- 避免过度依赖脆弱字符串匹配

#### MongoDB

参考 `plugin/hostdetection/mongodb.go` 的思路：

- 尝试无需认证的数据库信息查询
- 通过结果确认未授权访问

GoMap 中不建议照搬原始字节包优先的写法作为最终形态，更建议：

- 首选官方/稳定驱动方式验证匿名访问
- 若存在兼容问题，再考虑保留更底层的 fallback

## 7. 详情补采设计

### 7.1 目标

把 `Chujiu_reload` 的“爆破成功后详情补采”吸收进 GoMap，但改造成一个可选、可失败、不拖主链路的后处理步骤。

### 7.2 原则

- 探测器只回答“是否命中”
- enrichment 只在成功 finding 后执行
- enrichment 失败不改变 finding 是否成功
- enrichment 必须显式开启

### 7.3 首批补采内容

`v1.2` 首批只建议做：

- Redis
  - `INFO`
- MongoDB
  - `ListDatabaseNames`

未来可扩展但本次不实现：

- SSH
  - `whoami`
- FTP
  - 当前目录 listing
- MySQL
  - `SHOW DATABASES`
- PostgreSQL
  - `SELECT datname FROM pg_database`

### 7.4 返回方式

补采结果统一进入 `Enrichment`，而不是新开独立结果表。

## 8. CLI 设计

### 8.1 统一入口保持不变

继续保留：

- `gomap weak`
- `gomap port -weak`

### 8.2 新增参数建议

建议新增：

- `-enable-unauth`
- `-enable-enrichment`

不建议 `v1.2` 直接引入更复杂的：

- `-modes credential,unauth`

原因：

- 当前 GoMap CLI 已经有一定参数量
- 显式开关更符合 `v1.0 -> v1.2` 的渐进扩展方式

### 8.3 默认行为

默认仍保持保守：

- 默认只做 `credential`
- 默认不做 `unauth`
- 默认不做 `enrichment`

即：

- `weak` 默认行为不变
- `port -weak` 默认行为不变

只有显式传参时才扩大能力面。

## 9. 实施拆分建议

为了降低风险，建议不要一次性完成全部 `v1.2`，而是拆成三个批次。

### 9.1 批次一：模型与执行框架

范围：

- 引入 `ProbeKind`
- 扩展 `FindingType`
- 让 `secprobe` 内部支持 `credential` / `unauthorized` 两类探测器
- 先不做 enrichment

目标：

- 先把骨架搭清楚
- 为后续 `redis` / `mongodb` unauth 铺路

### 9.2 批次二：协议落地

范围：

- 接入 `redis` 未授权访问
- 接入 `mongodb` 未授权访问
- 补服务别名归一化

目标：

- 先把 `v1.2` 最核心的新能力落地

### 9.3 批次三：详情补采

范围：

- 增加 `-enable-enrichment`
- 为成功 finding 做可选补采
- 首批只做 Redis / MongoDB

目标：

- 把 `Chujiu_reload` 中“成功后补采”的有价值部分轻量吸收进来

## 10. 测试要求

### 10.1 单元测试

必须覆盖：

- 新的结果模型字段
- `ProbeKind` 分流
- `FindingType` 扩展
- 服务归一化与别名映射

### 10.2 集成测试

必须覆盖：

- Redis unauth 成功
- Redis unauth 失败
- MongoDB unauth 成功
- MongoDB unauth 失败
- enrichment 成功
- enrichment 失败但主 finding 仍保留成功

### 10.3 CLI 测试

必须覆盖：

- `weak` 默认仍只做 `credential`
- `-enable-unauth` 后才出现 unauth finding
- `-enable-enrichment` 后才出现 enrichment 字段
- `port -weak` 的输出包裹结构继续保持兼容

## 11. 风险与约束

### 11.1 误报风险

未授权访问比认证成功更容易误报，因此：

- 判定逻辑必须保守
- 命中证据必须清晰
- 尽量避免只靠模糊字符串判断

### 11.2 性能风险

enrichment 一旦直接并入主探测流程，会明显放大总耗时，因此必须：

- 默认关闭
- 与主 finding 分离
- 允许失败

### 11.3 范围膨胀风险

参考 `Chujiu_reload` 时最容易犯的错误，是顺手把：

- 更大协议面
- 外部爆破引擎
- 平台存储与缓冲
- 工作流编排

也一起纳入。

本设计明确不这么做。

## 12. 结论

`GoMap secprobe v1.2` 最合理的方向不是复制 `Chujiu_reload`，而是：

- 只吸收它在“弱认证能力分型”上的优点
- 只吸收它在“命中后详情补采”上的优点
- 保持 GoMap 自己轻量、统一入口、边界清晰的设计

最终结果应当是：

- `secprobe` 仍然是一个统一入口
- 内部明确区分 `credential` 与 `unauthorized`
- `redis` / `mongodb` 未授权成为 `v1.2` 的核心新能力
- enrichment 成为可选后处理，而不是主链路负担
