# secprobe 协议扩展开发指南

本文用于约束 GoMap `secprobe` 在 `v1.4` 之后的协议接入方式，目标不是把协议扩展改造成纯配置驱动，而是把“哪些地方统一、哪些地方留给代码”说明清楚，降低后续新增协议时的改动面和语义漂移风险。

## 目标

- 让新协议接入路径固定，避免每次新增协议都回到 `run.go` 临时拼装。
- 让协议元数据集中收敛，避免别名、端口、字典名、能力声明散落在多个文件里。
- 让探测结果语义一致，避免不同协议各自定义“成功”“失败”“已确认”的含义。
- 保持 `pkg/secprobe` 继续作为统一入口，对外 API、CLI 入口和结果结构不因单个协议扩展而变形。

## 一个协议应该放在哪里

新增协议时，代码和元数据应分别落在下面几个位置：

### 1. 协议实现目录

每个协议使用单独目录：

`internal/secprobe/<protocol>/`

目录内按能力拆分文件，优先采用下面骨架：

- `prober.go`
  - 凭证探测实现，适用于 `credential` 能力
- `unauthorized_prober.go`
  - 推荐作为未授权探测实现文件名，适用于 `unauthorized` 能力
- `enrichment.go`
  - 命中后的补采逻辑，适用于 `enrichment` 能力
- `*_test.go`
  - 对应能力的单元测试或集成测试

约束：

- 一个协议一个目录，不要把多个协议混放在同一实现目录下。
- 不同能力分文件实现，不要把未授权确认和 enrichment 主逻辑硬塞进同一个探测流程里。
- 如果协议当前只支持一种能力，也仍然保持单目录收敛，便于后续增量扩展。

### 2. 默认装配层

如果协议要进入内置默认注册表，需要在：

`pkg/secprobe/default_registry.go`

中注册对应 prober。

原则：

- `credential` 和 `unauthorized` 分别注册各自 prober。
- 默认注册表只负责装配，不承载协议逻辑。
- 不要把协议实现重新塞回 `pkg/secprobe/run.go`。

### 3. 协议目录

协议元数据应统一登记在：

`pkg/secprobe/protocol_catalog.go`

这里负责声明：

- 标准协议名
- 协议别名
- 默认端口
- 字典名列表
- 支持的 `ProbeKind`
- 是否支持 enrichment

新增协议时，优先先补协议目录，再接入实现与注册表。

注意：

- `protocol_catalog` 负责收敛协议元数据和能力声明。
- catalog 中声明某个能力，不等于默认 registry 会自动注册对应 prober。
- `SupportsEnrichment` 也不等于 enrichment router 会自动接通对应协议。
- registry 和 router 仍需单独补齐显式接线。

### 4. 字典候选路径

如果协议支持凭证探测，字典候选路径由：

`pkg/secprobe/dictionaries.go`

基于协议目录里的 `DictNames` 统一生成。

约束：

- 优先复用 `DictNames`，不要在协议实现里手拼字典路径。
- 当前候选文件名规则仅为 `<name>.txt`。
- 默认内置字典加载仍通过 `pkg/secprobe/assets.go` 和 `app/secprobe/dicts/<protocol>.txt` 内嵌资源处理。
- 对 `Run()` / 默认 CLI 路径来说，仅补 `DictNames` 还不够；若协议支持内置 credential 字典，还需要同步补齐 `app/assets.go` 中的 embed 资源和 `SecprobeDict` 分支，否则默认内置字典不可用。

## 哪些内容允许配置化

当前适合收敛为协议元数据、允许配置化的内容包括：

- 协议标准名
- 协议别名
- 默认端口
- 字典名列表
- 是否支持 `credential`
- 是否支持 `unauthorized`
- 是否支持 `enrichment`

这些内容的特点是：

- 不涉及真实网络交互
- 不决定协议是否命中成功
- 适合被候选构建、协议归一化、字典查找、能力路由复用

推荐做法：

- 优先在 `pkg/secprobe/protocol_catalog.go` 中声明
- 让 `candidates.go`、`dictionaries.go`、默认能力判断尽量消费同一份目录
- 把“协议有哪些能力”当作元数据声明，而不是在多个调用点各写一份 `switch`
- 同时明确 registry 注册和 enrichment router 仍是独立接线点，不由 catalog 自动生成

## 哪些内容必须代码实现

下面这些内容必须留在协议代码中实现，不能下沉成纯配置：

- 协议握手
- 连接建立与超时控制
- 凭证认证流程
- 未授权访问确认动作
- enrichment 补采逻辑
- 成功确认条件
- 错误识别与失败分类
- 证据文本生成
- 命中后能力标记

原因：

- 这些内容依赖真实协议交互，存在时序、状态机、返回值判定和失败分型。
- 同样叫“未授权访问”，不同协议的确认动作完全不同，不能只靠端口或 banner 推断。
- enrichment 不是简单字段拼接，而是“命中后补采且不能改变核心确认语义”的代码逻辑。

反例：

- 不要试图用配置声明“看到某个字符串就算成功”来替代真实确认动作。
- 不要把 `FailureReason` 直接做成协议配置常量表然后生搬硬套。
- 不要把某协议的特殊补采流程塞进公共执行链路。

## 新协议接入 Checklist

新增一个协议时，至少按下面顺序检查：

1. 明确协议标准名，确认是否已有别名或端口复用关系。
2. 在 `pkg/secprobe/protocol_catalog.go` 增加协议目录项。
3. 决定协议支持哪些能力：`credential`、`unauthorized`、`enrichment`。
4. 如果支持凭证探测，确定 `DictNames`，并准备内置字典或外部字典约定。
5. 在 `internal/secprobe/<protocol>/` 新建协议目录。
6. 实现对应 prober：
   - `credential` 用 `prober.go`
   - `unauthorized` 优先采用 `unauthorized_prober.go`
7. 如果协议支持命中后补采，实现 `enrichment.go`。
8. 在 `pkg/secprobe/default_registry.go` 注册新 prober。
9. 如果协议支持 enrichment，把路由接入 `pkg/secprobe/enrichment_router.go`。
10. 为协议实现补测试，至少覆盖：
   - 命中成功
   - 认证失败或未授权失败
   - 超时或取消
   - 证据填写
   - 结果阶段与失败原因填写
11. 如果协议支持默认内置 credential 字典，复查 `DictNames` 之外的内置字典接线是否补齐：
   - `app/secprobe/dicts/` 内嵌资源已包含对应 `<protocol>.txt`
   - `app/assets.go` 的 `SecprobeDict` 已增加协议分支
   - 默认 `Run()` / CLI 路径可实际加载该协议内置字典
12. 复查字典加载链路是否走协议目录，而不是协议实现私有路径。
13. 复查新增协议不会修改 `pkg/secprobe` 对外 API、CLI 参数语义和结果导出结构。

## 结果语义要求

协议实现必须遵守统一结果语义。`SecurityResult` 对外导出字段较少，但内部语义必须完整、可推断、可测试。

### 1. Success 与确认语义

- `Success=true` 只用于“已经确认命中”的结果。
- `credential` 命中表示认证成功，`FindingType` 应为 `credential-valid`。
- `unauthorized` 命中表示未授权访问被真实确认，`FindingType` 应为 `unauthorized-access`。
- 不能把“端口开放”“握手成功”“看起来像该协议”直接记为命中。

### 2. Stage 语义

- `matched`
  - 已命中协议路由，但还没完成有效尝试
  - 典型场景：能力被禁用、缺少字典导致跳过
- `attempted`
  - 已实际发起一次探测，但未确认成功
- `confirmed`
  - 已通过真实协议交互确认命中
- `enriched`
  - 在 `confirmed` 基础上，enrichment 追加了新的补采数据

约束：

- 不支持协议时可直接跳过，不必强行写 `matched`。
- enrichment 没有产生新数据时，不应强行把阶段改成 `enriched`。

### 3. SkipReason 语义

跳过场景必须显式分类：

- `unsupported-protocol`
  - 当前候选没有匹配到任何可用 prober
- `probe-disabled`
  - 协议存在对应能力，但该能力未启用
- `no-credentials`
  - 凭证探测需要字典或凭证，但实际不可用

约束：

- `SkipReason` 只用于“没有进入有效探测”或“命中后因前置条件不足而跳过”的情况。
- 已经发起协议交互后失败，不要再写成 skip。

### 4. FailureReason 语义

实际探测失败时，尽量归入统一失败分类：

- `connection`
  - 连接建立失败、连接被拒绝、网络层中断
- `authentication`
  - 用户名密码错误、服务端明确要求认证、鉴权失败
- `timeout`
  - 超时、deadline exceeded、timed out
- `canceled`
  - 上下文取消、任务主动中止
- `insufficient-confirmation`
  - 已交互但证据不足，不能确认成功

约束：

- 优先根据真实错误分类。
- 无法精确识别时，宁可落到 `insufficient-confirmation`，也不要误报成功。
- 成功结果不应残留失败原因。

### 5. Capabilities 语义

`Capabilities` 只在确认命中后填写，用于描述命中后的实际能力边界。

当前已有能力值：

- `enumerable`
  - 可列举对象、库、键、数据库等
- `readable`
  - 可读取明确内容或元数据

约束：

- 只有真实确认后才能填写。
- 只能填写已经被当前确认动作证明的能力，不要做推断性扩张。
- 能列举不等于能读取；能读取也不自动代表可写。

### 6. Evidence 语义

- `Evidence` 应说明“为什么这个结果可以被确认”。
- 证据应来自真实交互结果，而不是实现细节或主观描述。
- 推荐写成一句短句，例如：
  - `SSH authentication succeeded`
  - `INFO returned redis_version without authentication`
  - `listDatabaseNames succeeded without authentication`

### 7. Enrichment 语义

- enrichment 只能发生在成功结果上。
- enrichment 负责补充上下文，不负责篡改核心命中结论。
- 当前实现里，`StageEnriched` 的前提是 `Enrichment` map 产生了新的补采数据。
- enrichment 当前主要用于补 `Enrichment` 数据，不应把未确认结果“补采成成功”，也不应把 `Risk` 当作现阶段接入必填项。

## 建议的最小交付面

一个新协议若要进入默认内置能力，建议最少满足：

- 有协议目录项
- 有独立协议目录
- 至少一种可工作的 prober
- 结果语义测试覆盖
- 如支持凭证探测，则字典路径可解析
- 如支持 enrichment，则 enrichment 路由已接通且不会破坏 `confirmed` 语义

## 不建议的做法

- 为了少写代码，把协议扩展强行改成纯配置驱动
- 在 `pkg/secprobe/run.go` 里直接追加协议特判
- 把多个协议复用成一个“通用 prober”后再用大量分支区分
- 只根据 banner、端口或弱特征就直接判定未授权成功
- 不写失败分类，统一只回填 `Error`
- enrichment 与 probe 共用一条大函数，导致主流程难以维护

## 结论

`secprobe v1.4` 的协议扩展重点不是“更快多接协议”，而是“把后续每次接协议的工程动作固定下来”。后续新增协议应优先遵循目录、装配、元数据、结果语义这四类约束，确保协议越多，维护成本不会线性失控。
