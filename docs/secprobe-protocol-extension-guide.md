# secprobe 协议扩展开发指南

日期：2026-05-08

本文用于说明当前版本 GoMap `secprobe` 的协议扩展方式。重点不是把协议扩展改造成纯配置驱动，而是把当前已经落地的扩展模型、职责边界和接入步骤讲清楚，避免后续新增协议时再次回到“在运行主链路里临时拼协议”的模式。

## 1. 当前扩展模型

当前 `secprobe` 的主执行模型是：

`metadata -> planner -> engine -> provider`

可以把它理解成四层：

- `metadata`
  - 描述协议静态信息
  - 例如协议名、别名、默认端口、能力、默认字典、模板引用
- `planner`
  - 把候选目标和运行参数编译成执行计划
  - 决定本次要不要跑 `credential`、要不要跑 `unauthorized`、字典从哪里来、成功后是否补采
- `engine`
  - 负责统一执行顺序、停止条件、错误归类与结果归并
- `provider`
  - 负责单次原子协议动作
  - 例如“一次认证尝试”或“一次未授权确认”

当前弱口令候选生成则进一步收口为：

`metadata.dictionary -> credential profile -> generator -> engine`

这意味着当前协议扩展的核心已经不是：

- 在某处塞一个批量 prober
- 再让 `run.go` 用特判把它拼进去

而是：

- 用 metadata 描述协议静态属性
- 用 provider 提供单次原子能力
- 由 planner 和 engine 负责执行控制
- 由 generator 负责弱口令候选生成

## 2. 当前推荐扩展路径

新增协议时，当前推荐的顺序是：

1. 先补协议 metadata
2. 再实现协议 provider
3. 然后注册到默认 registry 或自定义 registry
4. 如需补采，再接 enrichment
5. 如属简单未授权协议，再评估是否可走 template executor

也就是说，当前推荐扩展模型不是：

- 只改 YAML 即可

也不是：

- 先写一个大而全的 public prober，再让主流程去适配它

而是：

- YAML 负责静态声明
- 代码负责真实执行

当前仓库里新增协议的参考实现已经可以直接对照：

- `imap`
  - metadata: `app/secprobe/protocols/imap.yaml`
  - provider: `internal/secprobe/imap/auth_once.go`
- `pop3`
  - metadata: `app/secprobe/protocols/pop3.yaml`
  - provider: `internal/secprobe/pop3/auth_once.go`
- `ldap`
  - metadata: `app/secprobe/protocols/ldap.yaml`
  - provider: `internal/secprobe/ldap/auth_once.go`
- `kafka`
  - metadata: `app/secprobe/protocols/kafka.yaml`
  - provider: `internal/secprobe/kafka/auth_once.go`

这四个协议可以视为当前版本“新增 credential 协议”的标准样板。

## 3. 一个协议应该放在哪里

新增协议时，代码和元数据通常会落在下面几类位置。

### 3.1 协议 metadata

内置协议 metadata 放在：

`app/secprobe/protocols/*.yaml`

这里负责声明的应是协议静态信息，例如：

- 协议标准名
- 协议别名
- 默认端口
- 支持的能力
- 默认字典来源
- 结果默认策略
- 简单模板引用

约束：

- metadata 只描述“协议是什么”，不描述“如何执行网络交互”
- metadata 不负责循环、重试、状态机、分支控制
- metadata 中声明支持某能力，不等于默认 registry 已经自动可执行该能力

### 3.2 协议实现目录

协议代码实现放在：

`internal/secprobe/<protocol>/`

推荐按能力拆分文件：

- `authenticator.go`
  - `credential` 原子认证动作
- `unauthorized.go`
  - `unauthorized` 原子确认动作
- `enrichment.go`
  - 命中后的补采逻辑
- `*_test.go`
  - 对应能力测试

当前建议优先采用如下文件命名：

- `auth_once.go`
  - 单次 credential 认证
- `auth_once_test.go`
  - 单次认证测试
- `unauthorized.go`
  - 单次 unauthorized 确认
- `enrichment.go`
  - 命中后的补采

约束：

- 一个协议一个目录
- 不同能力分文件，不要把认证、未授权确认和 enrichment 混成一条大流程
- provider 只做单次原子动作，不承担批量 loop 和停止策略

### 3.3 默认装配层

如果协议要进入内置默认能力，需要接到：

`pkg/secprobe/default_registry.go`

当前推荐装配方式是：

- `RegisterAtomicCredential(...)`
- `RegisterAtomicUnauthorized(...)`

而不是优先注册 legacy public prober。

原则：

- 默认 registry 只负责 wiring
- 协议逻辑不要重新塞回 `pkg/secprobe/run.go`
- builtin hot path 应继续保持 provider-first

### 3.4 模板目录

如果协议适合 simple unauthorized template executor，则模板放在：

`app/secprobe/templates/unauthorized/*.yaml`

当前模板装载与执行代码位于：

- `pkg/secprobe/template/loader.go`
- `pkg/secprobe/template/unauthorized.go`

适用前提不是“这个协议有未授权能力”，而是“这个未授权确认动作足够简单，能被受限模板准确表达”。

### 3.5 字典与候选生成层

当前弱口令字典相关实现集中在：

`pkg/secprobe/credentials/`

这一层负责：

- 把 metadata 中的 `dictionary` 编译成运行时 profile
- 统一处理 `inline > builtin shared password source` 来源优先级
- 执行基础去重
- 执行基础变异
- 按 tier 选择最终候选

这一层不负责：

- 网络交互
- 协议握手
- stop / retry / timeout
- 成功判定

因此后续如果要调整“默认用哪些口令”“是否允许空用户名”“是否启用基础变异”，优先应修改 metadata 或 `pkg/secprobe/credentials/*`，不要把这些逻辑塞回 provider。

当前内置默认弱口令维护方式已经进一步收口为：

- 一份共享密码池
  - `app/secprobe/dicts/passwords/global.txt`
- 每协议单独声明：
  - `default_users`
  - `extra_passwords`
  - `default_pairs`
  - `default_tiers`
  - `allow_empty_username`
  - `allow_empty_password`
  - `expansion_profile`

也就是说，现在不再推荐为每个协议长期维护一整份独立密码库。
真正需要协议差异时，优先：

1. 增补协议默认用户名
2. 增补少量协议特征密码
3. 补精确账号密码对
4. 必要时再补 generator 变异策略

而不是回退成“每个协议复制一份完整密码字典”。

## 4. 哪些内容适合 metadata

当前适合沉淀为 metadata 的内容包括：

- 协议标准名
- 协议别名
- 默认端口
- 默认用户
- 共享密码源
- 协议额外密码与精确账号密码对
- 默认字典层级
- 是否支持 `credential`
- 是否支持 `unauthorized`
- 是否支持 `enrichment`
- 简单模板引用
- 结果默认策略

这些内容的共同特点是：

- 属于静态声明
- 不依赖真实网络交互
- 适合被候选构建、能力选择、字典决策和 planner 复用

推荐做法：

- 优先在 `app/secprobe/protocols/*.yaml` 维护
- 让候选构建、协议归一化和字典选择尽量消费同一份 metadata
- 把“支持哪些能力”视为静态契约，而不是到处手写 `switch`

当前 `dictionary` 节点建议至少维护下面这些字段：

```yaml
dictionary:
  default_users:
    - root
    - admin
  password_source: builtin:passwords/global
  extra_passwords:
    - ssh
  default_pairs:
    - username: root
      password: toor
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
```

字段语义：

- `default_users`
  - 协议默认用户名列表；如 Redis、VNC、SNMP 这类无用户名协议，可显式写空字符串
- `password_source`
  - 默认共享密码池，目前内置为 `builtin:passwords/global`
- `extra_passwords`
  - 该协议在共享密码池之外追加的少量协议特征密码
- `default_pairs`
  - 需要精确保留的账号密码对，不参与用户名密码笛卡尔扩展
- `default_tiers`
  - 该协议默认允许使用哪些层
- `allow_empty_username`
  - 是否允许生成空用户名候选
- `allow_empty_password`
  - 是否允许生成空密码候选
- `expansion_profile`
  - 基础变异策略组

边界要求：

- YAML 只做策略声明
- YAML 不做循环
- YAML 不做网络操作
- YAML 不做状态机

## 5. 哪些内容必须代码实现

下面这些内容仍必须留在代码中：

- 协议握手
- 连接建立与超时控制
- 一次认证尝试
- 一次未授权确认动作
- enrichment 补采逻辑
- 成功确认条件
- 错误识别与失败分类
- 证据文本生成
- 命中后能力标记

原因很简单：

- 这些都依赖真实协议交互
- 很多协议存在握手时序、状态机和返回值判定差异
- 同样叫“未授权”，不同协议的确认动作完全不同

`kafka` 是一个比较典型的例子：

- metadata 只声明它是 `credential` 协议、默认端口是 `9092`、默认用户名有哪些
- 但 `SASL/PLAIN` 握手、`9093` 的 TLS 路径、错误码识别、认证成功证据，都必须留在代码里

这类协议如果强行模板化，反而会让维护复杂度升高。

反例：

- 不要试图用 YAML 描述循环和状态机
- 不要把错误分类做成一堆静态字符串表直接套用
- 不要把复杂协议交互硬挤进模板执行器

## 6. provider 的职责边界

当前推荐的扩展单元是 provider，而不是批量 public prober。

### 6.1 credential provider

`credential` provider 负责：

- 接收一个目标
- 接收一组用户名密码中的一对
- 完成一次 `AuthenticateOnce`
- 返回本次尝试结果

它不负责：

- 枚举整本字典
- 决定何时停止
- 决定失败后是否继续下一个 capability
- 统一重试或回退策略

这些都由 engine 负责。

### 6.2 unauthorized provider

`unauthorized` provider 负责：

- 接收一个目标
- 执行一次未授权确认动作
- 返回是否真实确认成功

它不负责：

- 维护复杂调度状态
- 介入 credential 执行顺序
- 改写 engine 的停止条件

### 6.3 为什么要收口成 atomic provider

因为这样可以把下面这些控制统一留在 engine：

- `stop-on-success`
- `credential` loop
- capability 顺序
- terminal-error 判定
- 结果归并

这样新增协议时，协议作者只需要回答一个更稳定的问题：

- “如何做一次原子协议动作”

而不必每次都重新实现一套批量执行控制。

## 7. 当前弱口令引擎的维护方式

当前建议把弱口令相关维护拆成三层：

### 7.1 策略层：metadata

放在：

- `app/secprobe/protocols/*.yaml`

这里维护：

- 默认用户名
- 共享密码源
- 协议额外密码
- 精确账号密码对
- 默认层级
- 空用户名/空密码开关
- 基础变异策略

### 7.2 数据层：共享密码池

放在：

- `app/secprobe/dicts/passwords/global.txt`

当前支持按密码行维护，并可显式标注 tier：

```text
123456
{user}
[common] {user}@123
[extended] Passw0rd
```

说明：

- 不带 tier 前缀的密码会被视为 `top`
- 只有显式写出 `[common]` / `[extended]`，分层过滤才会真实区分
- 当前内置密码项参考 fscan `DefaultPasswords` 维护，fscan 采用 MIT License；空密码不写成空行，由协议 metadata 的 `allow_empty_password` 控制生成
- 不再为每个协议维护 `app/secprobe/dicts/<protocol>.txt`
- 协议差异通过 metadata 的 `default_users`、`extra_passwords`、`default_pairs` 表达

这意味着当前版本不会再用“前 N 条”来伪装 `fast/default/full`。

### 7.3 执行层：generator

放在：

- `pkg/secprobe/credentials/sources.go`
- `pkg/secprobe/credentials/expand.go`
- `pkg/secprobe/credentials/tiers.go`
- `pkg/secprobe/credentials/generator.go`

这里负责：

- 来源优先级
- 候选去重
- 基础变异
- 层级过滤

维护原则：

- 想改来源顺序，改 generator
- 想改基础变异，改 `expand.go`
- 想改层级交集，改 `tiers.go`
- 不要把这些逻辑塞回 provider

## 8. legacy public prober 的位置

public `Registry.Register(...)` 当前仍然保留，但定位已经变化。

它现在的角色是：

- 历史兼容层
- 三方旧扩展过渡层
- 个别仍需兼容的 code-backed 路径桥接层

它不再是当前推荐的 builtin 扩展模型。

这点尤其重要：

- 不要再把“能通过 `Lookup(..., ProbeKindCredential)` 找到 batch prober”当成协议是否支持 builtin credential 的唯一判断信号

当前 builtin 协议很多已经走：

- metadata + atomic provider

而不是：

- legacy core/public prober 暴露

## 9. simple unauthorized template 的使用边界

当前 simple unauthorized template executor 是刻意收边的受限执行器，不是通用协议 DSL。

当前边界包括：

- 只支持 `tcp`
- 一次请求
- 一次读回包
- `contains-all` 匹配
- 不支持循环
- 不支持重试
- 不支持分支
- 不支持状态机

因此适合模板化的协议，应满足：

- 单次请求即可触发确认
- 单次响应即可提供足够证据
- 成功判定可由简单匹配表达

当前典型例子：

- `memcached unauthorized`

不适合模板化的协议，通常有这些特征：

- 需要多轮握手
- 需要会话维持
- 需要客户端库或真实 session
- 需要条件分支或状态切换

当前典型例子：

- `zookeeper unauthorized`

这类协议应继续走 code-backed provider，而不是为了“统一成 YAML”硬塞进模板。

## 10. 新协议接入 Checklist

新增一个协议时，建议至少按下面顺序检查：

1. 确认协议标准名、别名与默认端口
2. 在 `app/secprobe/protocols/*.yaml` 增加 metadata
3. 确认支持哪些能力：`credential`、`unauthorized`、`enrichment`
4. 如果支持凭证探测，确定默认用户与共享密码源
5. 如果支持凭证探测，明确 `default_tiers`
6. 如果需要基础变异，明确 `expansion_profile`
7. 在 `internal/secprobe/<protocol>/` 新建协议目录
8. 实现 atomic `authenticator`
9. 如支持未授权，实现 atomic `unauthorized checker`
10. 如命中后需补采，实现 `enrichment`
11. 在 `pkg/secprobe/default_registry.go` 注册 provider
12. 如果该协议是简单未授权协议，评估是否改走 template executor
13. 如果使用模板化未授权，补 `app/secprobe/templates/unauthorized/*.yaml`
14. 如果需要协议特征密码，优先补 metadata 的 `extra_passwords` 或 `default_pairs`
15. 如需扩充通用默认密码，补 `app/secprobe/dicts/passwords/global.txt` 并显式标注 tier
16. 补对应测试
17. 复查不会破坏 `Run` / `RunWithRegistry` 的对外契约

## 11. 结果语义要求

协议扩展必须遵守统一结果语义。即使 CLI / JSON 当前没有把所有内部字段都直接对外暴露，扩展实现仍应保持内部语义稳定、可推断、可测试。

### 11.1 Success 语义

- `Success=true` 只用于已经真实确认命中的结果
- `credential` 命中应落到 `credential-valid`
- `unauthorized` 命中应落到 `unauthorized-access`
- 不能把“端口开着”“像这个协议”“握手通了”直接算命中

### 11.2 Stage 语义

- `matched`
  - 命中协议路由，但还没形成有效尝试
- `attempted`
  - 已实际发起一次探测，但未确认成功
- `confirmed`
  - 已通过真实协议交互确认命中
- `enriched`
  - 在成功结果基础上追加了新的补采数据

约束：

- 不支持协议时可以直接跳过
- enrichment 没有产生新数据时，不应强行改成 `enriched`

### 11.3 SkipReason 语义

跳过原因应尽量落在统一分类：

- `unsupported-protocol`
- `probe-disabled`
- `no-credentials`

约束：

- `SkipReason` 用于没有进入有效探测或前置条件不足的场景
- 已经做了真实协议交互后失败，不要再写成 skip

### 11.4 FailureReason 语义

探测失败时，尽量归入统一失败分类：

- `connection`
- `authentication`
- `timeout`
- `canceled`
- `insufficient-confirmation`

约束：

- 无法精确识别时，宁可归到 `insufficient-confirmation`
- 不要因为错误分类不确定就误报成功
- 成功结果不应残留失败原因

### 11.5 Evidence 语义

- `Evidence` 应说明为什么可以确认该结果
- 证据应来自真实交互
- 应尽量短、稳定、可测试

推荐风格：

- `SSH authentication succeeded`
- `INFO returned redis_version without authentication`
- `listDatabaseNames succeeded without authentication`

### 11.6 Enrichment 语义

- enrichment 只能发生在成功结果上
- enrichment 负责补上下文，不负责篡改主 finding 结论
- 不能把失败结果“补采成成功”

## 12. 推荐的测试基线

新增协议时，至少建议覆盖下面几类测试：

1. 单次 provider 成功
2. 单次 provider 失败
3. 超时传播
4. 取消传播
5. 错误分类是否符合预期
6. `Evidence` 是否稳定
7. 成功结果的 `FindingType` 是否正确
8. `RunWithRegistry` 下能否被正确调度
9. 如支持 credential，字典链路是否可用
10. 如支持 credential，inline 凭据是否保持字面语义且优先于 builtin
11. 如支持 credential，显式 tier 行是否能被正确过滤
12. 如支持 credential，共享密码源缺失或 tier 过滤为空时是否按 `no-credentials` 处理
13. 如支持 unauthorized，credential / unauthorized 顺序与回退是否符合预期
14. 如支持 enrichment，补采失败是否不影响主 finding
15. 如使用 template executor，模板匹配成功与失败是否都可覆盖

## 13. 当前 scan profile 边界

当前 credentials 层已经具备：

- `fast`
- `default`
- `full`

三种 scan profile 语义，但需要特别说明：

- 当前公开 `Run` / `RunWithRegistry` / `Scan` 主链路仍固定使用 `default`
- 也就是当前外部调用方还不能通过 public API 直接切换到 `fast` 或 `full`

因此文档中提到 `fast/default/full` 时，当前含义是：

- 内部字典与候选生成模型已经按这个抽象设计
- 后续可以平滑开放
- 当前默认运行语义等价于 `default`

## 14. 不建议的做法

- 为了少写代码，把协议扩展强行改成纯 YAML 执行
- 在 `pkg/secprobe/run.go` 里继续追加协议特判
- 在 provider 里自己重写 loop、stop 或 retry
- 把 legacy public prober 当成推荐新模型继续扩
- 只根据 banner、端口或弱特征直接判定未授权成功
- 把复杂会话协议硬塞进 simple template executor
- 让 enrichment 改写主 finding 的确认语义
- 把旧 flat txt 的前几条硬解释成 `top/common/extended`
- 用隐藏截断冒充 `fast/default/full`

## 15. 结论

当前 `secprobe` 的协议扩展方式，核心已经从“批量 prober 驱动”切换到“metadata + planner + engine + provider”驱动。

后续新增协议时，建议始终记住四个判断：

- 这个信息是不是静态 metadata
- 这个动作是不是单次原子 provider
- 这个执行控制是不是应该交给 engine
- 这个协议是否真的适合 template executor

只要这四个边界不被破坏，协议数量继续增长时，`secprobe` 的维护成本和行为一致性都会更可控。
