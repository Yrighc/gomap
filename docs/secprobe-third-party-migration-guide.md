# secprobe 三方接入升级迁移指南

日期：2026-05-08

## 1. 文档目的

本文面向以库形式集成 `secprobe` 的三方调用方、协议扩展方与历史兼容接入方，说明 `secprobe` 在本轮 phase 调整后的接入方式、兼容边界与升级建议。

本文重点回答三个问题：

- 这轮 phase 到底改了什么。
- 现有三方调用代码是否需要修改。
- 如果你是协议扩展方，今后应该按什么方式继续接入。

## 2. 本轮调整的本质

本轮不是单纯“又加了几个协议”，而是把 `secprobe` 的运行模型进一步收口成：

`metadata -> planner -> engine -> provider`

也就是：

- `metadata`
  - 负责描述协议静态信息，例如协议名、别名、端口、能力、默认用户与共享密码源
- `planner`
  - 负责把候选目标与运行参数编译成执行计划
- `engine`
  - 负责统一执行顺序、停止条件、错误分类与结果归并
- `provider`
  - 负责单次原子协议动作，例如“一次认证尝试”或“一次未授权确认”

同时弱口令候选侧已经进一步收口成：

`metadata.dictionary -> credential profile -> generator -> engine`

这意味着当前默认内置路径已经不再以“是否存在一个 legacy batch prober”作为主心智模型，而是以：

- 是否有协议元数据
- 是否注册了对应 capability 的 provider
- 候选是否能由 generator 成功生成

来决定协议是否真正可执行。

## 3. 本轮 phase 实际完成了什么

结合 Phase 3 / 4 / 5，当前已经完成：

- 内置 `credential` 协议收口为 atomic provider 执行路径
- `Run` / `RunWithRegistry` 统一走 planner + engine 主链路
- `credential` 候选加载已统一走 generator，而不是各协议零散直读 txt
- `memcached unauthorized` 改为 simple template executor 执行
- 内置默认弱口令从“每协议一份字典”改为“全局共享密码池 + 协议差异 metadata”
- `DictDir` / `dict_dir` / `-weak-dict-dir` 这类自定义默认字典目录入口已移除
- public `Registry.Register(...)` 兼容路径继续保留，但被隔离为显式 compatibility adapter
- builtin 协议能力判断不再等价于 `Lookup(..., ProbeKindXxx)` 是否命中
- 新增 `imap` / `pop3` / `ldap` / `kafka` 已按同一 provider-first 模型进入默认能力面

当前默认行为可以概括为：

- builtin hot path 是 provider-first
- legacy public prober 仍可用
- 但 legacy public prober 不再是内置协议默认实现模型

可以把这次新增协议的落地理解成一个很明确的升级信号：

- 新协议先补 metadata
- 再补 atomic provider
- 最后进默认 registry

而不是像早期那样：

- 先写一个批量 prober
- 再让 `Run` 主链路去做特判兼容

## 4. 对三方调用方的影响

### 4.1 直接调用方

如果你只是把 `secprobe` 当成库来调用，例如使用：

- `BuildCandidates`
- `Run`
- `RunWithRegistry`
- `DefaultRegistry`
- `CredentialProbeOptions`

那么大多数情况下不需要改接口调用代码。

也就是说，下面这类调用仍然成立：

```go
candidates := secprobe.BuildCandidates(scanResult, secprobe.CredentialProbeOptions{})
out := secprobe.Run(context.Background(), candidates, secprobe.CredentialProbeOptions{
    Timeout:            3 * time.Second,
    StopOnSuccess:      true,
    EnableUnauthorized: true,
})
```

这类调用方需要更新的不是 API，而是认知：

- `Run` 内部已经不是“直接找一个 prober 然后跑完一批凭证”
- 而是“先编译 Plan，再由 engine 调度 provider 执行”

如果你当前的三方扫描器只是调用 `Run` / `RunWithRegistry`，那么这轮新增 `imap` / `pop3` / `ldap` / `kafka` 后，通常不需要额外改调用代码。

更准确地说，你需要关注的是“输入候选是否能命中这些协议”：

- `imap`
  - 支持 `143`、`993`、`imaps`、`imap/ssl`
- `pop3`
  - 支持 `110`、`995`、`pop3s`、`pop3/ssl`
- `ldap`
  - 支持 `389`、`636`、`ldaps`
- `kafka`
  - 第一版按 `9092` service / port fallback 建模
  - 默认认证路径是 `SASL/PLAIN`
  - `9093` 作为 TLS 常见端口由 provider 内部处理

也就是说，对三方调用方最常见的适配动作不是改 API，而是：

1. 更新服务识别或候选映射
2. 确认目标端口会被送入 `BuildCandidates` / `Run`
3. 如有自定义服务名，补齐到 metadata alias 或候选归一化层

### 4.2 协议扩展方

如果你是自己往 registry 里扩协议的人，本轮建议你把扩展模式从：

- `Register(myProber)`

迁移到：

- `RegisterAtomicCredential(...)`
- `RegisterAtomicUnauthorized(...)`

也就是从“注册一个批量 prober”切到“注册单次原子能力 provider”。

### 4.3 历史兼容方

如果你的现有三方扩展已经实现了 public `Prober`，当前仍然可以继续使用：

```go
r := secprobe.NewRegistry()
r.Register(myLegacyProber)
```

但这条路径现在的定位是：

- 兼容旧扩展
- 过渡保留
- 不再代表推荐扩展模型

## 5. 三种接入方式

### 5.1 方式一：直接调用型

适用场景：

- 你不扩协议
- 只想直接调用内置能力
- 只关心输出结果，不关心内部执行模型

推荐写法：

```go
package main

import (
    "context"
    "time"

    "github.com/yrighc/gomap/pkg/secprobe"
)

func run(candidates []secprobe.SecurityCandidate) secprobe.RunResult {
    return secprobe.Run(context.Background(), candidates, secprobe.CredentialProbeOptions{
        Timeout:            5 * time.Second,
        Concurrency:        10,
        StopOnSuccess:      true,
        EnableUnauthorized: true,
        EnableEnrichment:   true,
    })
}
```

升级建议：

- 继续使用现有 API 即可
- 不要假设内置协议一定能通过 `Registry.Lookup(..., kind)` 暴露出 legacy batch prober
- 如果你只需要执行结果，优先使用 `Run` / `RunWithRegistry`，不要依赖 registry 内部实现细节

### 5.2 方式二：provider 扩展型

适用场景：

- 你要新增私有协议
- 你要接入自定义认证器
- 你希望和当前 engine 主路径保持一致

这是当前推荐的三方扩展方式。

推荐写法：

```go
package main

import (
    "context"

    "github.com/yrighc/gomap/pkg/secprobe"
    myproto "github.com/your-org/your-project/internal/secprobe/myproto"
)

func run(candidates []secprobe.SecurityCandidate) secprobe.RunResult {
    r := secprobe.NewRegistry()
    secprobe.RegisterDefaultProbers(r)

    r.RegisterAtomicCredential("myproto", myproto.NewAuthenticator(nil))
    r.RegisterAtomicUnauthorized("myproto", myproto.NewUnauthorizedChecker(nil))

    return secprobe.RunWithRegistry(context.Background(), r, candidates, secprobe.CredentialProbeOptions{
        EnableUnauthorized: true,
        StopOnSuccess:      true,
    })
}
```

这条路径的优点是：

- 与当前 builtin 主执行链一致
- 停止条件、错误分类、结果归并统一由 engine 控制
- provider 只需要实现单次动作，职责边界更清晰
- 不会把 loop、重试和停止策略重新散落回协议实现里

适配原则：

- `Credential` provider 只负责一次 `AuthenticateOnce`
- `Unauthorized` provider 只负责一次 `CheckUnauthorizedOnce`
- 字典循环、停止条件、能力顺序由 engine 决定

如果你要参考当前仓库里的真实样板，建议优先看：

- `internal/secprobe/imap/auth_once.go`
- `internal/secprobe/pop3/auth_once.go`
- `internal/secprobe/ldap/auth_once.go`
- `internal/secprobe/kafka/auth_once.go`
- `internal/secprobe/activemq/auth_once.go`
- `internal/secprobe/zabbix/auth_once.go`
- `internal/secprobe/neo4j/auth_once.go`

这四个协议分别覆盖了：

- 文本协议显式 TLS 端口
- DN 风格用户名
- 二进制协议最小握手
- 统一错误分类回传

对三方扩展方来说，这比继续参考历史 batch prober 更接近当前推荐模型。

### 5.2.1 P2 HTTP/API Credential 子层

当前 `zabbix`、`neo4j` 通过 `internal/secprobe/httpauth` 复用 HTTP 登录辅助逻辑，
但对外仍然只是普通 `credential` provider。

这意味着三方扩展方如果需要接类似协议，应优先：

1. 保持 `RegisterAtomicCredential(...)`
2. 在 provider 内复用 HTTP helper
3. 由 provider 自己定义固定登录 endpoint 与成功判定
4. 不新增顶层 capability

### 5.3 方式三：历史 public prober 兼容型

适用场景：

- 你已经有一批 public `Prober` 实现
- 你暂时不想重写成 atomic provider
- 你需要平滑升级，不想一次性改造

兼容写法：

```go
r := secprobe.NewRegistry()
r.Register(myLegacyProber)
out := secprobe.RunWithRegistry(ctx, r, candidates, opts)
```

当前兼容模型的真实含义是：

- `Registry.Register(...)` 仍然接受旧 public prober
- 运行时会通过显式 adapter 桥接到新 engine 所需的 provider 语义
- 这条路径的目标是兼容，不是推荐新接入方式

如果你准备长期维护该扩展，建议逐步迁移到 provider 扩展型。

## 6. 老写法与新写法对照

### 6.1 只调用内置能力

老写法：

```go
out := secprobe.Run(ctx, candidates, opts)
```

新写法：

```go
out := secprobe.Run(ctx, candidates, opts)
```

结论：

- 调用方式基本不变
- 变化在内部执行模型，不在 public API

### 6.2 注册自定义协议

老写法：

```go
r := secprobe.NewRegistry()
r.Register(myProber)
```

推荐新写法：

```go
r := secprobe.NewRegistry()
r.RegisterAtomicCredential("myproto", myAuthenticator)
r.RegisterAtomicUnauthorized("myproto", myUnauthorizedChecker)
```

结论：

- 旧写法还能跑
- 新写法更符合当前主链路

### 6.3 判断协议是否“被支持”

老心智：

- `Lookup(candidate, ProbeKindCredential)` 能命中，就说明协议支持 credential

新心智：

- 一个协议是否支持某 capability，应以 metadata + provider 注册结果为准
- 不应再把 `Lookup(..., ProbeKindCredential)` 当成 builtin capability 的唯一判定信号

这是本轮最容易踩的坑之一。

## 7. 三方库形式引用时的更新适配方式

如果你是通过 `go get` 方式把 `gomap` 作为依赖集成，建议按下面三类情况处理。

### 7.1 你只是业务调用方

建议：

- 保持原有 `Run` / `RunWithRegistry` 调用
- 升级后重点回归结果是否符合预期
- 不要依赖 `Registry` 的内部查找行为做 capability 推断

重点回归项：

- `EnableUnauthorized` 开关是否仍符合预期
- `StopOnSuccess` 是否仍符合预期
- 命中结果的 `FindingType`、`Evidence`、`Username`、`Password` 是否符合预期
- 未显式传入 `Credentials` 时，默认候选是否来自内置共享密码池

### 7.2 你维护私有协议扩展

建议：

- 新增协议优先直接写 atomic provider
- 在自己的封装层里保留一层 registry 装配函数
- 明确把“协议实现”和“装配入口”分开维护

推荐结构：

- `internal/secprobe/myproto/authenticator.go`
- `internal/secprobe/myproto/unauthorized.go`
- `pkg/yourwrapper/secprobe_registry.go`

装配层示例：

```go
func RegisterMySecprobe(r *secprobe.Registry) {
    if r == nil {
        return
    }
    r.RegisterAtomicCredential("myproto", myproto.NewAuthenticator(nil))
    r.RegisterAtomicUnauthorized("myproto", myproto.NewUnauthorizedChecker(nil))
}
```

如果你的私有协议也需要默认弱口令候选生成能力，当前建议同步维护：

- 一份协议 metadata
- 必要的 `default_users` / `extra_passwords` / `default_pairs`
- 一个 atomic provider

也就是让私有协议尽量和内置协议保持同一条链路：

`metadata -> generator -> engine -> provider`

### 7.3 你维护历史 legacy prober 扩展

建议分两步走：

1. 先继续通过 `Registry.Register(...)` 保持功能可用
2. 再逐步把旧 prober 拆成 atomic `credential` / `unauthorized` provider

这样做的好处是：

- 升级成本可控
- 可先验证行为一致性
- 后续再切到推荐模型时风险更低

## 8. 本轮后默认内置能力的维护方式

当前弱口令引擎建议按下面方式维护：

- 协议静态信息放在 metadata
- 候选生成策略放在 dictionary metadata + generator
- 执行计划由 planner 统一生成
- 执行控制由 engine 统一负责
- 协议单次动作由 provider 负责
- 只有确实无法模板化、必须真实状态交互的协议逻辑，才继续保留 code-backed 特例

当前可以这样理解内置能力：

- `credential`
  - 已基本收口为 atomic provider 执行
- `unauthorized`
  - 简单请求/响应型能力可走 bounded template executor
  - 复杂状态型能力仍保留 code-backed 实现

当前仓库中的典型例子：

- `memcached unauthorized`
  - 已接到 simple template executor
- `zookeeper unauthorized`
  - 仍保留 code-backed 路径

字典侧当前也可以这样理解：

- `inline`
  - 仍然最高优先级，显式传入后只做去重，不做自动扩展
- `builtin shared password source`
  - 未传 inline 时使用 `app/secprobe/dicts/passwords/global.txt`
- `protocol metadata`
  - 只描述默认用户、协议额外密码、精确账号密码对与默认 tier

这意味着默认候选的维护重心不再是多份协议字典，而是一份共享密码池加少量协议差异声明。

## 9. 当前 simple unauthorized template 的边界

为了避免 YAML 继续膨胀成 DSL，当前模板执行器是刻意收边的。

当前边界包括：

- 只支持 `tcp`
- 一次请求
- 一次读回包
- `contains-all` 匹配
- 不支持循环
- 不支持重试
- 不支持分支
- 不支持状态机

如果某协议的未授权确认需要：

- 多轮握手
- 会话维持
- 条件分支
- 复杂状态切换

那么应继续使用代码实现，不应强行塞进模板。

## 10. 当前 scan profile 与字典分层边界

当前 credentials 层内部已经具备：

- `fast`
- `default`
- `full`

三种 scan profile，以及：

- `top`
- `common`
- `extended`

三层 tier 语义。

但对三方调用方需要特别说明两点：

1. 当前公开 `Run` / `RunWithRegistry` / `Scan` 主链路仍固定使用 `default`
2. 当前只有显式写出 `[common]` / `[extended]` 的字典行，tier 过滤才会真正区分层级

这意味着：

- 你现在升级到这版后，不需要额外传 scan profile 参数
- 但如果你维护共享密码池，已经可以开始按 tier 写数据
- 不应再用“取前 N 条”这种隐藏截断方式模拟 `fast/default/full`

## 11. 常见坑

### 11.1 把 `Lookup(...)` 当成 builtin capability 判断依据

这是升级后最常见的误判来源。

不要再假设：

- `Lookup(candidate, ProbeKindCredential)` 没命中
- 就表示这个 builtin 协议不支持 credential

在当前模型里，builtin credential 很多是 atomic/provider-first，不必经由 legacy lookup 暴露。

### 11.2 在 provider 里重新实现 loop

atomic provider 的职责是单次动作，不应重新承担：

- 字典循环
- 停止条件
- 重试策略
- 多 capability 调度

这些都应该交给 engine。

### 11.3 试图把复杂未授权逻辑下沉到模板

simple template executor 是受限执行器，不是通用协议 DSL。

如果协议需要多阶段交互，就继续写代码，不要为了“看起来统一”而把逻辑塞进模板。

### 11.4 混淆“兼容可用”和“推荐模式”

`Registry.Register(...)` 现在的语义是“兼容仍可用”，不是“推荐新扩展继续这么写”。

### 11.5 继续按协议维护多份默认字典

当前版本已经移除自定义默认字典目录入口，也不再推荐新增 `app/secprobe/dicts/<protocol>.txt`。

推荐做法是：

- 通用密码维护在 `app/secprobe/dicts/passwords/global.txt`
- 协议默认用户维护在 `app/secprobe/protocols/*.yaml`
- 少量协议特征密码写入 `extra_passwords`
- 必须精确保留的账号密码组合写入 `default_pairs`

## 12. 建议的回归测试基线

三方升级后，至少建议覆盖下面几类回归：

1. 内置 credential 命中回归
2. 内置 unauthorized 命中回归
3. unauthorized 失败后 credential 回退回归
4. `StopOnSuccess=true` 时的停止行为
5. `EnableUnauthorized=true/false` 的分支行为
6. 共享密码源缺失或 tier 过滤为空时的 `no-credentials` 行为
7. inline 凭据优先且保持字面语义
8. 如使用 tier-tagged 字典，默认档位过滤行为
9. 自定义 provider 注册后的 capability 命中行为
10. legacy public prober 兼容路径行为

如果你有私有协议扩展，建议额外覆盖：

1. atomic provider 单次成功
2. atomic provider 单次失败分类
3. 超时与取消传播
4. 与 engine 停止条件联动

## 13. 升级 checklist

建议三方升级时按下面顺序核对：

1. 确认你是“直接调用方”还是“协议扩展方”
2. 如果只是调用方，先保持现有 API 不变
3. 如果是扩展方，优先评估能否迁移到 atomic provider
4. 检查是否有代码依赖 `Lookup(..., kind)` 作为 capability 判断
5. 检查是否把 loop、重试、停止条件写死在协议实现里
6. 检查是否仍依赖 `DictDir` / `-weak-dict-dir` / 每协议默认字典文件
7. 检查未授权确认是否适合模板化，还是应继续 code-backed
8. 补齐回归测试后再升级生产调用

## 14. 总结

这轮升级对三方最重要的变化，不是“API 变了”，而是“推荐扩展模型变了”。

可以把当前结论简单记成：

- 直接调用方基本无感升级
- 新扩展优先走 atomic provider
- 老扩展仍可通过 public prober adapter 兼容
- builtin 心智模型已经从 legacy prober 驱动切换为 metadata + planner + engine + provider

如果后续继续在 `secprobe` 上维护私有协议，建议把 provider 扩展型作为默认方案，把 legacy public prober 仅视为迁移过渡层。
