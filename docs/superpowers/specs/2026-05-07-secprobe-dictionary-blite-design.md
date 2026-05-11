# secprobe 字典子系统 B-lite 设计

日期：2026-05-07

## 1. 文档目的

本文用于定义 GoMap `secprobe` 弱口令引擎下一阶段的字典子系统整改方案。

本次设计不调整当前已经完成的：

- `metadata -> planner -> engine -> provider` 主执行模型
- atomic `AuthenticateOnce` provider 约束
- unauthorized template executor 边界

本次只聚焦一个问题：

- 当前字典系统仍停留在“静态 txt 文件读取器”阶段，导致弱口令能力只能支撑少量爆破，难以同时兼顾命中率、可理解性与后续可演进性

本文目标是把当前字典侧能力升级为：

- 一个小而稳、可解释、可演进的 `B-lite` 字典子系统

## 2. 问题定义

当前系统已经具备：

- 协议 metadata 中的 `dictionary.default_sources`
- `ExpansionProfile / AllowEmptyUsername / AllowEmptyPassword` 字段
- `inline > dict_dir > builtin` 的来源优先级
- engine 逐条消费 credential 并调用 atomic provider

但当前实际生效的字典行为仍主要是：

1. 根据协议找到一个或多个字典文件名
2. 读取文本
3. 解析 `username : password`
4. 去重
5. 逐条执行

这会带来几个明显问题：

- 只能表达静态候选，不能表达“协议默认先试什么”
- metadata 中已有的 `ExpansionProfile` 等字段没有真正发挥作用
- 用户无法明确区分“默认深度”和“全量深扫”
- 当前弱口令能力更像“能执行的文件读取器”，而不是“可控的候选生成器”

## 3. 本次设计目标

本次 `B-lite` 设计目标如下：

1. 在不修改执行主链路语义的前提下，升级字典候选生成质量
2. 把当前 metadata 中与字典相关的字段真正接入运行时
3. 引入显式扫描档位，而不是隐式预算截断
4. 提升默认模式命中率，同时保持用户对扫描深度的认知清晰
5. 为后续更强字典能力预留演进路径，但本次不引入复杂评分或学习系统

## 4. 非目标

本次明确不做：

- 命中统计学习
- 评分模型
- 流式超大规模候选生成
- 多目标共享候选池
- YAML/metadata DSL 化
- 复杂协议族画像系统
- provider 侧批量循环
- engine 主执行模型重构

本次也不以“接近 fscan/chujiu 全部能力”为目标，而是先把当前系统从“静态 txt 读取器”升级为“可控的最小候选生成器”。

## 5. 设计总览

本次建议新增一层：

`metadata -> credential profile -> candidate generator -> engine`

各单元职责如下：

### 5.1 metadata

继续存放协议静态声明，例如：

- `default_sources`
- `expansion_profile`
- `allow_empty_username`
- `allow_empty_password`
- `default_tiers`

metadata 负责声明策略，不负责真实候选生成。

### 5.2 credential profile

把协议 metadata 解析成运行时可消费的轻量配置对象。

职责：

- 标准化协议字典策略
- 给 generator 提供稳定输入
- 隔离 metadata schema 与具体生成逻辑

### 5.3 candidate generator

这是本次新增的核心单元。

职责：

- 合并 `inline / dict_dir / builtin` 来源
- 执行基础去重
- 执行基础变异
- 按扫描档位决定使用哪些层
- 输出最终有序 credential 列表

它不负责：

- 协议网络交互
- 成功判断
- stop-on-success
- timeout / cancel 处理
- terminal error 判定

### 5.4 engine

继续保持现状：

- 按既有顺序消费 candidate generator 产出的 credential 列表
- 逐条调用 atomic `AuthenticateOnce`
- 控制 success / attempted / failed / skip 语义

## 6. 扫描档位设计

本次不采用“隐式预算截断”。

原因：

- 它会制造“用户以为扫全了，实际上只扫了前 N 条”的假完整性
- 不利于理解结果
- 不利于后续日志和结果解释

本次改为显式扫描档位：

- `fast`
- `default`
- `full`

语义定义如下：

### 6.1 fast

- 只使用 `top`
- 只做最小基础变异
- 用于快速高命中探测

### 6.2 default

- 使用 `top + common`
- 做基础变异
- 作为默认模式

### 6.3 full

- 使用 `top + common + extended`
- 做完整基础变异
- 作为显式深扫模式

结果语义要求：

- 用户必须能明确知道当前跑的是哪个档位
- 档位描述的是“扫描深度”，不是“隐藏截断数”

## 7. metadata 扩展方式

在当前 `dictionary` 节点上做最小扩展，不重做 schema。

建议新增：

```yaml
dictionary:
  default_sources:
    - ssh
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
  default_tiers:
    - top
    - common
```

字段语义：

- `default_sources`
  - 默认字典来源名
- `allow_empty_username`
  - 是否允许生成空用户名候选
- `allow_empty_password`
  - 是否允许生成空密码候选
- `expansion_profile`
  - 基础变异规则组
- `default_tiers`
  - 该协议默认推荐使用哪些层

合并规则：

- 运行时扫描档位决定“最多允许哪些层”
- 协议 metadata 决定“该协议默认推荐哪些层”
- generator 最终使用两者交集

例如：

- 运行时是 `default`
- 协议 `default_tiers` 是 `top + common`
- 则最终使用 `top + common`

如果：

- 运行时是 `full`
- 协议只声明 `top`

则本次仍只使用 `top`，不自动推断更多层。

## 8. 候选生成器设计

### 8.1 输入

generator 输入包括：

- 协议名
- `CredentialProfile`
- 运行时扫描档位
- `inline credentials`
- `dict_dir`
- builtin 字典读取能力

### 8.2 输出

输出为：

- 一个已排序、已去重、已完成基础变异的 `[]Credential`

### 8.3 来源优先级

保留当前用户心智：

- `inline`
- `dict_dir`
- `builtin`

但实现从“直接返回某一来源结果”升级为“进入同一生成流程”。

也就是说：

- 来源优先级仍存在
- 但后续仍统一经过去重、变异、层次拼接等处理

### 8.4 基础变异规则

`B-lite` 只做基础、可解释的变异。

第一版建议包括：

- `username == password`
- `username + 123`
- `username + @123`
- 空用户名
- 空密码

变异是否启用由：

- `expansion_profile`
- `allow_empty_username`
- `allow_empty_password`

共同决定。

本次不做复杂变异，例如：

- 主机名相关变异
- 年份/环境名/组织名变异
- 高级协议族特化词典

### 8.5 分层策略

本次引入三层：

- `top`
- `common`
- `extended`

语义如下：

- `top`
  - 极小、高命中、默认最快
- `common`
  - 协议常用候选
- `extended`
  - 显式深扫时才启用

第一期可以只先建立逻辑抽象，不强制立刻重排所有物理字典文件目录。

## 9. 数据流

运行数据流如下：

1. `metadata` 解析协议字典策略
2. 生成 `CredentialProfile`
3. generator 读取候选来源
4. generator 执行：
   - 去重
   - 变异
   - 分层选择
   - 排序
5. generator 输出最终 `[]Credential`
6. engine 逐条消费
7. provider 继续只做一次 `AuthenticateOnce`

这样职责边界保持清晰：

- metadata 决定“策略是什么”
- generator 决定“候选长什么样”
- engine 决定“怎么执行”
- provider 决定“一次尝试如何认证”

## 10. 目录结构建议

建议新增：

- `pkg/secprobe/credentials/profile.go`
- `pkg/secprobe/credentials/generator.go`
- `pkg/secprobe/credentials/sources.go`
- `pkg/secprobe/credentials/expand.go`
- `pkg/secprobe/credentials/tiers.go`
- `pkg/secprobe/credentials/types.go`

各文件职责：

- `profile.go`
  - 定义 `CredentialProfile`
  - metadata -> profile 解析
- `generator.go`
  - 统一生成入口
- `sources.go`
  - `inline / dict_dir / builtin` 候选读取
- `expand.go`
  - 基础变异规则
- `tiers.go`
  - 档位与层次合并逻辑
- `types.go`
  - 内部小类型

第一期不建议直接大规模搬迁：

- `app/secprobe/dicts/*.txt`

更稳妥的做法是：

- 先抽象逻辑
- 后续如确有需要，再逐步重组内置字典目录

## 11. 与现有系统的兼容要求

本次设计必须满足：

1. 不修改 public API 语义
2. 不修改 atomic provider 接口
3. 不修改 engine 主循环语义
4. 不要求协议 provider 改造
5. `inline > dict_dir > builtin` 用户认知不被破坏
6. `no-credentials` 语义保持兼容

## 12. 验收标准

本次完成后，至少应满足：

1. `ExpansionProfile` 在运行时真正生效
2. `AllowEmptyUsername / AllowEmptyPassword` 真正影响候选生成
3. 扫描档位 `fast/default/full` 行为清晰且可解释
4. 默认模式下不出现“隐式截断但用户不知情”的行为
5. 旧协议 provider 无需改造即可获得字典增强收益
6. `ssh/mysql/redis/telnet` 至少能吃到一批基础变异候选

## 13. 测试要求

至少需要覆盖以下测试：

### 13.1 profile 解析测试

- metadata 缺省值处理
- `default_tiers` 解析
- `expansion_profile` 解析
- `allow_empty_*` 解析

### 13.2 generator 测试

- `inline` 优先级
- `dict_dir` 优先级
- builtin 回退
- 去重行为
- 基础变异行为
- 档位与层次交集逻辑
- 空用户名/空密码开关行为

### 13.3 engine 集成测试

- generator 输出可被 `engine.Run` 正常消费
- `stop-on-success` 不退化
- terminal error 行为不退化
- `no-credentials` 语义不退化

### 13.4 回归测试

- 旧 `inline / dict_dir / builtin` 行为保持兼容
- 不改 provider 代码也能获得新候选生成收益

## 14. 风险与控制

本次最大的风险不是实现难度，而是范围膨胀。

重点防止：

- 把 generator 做成第二个 engine
- 把 metadata 扩张成小 DSL
- 把 `B-lite` 设计顺手长成评分系统
- 为了分层字典立即大规模重组资源目录

控制方式：

- 明确本次只做基础变异
- 只做显式扫描档位
- 不做隐藏预算截断
- 不做复杂评分与学习
- 先抽逻辑，再考虑资源重组

## 15. 结论

本次 `B-lite` 方案的本质，不是把 `secprobe` 变成重型爆破平台，而是把它从：

- “能执行的静态 txt 读取器”

升级为：

- “可控、可解释、可演进的最小候选生成器”

这是当前阶段最合适的整改目标。

它既能提升默认命中率，又不会破坏现有执行架构，也为后续再向更强字典能力演进留下了清晰边界。
