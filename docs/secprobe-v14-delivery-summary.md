# GoMap secprobe v1.4 交付总结

日期：2026-04-23

## 1. 文档目的

本文用于总结 `secprobe v1.4` 的实际交付结果，方便后续做：

- 版本回顾
- 团队同步
- roadmap 衔接
- 后续协议扩展参考

本文重点说明：

- `v1.4` 实际解决了什么问题
- 为什么本轮不是“继续扩协议”
- 当前 `secprobe` 的扩展模式已经被整理到什么程度
- 后续新增协议应该沿着什么路径继续推进

## 2. 本次交付目标

`v1.4` 的定位不是继续扩大协议面，而是先把 `secprobe` 的协议扩展模式整改清楚，让后续新增协议时的改动边界更清晰、成本更可控、行为更一致。

本次目标包括：

- 拆分默认协议装配逻辑，收口 `run.go` 职责
- 提取内置协议目录元数据，统一协议别名、默认端口、字典名、能力声明
- 统一弱口令字典候选装配逻辑，减少协议扩展时的重复代码
- 明确 enrichment 路由边界，避免协议装配与补采逻辑耦合
- 补齐协议扩展开发指南和 README 入口说明
- 保持 GoMap 作为引擎端 / 工具端定位，不引入平台化概念

## 3. 已完成能力

### 3.1 默认协议装配层拆分

`pkg/secprobe/run.go` 不再直接承载默认协议装配细节，相关逻辑已拆分为独立的默认注册表装配层。

本次已完成：

- 新增 `pkg/secprobe/default_registry.go`
- 把默认协议装配从执行链中解耦出来
- 新增 `pkg/secprobe/enrichment_router.go`
- 将 enrichment 路由从默认装配逻辑中继续拆开

这样可以明确区分：

- 执行编排
- 默认协议注册
- enrichment 路由

后续新增协议时，不再需要优先修改一处不断膨胀的 `run.go`。

### 3.2 内置协议目录元数据收口

本次新增 `pkg/secprobe/protocol_catalog.go`，用于集中维护内置协议的元数据定义。

当前已统一纳管的元数据包括：

- 协议标准名
- 协议别名
- 默认端口
- 默认字典名
- 支持的探测类型
- 是否支持 enrichment

本次也明确了边界：

- protocol catalog 是“元数据目录”，不是协议实现本身
- 将协议写入 catalog，并不会自动完成 registry 注册
- 如协议支持 enrichment，仍需显式接入 enrichment router

这保证了“元数据可配置”和“核心握手逻辑必须代码实现”之间的边界清晰。

### 3.3 字典候选装配统一

本次新增 `pkg/secprobe/dictionaries.go`，统一弱口令字典候选路径计算逻辑。

历史版本已完成：

- `loadCredentialsFromDir` 统一通过 `CredentialDictionaryCandidates` 获取候选
- catalog 命中时优先使用 `DictNames`
- 支持别名输入兼容，例如：
  - `postgres`
  - `redis/tls`
- 未知协议仍保留原始输入，用于回退路径计算
- 空协议名不再生成异常候选路径

当前版本已进一步演进为共享密码池模型，上述 `CredentialDictionaryCandidates` / `DictNames` / 协议字典装配方式已不再作为推荐入口。

这使后续新增协议时：

- 默认密码装配逻辑不需要散落在多处
- 别名、标准协议名、TLS 变体的兼容策略更一致
- 协议扩展时的测试点也更集中

### 3.4 扩展开发边界文档化

本次补齐了协议扩展指南与 README 说明，明确了 `secprobe` 当前的扩展模式。

已完成：

- 新增 `docs/secprobe-protocol-extension-guide.md`
- 更新 `README.md` 中的 `v1.4` 扩展模式说明

当前已经明确：

- GoMap 的 `secprobe` 扩展模式更接近“内置插件 / registry 风格”
- 新增协议仍需要在 `internal/secprobe/<protocol>/` 下实现代码
- metadata 只能帮助声明别名、端口、默认用户、共享密码源、能力等静态信息
- 握手、认证、未授权确认、enrichment、失败分类仍必须由代码实现
- 默认密码如需内置，应维护共享密码池 `app/secprobe/dicts/passwords/global.txt`，协议差异放入 metadata

这意味着 `v1.4` 已经把“后续怎么扩”说清楚了，但没有把新增协议误简化成“只改配置文件”。

## 4. 实际交付文件范围

本次交付重点涉及：

- `pkg/secprobe/default_registry.go`
- `pkg/secprobe/default_registry_test.go`
- `pkg/secprobe/enrichment_router.go`
- `pkg/secprobe/protocol_catalog.go`
- `pkg/secprobe/protocol_catalog_test.go`
- `pkg/secprobe/dictionaries.go`
- `pkg/secprobe/dictionaries_test.go`
- `pkg/secprobe/run.go`
- `README.md`
- `docs/secprobe-protocol-extension-guide.md`

## 5. 交付提交记录

本轮核心交付对应以下提交链：

1. `2986480`
   - `refactor(secprobe): 拆分默认协议装配层`
2. `a84d4ec`
   - `refactor(secprobe): 解耦默认装配与 enrichment 路由`
3. `5b15029`
   - `refactor(secprobe): 提取内置协议目录元数据`
4. `84731bc`
   - `fix(secprobe): 修复协议目录兼容与隔离问题`
5. `a0d3b4d`
   - `refactor(secprobe): 统一字典候选与协议能力查询`
6. `f90eeef`
   - `fix(secprobe): 修复字典候选兼容边界`
7. `1673deb`
   - `docs(secprobe): 新增协议扩展开发指南`
8. `9a75a52`
   - `docs(secprobe): 修正协议扩展指南边界说明`
9. `2425dc8`
   - `docs(secprobe): 补充 v1.4 扩展模式说明`
10. `deecd9d`
   - `docs(secprobe): 修正 README 扩展入口说明`

## 6. 验证结果

本次已实际通过：

- `go test -count=1 ./pkg/secprobe ./internal/secprobe/... ./cmd`
- `go test ./...`

同时，本轮各子任务在执行过程中也已分别完成针对性测试与复核，包括：

- 默认注册表装配测试
- 协议目录兼容与隔离测试
- 字典候选装配与别名兼容测试
- 文档边界复核

因此，本轮应视为：

- `secprobe v1.4` 扩展模式整改已完成
- 当前仓库在最终验证时全量测试通过

## 7. 当前能力边界

`v1.4` 已完成的是“扩展模式整改”，不是“协议扩容版本”。

当前边界包括：

- 不把新增协议简化成纯配置驱动
- 不引入平台控制层概念
- 不把 GoMap 改造成运营平台
- 不在本轮同时推进多目标并发治理
- 不增加过多 CLI 显示控制参数
- 不把内部状态字段直接稳定为平台侧对外契约

当前更适合的定位仍然是：

- GoMap 作为引擎端 / 即时工具端
- 接收上层中心或扫描平台下发的探测任务
- 负责按协议执行探测并返回结果

## 8. 当前已知限制

### 8.1 新协议扩展仍需要代码接入

虽然 `v1.4` 已经补齐元数据目录与扩展指南，但新增协议仍至少需要补齐以下内容：

- `internal/secprobe/<protocol>/` 协议实现
- 默认 registry 注册
- 如支持 enrichment，则接入 enrichment router
- 协议测试

因此，当前模式并不是“新增规则只改配置文件”。

### 8.2 protocol catalog 不会自动驱动完整能力接入

当前 `protocol_catalog.go` 仅负责维护协议元数据，不负责自动生成：

- 协议实现
- registry wiring
- enrichment wiring
- 默认字典资源打包

这属于当前有意保留的工程边界，用来避免配置元数据与真实协议能力脱节。

### 8.3 内部状态字段仍不建议作为平台稳定契约

`Stage`、`FailureReason`、`Capabilities`、`Risk` 等字段当前更适合作为：

- 内部执行语义
- 测试断言
- 后续演进预留

但目前不建议直接作为运营平台的稳定对接契约字段使用。

## 9. 对后续工作的建议

建议后续继续沿着 `docs/secprobe-v13-v20-roadmap.md` 的方向推进，并以 `v1.4` 整理好的扩展模式为基础做协议扩展。

建议包括：

- 后续新增协议优先遵循 `docs/secprobe-protocol-extension-guide.md`
- 先按统一骨架补协议实现，再接 registry / enrichment / 字典资源
- 优先保证单协议确认准确性、失败分类一致性、测试完整性
- 多目标并发治理继续放在 `v2.0` 之后再评估
- 继续保持 GoMap 作为引擎端供外部平台集成，不在当前项目内引入平台概念

如果后续进入协议扩展阶段，应优先把新增协议视为“按统一模式接入的新内置协议”，而不是“配置驱动规则项”。

## 10. 结论

`secprobe v1.4` 已经完成了从“可以继续往里堆协议”到“扩协议前先把工程模式整理清楚”的升级。

它的核心价值不在于本轮新增了多少协议，而在于把后续协议扩展最容易失控的几个边界先收住了：

- 装配边界更清晰
- 协议元数据更集中
- 字典候选策略更统一
- 文档入口更明确
- 扩展路径更可复用

这为后续继续补充更多弱口令协议和未授权协议，提供了更稳定的工程基础。
