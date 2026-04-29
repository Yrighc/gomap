# secprobe MongoDB Credential 接入设计

日期：2026-04-29

## 1. 背景

当前 `GoMap secprobe` 中，`mongodb` 已接入：

- `unauthorized` 探测
- `enrichment` 补采

同时，`Run` 链路已经支持同一服务同时存在 `credential` 与 `unauthorized` 两类 prober，并已调整为：

1. 开启 `EnableUnauthorized` 时优先执行 `unauthorized`
2. `unauthorized` 失败后回退到 `credential`
3. 仍保持“一次只返回一个成功 finding”的结果模型

在这个前提下，补齐 `mongodb credential` 已不再需要修改公共结果模型，只需要将 MongoDB 的凭证爆破能力按现有协议扩展契约接入。

## 2. 目标

本设计目标：

1. 为 `mongodb` 新增 `credential` 探测能力
2. 保留现有 `mongodb unauthorized` 与 `mongodb enrichment`
3. 复用当前 `unauthorized -> credential` 的执行顺序
4. 不改变 `Run` 的单 finding 返回模型

本设计不包含：

- 同一目标同时输出 `unauthorized` 与 `credential` 两条成功 finding
- `mongodb` 之外的协议改造
- `secprobe` 公共结果模型重构

## 3. 现状

### 3.1 当前 MongoDB 能力

`mongodb` 当前仅声明：

- `ProbeKinds: unauthorized`
- `SupportsEnrichment: true`

默认 registry 仅注册 `mongodb unauthorized`。

### 3.2 当前公共执行顺序

当同一服务同时具备两类 prober，且启用 `EnableUnauthorized` 时：

1. 先执行 `unauthorized`
2. 若 `unauthorized` 成功，立即返回
3. 若 `unauthorized` 失败，再执行 `credential`

因此 `mongodb credential` 接入后，将天然服从这套策略。

## 4. 方案选择

### 4.1 方案 A：最小增量接入

做法：

- 为 `mongodb` 新增 `credential` prober
- `protocol_catalog` 将 `mongodb` 改为同时支持 `credential` 和 `unauthorized`
- `default_registry` 同时注册两类 prober
- 保持现有 `Run` 行为不变

优点：

- 改动最小
- 与当前链路天然兼容
- 回归边界清晰

缺点：

- 同一目标仍只返回一个成功结果

### 4.2 方案 B：用 `credential` 替代 `unauthorized`

做法：

- 新增 `mongodb credential`
- 移除 `mongodb unauthorized`

问题：

- 会退化现有未授权能力
- 与当前 roadmap 方向不一致

### 4.3 方案 C：升级为双 finding 模型

做法：

- 同时执行 `unauthorized` 与 `credential`
- 同一候选可产出两条成功 finding

问题：

- 需要修改 `Run` 结果模型与统计语义
- 超出当前范围

### 4.4 推荐

采用方案 A。

原因：

- 业务目标只是补齐 `mongodb credential`
- 当前公共执行链已经能承载双路线
- 不需要为本次需求引入更大的结果模型变更

## 5. 设计

### 5.1 catalog 调整

更新 `pkg/secprobe/protocol_catalog.go` 中的 `mongodb` 声明：

- 保留现有 `DictNames`
- 保留 `SupportsEnrichment: true`
- 将 `ProbeKinds` 从仅 `unauthorized` 调整为：
  - `credential`
  - `unauthorized`

这表示 MongoDB 同时接入两类探测能力。

### 5.2 registry 调整

更新 `pkg/secprobe/default_registry.go`：

- 继续注册 `mongodb unauthorized`
- 新增注册 `mongodb credential`

保持 MongoDB 协议能力在默认 registry 中闭环。

### 5.3 协议实现

新增：

- `internal/secprobe/mongodb/credential_prober.go`

职责：

- 仅负责 MongoDB 的凭证探测
- 不承担 unauthorized 或 enrichment 逻辑

接口约定：

- `Name() == "mongodb"`
- `Kind() == credential`
- `Match(candidate)` 仅匹配 `candidate.Service == "mongodb"`

### 5.4 凭证成功判定

凭证探测必须满足“真实认证成功”原则。

建议流程：

1. 遍历候选用户名/密码
2. 使用真实凭证构造 MongoDB URI
3. 建立客户端连接
4. 执行一个最小只读确认动作
5. 仅当认证与确认都成功时，返回 `credential-valid`

推荐确认动作：

- `ListDatabaseNames`

原因：

- 当前 `mongodb unauthorized` 已使用该动作
- 语义稳定
- 可直接证明连接建立后具备真实访问能力

不建议只以 `mongo.Connect` 或纯 `Ping` 作为成功判定，因为它们对“认证成功且具备真实访问能力”的确认强度更弱。

### 5.5 结果语义

`mongodb credential` 命中时：

- `FindingType = credential-valid`
- `Stage = confirmed`
- 记录命中的 `Username` / `Password`
- `Evidence` 明确说明认证成功依据

推荐 evidence：

- `listDatabaseNames succeeded after authentication`

失败时：

- 优先复用当前已有失败原因语义：
  - `authentication`
  - `connection`
  - `timeout`
  - `canceled`
  - `insufficient-confirmation`

不引入新的 failure reason。

### 5.6 与 unauthorized 的协同

接入完成后，MongoDB 的默认行为为：

1. `EnableUnauthorized=false`
   - 仅执行 `credential`
2. `EnableUnauthorized=true`
   - 先执行 `unauthorized`
   - 命中则返回 `unauthorized-access`
   - 失败则继续执行 `credential`

这意味着：

- 未授权暴露仍是更高优先级结果
- 凭证爆破只在未授权未命中时介入

### 5.7 enrichment 约束

`mongodb enrichment` 继续保留，且只对成功结果生效。

本次不新增：

- credential 专属 enrichment 路由
- unauthorized 与 credential 的双 enrichment 并存策略

即：

- 有成功 finding，就按现有 enrichment 总开关继续走补采
- 不因本次改造改变 enrichment 公共语义

## 6. 测试设计

### 6.1 协议单测

新增 `mongodb credential` 单测，至少覆盖：

1. 正确命中服务匹配
2. 凭证成功时返回 `credential-valid`
3. 认证失败时返回失败结果
4. 上下文取消/超时分类正确
5. 仅连接成功但确认不足时不误判成功

### 6.2 registry / catalog 测试

更新：

- `protocol_catalog` 相关测试
- `default_registry` 相关测试

至少覆盖：

- `mongodb` 同时支持 `credential` 与 `unauthorized`
- 默认 registry 可分别 lookup 到两类 prober

### 6.3 Run 路径测试

至少补两条关键回归：

1. 当 `unauthorized` 成功时：
   - MongoDB 不再继续进入 credential
2. 当 `unauthorized` 失败时：
   - MongoDB 会继续回退到 credential
   - credential 成功时返回 `credential-valid`

### 6.4 真实容器回归

建议补真实 MongoDB 鉴权容器夹具，覆盖默认 registry 路径：

- 启动启用用户名/密码认证的 MongoDB 容器
- 使用内置或测试专用凭证
- 验证 `Run` 在 `EnableUnauthorized=true` 且 unauthorized 未命中的情况下，最终能回退到 credential 成功

## 7. 风险与边界

### 7.1 结果优先级

本次接入后，MongoDB 即使同时存在：

- 未授权访问
- 弱口令账号

默认也只返回第一个成功 finding。

这是当前结果模型的既有限制，不在本次解决范围内。

### 7.2 认证成功判定强度

若成功判定过弱，容易把“连接建立”误当成“认证成功”。

因此必须坚持：

- 真实凭证
- 真实只读确认动作

不能只看握手或客户端创建成功。

### 7.3 字典兼容

MongoDB 已有 `DictNames: mongodb, mongo`。

本次接入后，需要确保：

- 内置字典加载链路可直接复用
- 别名 `mongo` 仍能正确命中字典候选

## 8. 实施范围

计划中的预期改动文件：

- `internal/secprobe/mongodb/credential_prober.go`
- `internal/secprobe/mongodb/credential_prober_test.go`
- `internal/secprobe/testutil/testcontainers.go`
- `pkg/secprobe/protocol_catalog.go`
- `pkg/secprobe/protocol_catalog_test.go`
- `pkg/secprobe/default_registry.go`
- `pkg/secprobe/default_registry_test.go`
- `pkg/secprobe/run_test.go`

视现有测试组织方式，可能补充：

- 与候选构建或默认行为相关的测试文件

## 9. 验收标准

满足以下条件即视为完成：

1. `mongodb` 同时支持 `credential` 与 `unauthorized`
2. 默认 registry 可同时解析两类 prober
3. 开启 `EnableUnauthorized` 时，MongoDB 先跑未授权，失败后回退凭证爆破
4. 凭证成功必须基于真实认证与只读确认
5. 不引入新的公共结果模型变化
6. 相关单测、registry 测试、Run 测试与真实容器回归通过
