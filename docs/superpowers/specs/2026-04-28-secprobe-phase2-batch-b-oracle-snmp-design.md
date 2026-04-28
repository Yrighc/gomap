# secprobe 第二阶段 Batch B（Oracle + SNMP）设计

日期：2026-04-28

## 1. 背景

`GoMap secprobe` 第二阶段第一批 `smtp + amqp` 已经完成：

- `catalog / dict / assets / default registry / candidate / README` 闭环已建立
- `confirmed + credential-valid` 成功契约已在新协议上复用并验证
- 协议扩展模式继续保持为：
  - `pkg/secprobe/protocol_catalog.go` 负责协议元数据
  - `app/secprobe/dicts/*.txt` 与 `app/assets.go` 负责内置字典闭环
  - `internal/secprobe/<protocol>/` 负责协议私有实现
  - `pkg/secprobe/default_registry.go` 控制默认接线

第二阶段剩余的 `credential` 协议为：

- `oracle`
- `snmp`

与 `smtp + amqp` 相比，第二批的难点更集中在两处：

- `oracle` 需要更重的数据库连接驱动与更严格的连接目标约束
- `snmp` 不属于传统用户名密码协议，其凭证语义需要映射进当前 secprobe `credential` 契约，但不能污染已经稳定的公共路径

## 2. 目标

本设计目标：

1. 在不修改 secprobe 公共 API 的前提下接入 `oracle` 与 `snmp`
2. 把 `oracle` 第一版收敛到最小稳定登录面，避免一开始扩成多种连接模型
3. 把 `snmp` 第一版收敛到 `v2c community`，以最小真实读操作确认凭证成立
4. 延续 batch-A 的任务分段、review 节奏和回归方式，降低第二批实现风险
5. 顺手清理 `go.mod` 中 `github.com/rabbitmq/amqp091-go` 被错误标记为 `// indirect` 的依赖噪音

本设计不包含：

- Oracle `SID` 模式
- Oracle 多地址、TNS 别名、复杂网络拓扑支持
- SNMP v3
- 新的公共结果字段或新的公共 `Credential` 结构
- 为了适配 SNMP 而改造通用字典解析器

## 3. 范围与最小协议面

### 3.1 Oracle

Batch B 中的 `oracle` 第一版只支持：

- 默认端口 `1521`
- `service name` 直连
- 传统 `username : password` 字典格式

第一版明确不支持：

- `SID`
- TNS alias
- 多 host / RAC / 地址列表
- 额外高级连接参数矩阵

目标是先确认“最小稳定登录成功”，而不是在第一版就把 Oracle 连接串变体全部吃下。

### 3.2 SNMP

Batch B 中的 `snmp` 第一版只支持：

- `SNMP v2c`
- `community` 作为唯一凭证面
- 最小只读 OID 请求作为成功确认依据

第一版明确不支持：

- `SNMP v3`
- authPriv / authNoPriv
- trap
- 扩展 transport（TLS/DTLS/SSH）

## 4. 凭证映射策略

### 4.1 Oracle

`oracle` 完全复用现有 secprobe `Credential` 结构：

- `Username` = 数据库用户名
- `Password` = 数据库密码

字典格式继续使用：

```text
system : oracle
scott : tiger
```

### 4.2 SNMP

`snmp` 不引入新的公共凭证字段，也不修改全局字典解析器。

第一版采用“兼容现有解析链、由协议私有实现解释”的映射策略：

- `Username` 固定允许为空
- `Password` 视为 `community`

因此 `snmp.txt` 第一版采用如下兼容格式：

```text
: public
: private
: manager
```

解释规则：

- 行仍然通过现有 `username : password` 解析器进入 `Credential`
- `snmp` prober 只读取 `Password` 作为 community
- 空用户名不会向公共 API 暴露新语义

这样可以保持：

- 不改公共 API
- 不改全局解析器
- 不反向污染已经稳定的用户名密码协议路径

## 5. 成功与失败契约

### 5.1 通用约束

`oracle` 与 `snmp` 都必须继续遵循现有 secprobe 成功契约：

- `Success = true`
- `Stage = confirmed`
- `FindingType = credential-valid`

只有真实认证成功后，才允许返回上述结果。

以下情况都不能判成功：

- 端口开放
- listener / banner 返回
- capability / feature advertisement 返回
- 握手建立但认证未完成
- 未经确认的匿名或默认开放状态

### 5.2 Oracle 成功边界

只有在真实数据库登录成功后，才允许确认成功。

建议成功证据格式：

- `Oracle authentication succeeded`
- 或带最小版本/实例信息的安全证据文本

但第一版不以“补充丰富证据”为前提，优先保证登录确认语义稳定。

### 5.3 SNMP 成功边界

只有在使用 `community` 完成最小只读 OID 请求并获得有效响应时，才允许确认成功。

建议成功证据格式：

- `SNMP v2c community succeeded`
- 或附带最小 OID 成功读取说明

第一版不因为：

- UDP 端口有响应
- 收到不完整协议片段
- 协议识别命中

就直接判定成功。

## 6. 失败分类策略

### 6.1 Oracle

第一版至少区分：

- `authentication`
  - 用户名密码错误
  - 认证拒绝
- `connection`
  - 拨号失败
  - 连接失败
  - listener 不可达
  - 连接串目标不可达
- `timeout`
  - 上下文超时
  - 驱动连接/登录超时
- `canceled`
  - caller context 取消
- `insufficient-confirmation`
  - 少见、无法明确归类的错误

### 6.2 SNMP

第一版至少区分：

- `authentication`
  - community 无效
  - 无权限完成最小读操作
- `connection`
  - UDP 不可达
  - 网络错误
  - 建链/传输层失败
- `timeout`
  - 请求超时
- `canceled`
  - caller context 取消
- `insufficient-confirmation`
  - 无法明确归类但也未形成成功确认

## 7. 依赖与实现建议

### 7.1 Oracle 驱动

第一版应优先选择纯 Go、无需本机 Oracle Client 的最小稳定依赖。

选择标准：

- 能支持 `service name` 直连
- 能受 secprobe `ctx + timeout` 约束
- 不额外要求系统级 Oracle runtime
- 可通过最小 `Ping` 或等价登录确认完成成功判定

### 7.2 SNMP 依赖

`snmp` 第一版建议使用 `github.com/gosnmp/gosnmp`。

原因：

- 社区成熟
- 对 `v2c` 足够直接
- 可较容易注入 timeout 与最小请求行为

## 8. 文件与接线范围

### 8.1 Task 0：依赖清理

- Modify: `go.mod`

目标：

- 清理 `github.com/rabbitmq/amqp091-go` 的 `// indirect`
- 不做其他依赖噪音改动

### 8.2 Task 1：Batch B 共享接线

- Create: `app/secprobe/dicts/oracle.txt`
- Create: `app/secprobe/dicts/snmp.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`

目标：

- 完成 `oracle` / `snmp` 的字典、assets、catalog、alias 闭环
- `snmp` 的 canonical `DictNames` 也必须固定，不能走“原始服务名直接找文件”的旧路径

### 8.3 Task 2：Oracle

- Create: `internal/secprobe/oracle/prober.go`
- Create: `internal/secprobe/oracle/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

目标：

- 完成 Oracle 最小登录确认
- 接入默认 registry
- 补齐成功/失败/超时/取消/接线测试

### 8.4 Task 3：SNMP

- Create: `internal/secprobe/snmp/prober.go`
- Create: `internal/secprobe/snmp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

目标：

- 完成 SNMP v2c community 最小确认
- 接入默认 registry
- 补齐成功/失败/超时/取消/接线测试

### 8.5 Task 4：README 与回归切片

- Modify: `README.md`

目标：

- 更新内置 `credential` 协议说明
- 更新示例协议列表
- 跑 batch-B 回归切片并收尾

## 9. 默认 registry 与 candidate 约束

只有以下条件都满足后，协议才允许进入 `pkg/secprobe/default_registry.go`：

- catalog 声明完成
- 字典接线完成
- prober 实现完成
- 测试闭环完成
- 成功确认语义通过 review

Batch B 结束后，默认 registry 预期新增：

- `oracle`
- `snmp`

`BuildCandidates()` 仍继续受 `DefaultRegistry()` 约束，避免 catalog-only 协议提前进入候选集合。

## 10. 测试策略

### 10.1 共享接线测试

至少覆盖：

- `oracle` / `snmp` 字典资源 embed 成功
- `BuiltinCredentials()` 可以加载 canonical 协议
- alias 能正确归一到 canonical `DictNames`
- default registry 契约更新
- candidate 构建只在默认 registry 接入后才包含协议

### 10.2 Oracle 单测

至少覆盖：

- 登录成功
- 认证失败分类
- 超时
- 上下文取消
- 不能因 listener/握手弱信号误判成功

### 10.3 SNMP 单测

至少覆盖：

- community 成功
- community 失败分类
- 超时
- 上下文取消
- 不能因 UDP 可达或弱协议响应误判成功

### 10.4 回归切片

Batch B 收尾至少跑：

```bash
go test ./app ./pkg/secprobe ./internal/secprobe/oracle ./internal/secprobe/snmp -v
```

以及按需要补充与 batch-A 联动切片，避免二次扩容影响 `smtp` / `amqp` 已稳定路径。

## 11. 推荐实施顺序

推荐严格按如下顺序推进：

1. Task 0：清理 `amqp091-go // indirect`
2. Task 1：`oracle + snmp` 共享接线
3. Task 2：Oracle 实现与 review
4. Task 3：SNMP 实现与 review
5. Task 4：README / 回归切片 / 文档收尾

原因：

- 先消除依赖声明噪音，降低后续 diff 干扰
- 先锁共享接线，再分协议实现，避免 registry/candidate 契约漂移
- 把 `oracle` 和 `snmp` 分开 review，避免“重驱动问题”和“特殊凭证模型问题”互相放大

## 12. 成功标准

Batch B 完成后，应满足：

- `oracle` 与 `snmp` 均在不修改 secprobe 公共 API 的前提下接入
- `oracle` 第一版以 `1521 + service name` 的最小稳定登录面工作
- `snmp` 第一版以 `v2c community` 的最小真实读操作工作
- `snmp` 的特殊凭证语义被约束在协议私有实现内，不污染公共简单路径
- `catalog / dict / assets / registry / candidate / README` 闭环一致
- 成功结果严格满足 `StageConfirmed + credential-valid`
- 不因端口、banner、listener、capability、弱响应误判成功
- batch-B 回归切片通过
