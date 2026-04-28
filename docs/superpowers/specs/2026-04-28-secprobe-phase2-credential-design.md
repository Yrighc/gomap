# secprobe 第二阶段 credential 协议扩展设计

日期：2026-04-28

## 1. 背景

`GoMap secprobe` 第一阶段已完成以下 `credential` 协议接入：

- `mssql`
- `rdp`
- `vnc`
- `smb`

同时，第一阶段已经验证了当前扩展模式可以稳定承载新增协议：

- `pkg/secprobe/protocol_catalog.go` 统一声明协议元数据
- `pkg/secprobe/default_registry.go` 统一控制默认接线
- `app/secprobe/dicts/*.txt` 与 `app/assets.go` 组成内置字典闭环
- `internal/secprobe/<protocol>/` 独立承载协议私有实现
- `BuildCandidates` 继续受 `DefaultRegistry()` 约束，避免 catalog-only 协议提前进入候选集合

基于 `Chujiu_reload` 的能力对标，第二阶段需要继续向 `credential` 模型扩展：

- `smtp`
- `amqp`
- `oracle`
- `snmp`

## 2. 目标

本设计目标：

1. 明确第二阶段四个协议的接入边界与分批策略
2. 在不改变 `secprobe` 公共 API 的前提下，定义可执行的协议契约
3. 先收敛第一批 `smtp + amqp` 的最小可用面
4. 为第二批 `oracle + snmp` 提前锁定语义边界，避免后续实现时再次争议

本设计不包含：

- 第一阶段协议的重构
- 新的公共执行链抽象层
- `unauthorized` 协议接入
- 通用代理 / 中间层协议接入

## 3. 分批策略

第二阶段采用“一份统一 spec，分两批实现”的方式推进。

### 3.1 Batch A：`smtp + amqp`

作为第二阶段第一批落地对象。

选择原因：

- 二者都可以在现有 `credential` 语义下表达“真实认证成功”
- 成功/失败边界比 `oracle` / `snmp` 更清晰
- 更适合沿用第一阶段已经验证过的默认 registry、字典、测试替身模式
- 依赖与本地验证成本相对可控，适合尽快形成第二阶段稳定基线

### 3.2 Batch B：`oracle + snmp`

作为第二阶段第二批落地对象。

推迟原因：

- `oracle` 往往需要更重的驱动依赖和更严格的连接参数约束
- `snmp` 虽然常被归类为“弱口令/弱凭证”，但它的凭证语义与用户名密码协议显著不同
- 二者如果和 `smtp + amqp` 同批推进，会明显提高实现与 review 风险

## 4. 协议边界

### 4.1 SMTP

第一批只覆盖最常见用户名密码认证面：

- `AUTH PLAIN`
- `AUTH LOGIN`

第一批不承诺支持：

- `CRAM-MD5`
- `NTLM`
- `XOAUTH2`
- 客户端证书认证
- 厂商私有扩展认证流

成功判定原则：

- 必须完成真实 SMTP 认证并得到服务端明确接受
- 仅因为服务返回 `EHLO` capability、声明支持 `AUTH`、或允许明文连接，不能判定成功

### 4.2 AMQP

第一批只覆盖最常见的用户名密码认证模型。

第一批不承诺支持：

- 特定 broker 私有扩展认证流
- 复杂 SASL 族群的广覆盖兼容
- 除标准用户名密码外的额外令牌模型

成功判定原则：

- 必须完成真实连接建立并通过认证阶段
- 仅因为端口开放、协议头握手成功、broker 返回 capability，不能判定成功

### 4.3 Oracle

第二批仍放在 `credential` 模型内，但在实现前就锁定以下边界：

- 目标是“真实数据库登录成功确认”
- 不为了接入 `oracle` 改造现有公共执行链
- 采用最小可用连接模式，不追求第一版即覆盖所有 SID / Service Name / 网络拓扑变体

后续计划应重点明确：

- 驱动选择
- 最小连接字符串策略
- 成功确认方式
- 典型错误分类

### 4.4 SNMP

`snmp` 继续归入第二阶段 `credential` 范畴，但必须明确它属于“特殊凭证模型”：

- 其凭证不完全等同于传统用户名密码
- 第一版更偏向“community / 安全参数成功确认”

因此 `snmp` 接入时允许出现以下差异：

- 字典内容格式可不同于传统 `username : password`
- 成功证据表达允许更贴近 SNMP 语义
- 但最终结果仍必须映射到当前 `credential-valid` 契约

第二批实现前必须再次明确：

- 采用的最小 SNMP 认证面
- community 或安全参数如何映射进当前字典加载链
- 成功证据和失败分类如何保持与公共语义兼容

## 5. 结果契约

第二阶段全部协议继续遵循现有 `credential` 契约，不修改公共 API，不新增对外结果字段。

### 5.1 成功语义

只有在真实认证成功后，才允许返回：

- `Success = true`
- `Stage = confirmed`
- `FindingType = credential-valid`

允许的证据示例：

- SMTP 服务端明确接受认证
- AMQP 认证完成并建立可用连接
- Oracle 登录成功
- SNMP 通过真实参数确认访问成立

### 5.2 禁止语义

以下情况都不能算成功：

- 端口开放
- banner 返回
- capability / feature advertisement 返回
- 握手建立但认证未完成
- 匿名访问或无需凭证的默认开放状态

## 6. 字典与 catalog 约束

### 6.1 字典接线

第二阶段四个协议全部属于 `credential`，因此都必须完成字典闭环：

- `app/secprobe/dicts/<protocol>.txt`
- `app/assets.go`
- `pkg/secprobe/protocol_catalog.go` 中的 `DictNames`

### 6.2 字典格式策略

- `smtp`、`amqp`、`oracle` 默认沿用现有 `username : password` 行格式
- `snmp` 若最终采用特殊格式，必须在第二批实现前单独确认其兼容策略
- alias 加载继续优先参考 canonical `DictNames`，不回退到“直接拿原始服务名找字典”的旧路径

### 6.3 catalog 边界

`pkg/secprobe/protocol_catalog.go` 只负责：

- 协议标准名
- 别名
- 默认端口
- `DictNames`
- `ProbeKinds`

不得在 catalog 中塞入协议私有认证逻辑。

## 7. 默认 registry 约束

协议只有在以下条件都满足后，才允许进入 `pkg/secprobe/default_registry.go`：

- catalog 声明完成
- 字典接线完成
- prober 实现完成
- 测试闭环完成
- 成功确认语义通过 review

Batch A 结束时，默认 registry 预期新增：

- `smtp`
- `amqp`

Batch B 结束时，默认 registry 再新增：

- `oracle`
- `snmp`

## 8. 实现批次设计

### 8.1 Batch A：`smtp + amqp`

第一批目标是复制第一阶段的成功模式，用最小兼容面建立第二阶段新基线。

预期特征：

- 不新增公共抽象层
- 每个协议各自拥有独立 `internal/secprobe/<protocol>/prober.go`
- 先解决“真实认证成功确认 + 最小错误分类 + 默认接线”

第一批完成后应满足：

- `smtp` 与 `amqp` 能进入默认 registry
- README 能明确更新内置 `credential` 协议说明
- `BuildCandidates` / registry / dict / catalog 闭环仍然一致

### 8.2 Batch B：`oracle + snmp`

第二批目标不是追求一次性覆盖所有复杂变体，而是在保持公共契约稳定的前提下接入“更重、更特化”的 credential 协议。

第二批设计原则：

- `oracle` 优先解决最小稳定驱动与登录确认
- `snmp` 优先解决 secprobe 语义映射，而不是追求协议覆盖面最大化
- 不为了适配 `snmp` 特殊凭证格式，反向破坏前面用户名密码协议的简单路径

## 9. 测试与验证策略

### 9.1 单元测试优先

Batch A 优先通过可注入握手桩、协议替身和最小状态机测试覆盖：

- 成功认证
- 认证失败
- 握手成功但认证未完成时不得误判成功
- 默认 registry 注册
- candidate / canonical dict 路径一致

### 9.2 集成测试策略

第二阶段第一批不把重型真实服务集成测试作为前置门槛。

原因：

- 目标是先稳定扩展模式
- 避免第一批被环境依赖拖慢
- 与第一阶段的“单测闭环 + 定向回归切片”方式保持一致

如后续有真实环境验证需求，可在实现完成后单独追加联调清单，而不是提前绑定到第一批计划里。

## 10. 成功标准

第二阶段 spec 完成后，后续实现应以以下标准验收：

### Batch A 成功标准

- `smtp`、`amqp` 完成 catalog / dict / registry / prober / README 闭环
- 成功结果严格满足 `StageConfirmed + credential-valid`
- 不因 capability、banner、开放端口误判成功
- 回归切片通过

### Batch B 成功标准

- `oracle`、`snmp` 在不改变公共 API 的前提下完成接入
- `snmp` 的特殊凭证语义得到明确约束，不污染已稳定的用户名密码路径
- 第二阶段整体文档、默认 registry 契约测试和回归切片完成同步
