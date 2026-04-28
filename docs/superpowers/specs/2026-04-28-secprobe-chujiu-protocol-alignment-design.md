# secprobe 协议赋能设计（基于 Chujiu_reload 对标）

日期：2026-04-28

## 1. 背景

当前 `GoMap secprobe` 已形成相对稳定的协议扩展骨架，支持：

- `credential`：`ftp`、`ssh`、`telnet`、`mysql`、`postgresql`、`redis`
- `unauthorized`：`redis`、`mongodb`

同时，项目已经明确：

- 协议目录声明由 `pkg/secprobe/protocol_catalog.go` 统一维护
- 默认装配由 `pkg/secprobe/default_registry.go` 统一注册
- 协议实现位于 `internal/secprobe/<protocol>/`
- 结果语义、失败分类、字典接线遵循 `docs/secprobe-protocol-extension-guide.md`

`Chujiu_reload` 是一个独立扫描器，不是 `GoMap` 的子引擎。本次目标不是复用其运行模式，而是对标其“弱口令 + 未授权访问”覆盖能力，筛选适合迁移到 `GoMap secprobe` 的协议集合，并给出分阶段接入设计。

## 2. 目标

本设计目标：

1. 明确 `Chujiu_reload` 当前已具备的相关协议能力边界
2. 明确哪些协议适合直接进入 `GoMap secprobe` 主目录
3. 明确哪些协议应暂缓，仅保留为候选扩展层
4. 给出稳定、可分批执行的协议接入路线

本设计不包含：

- 具体协议代码实现
- 对 `secprobe` 公共执行链路的大规模重构
- 与弱口令/未授权无关的漏洞插件迁移

## 3. 对标口径

本次对标采用以下口径：

- 同时统计 `credential` 与 `unauthorized` 两类协议
- 同时展示“当前默认有效支持”和“潜在可迁移能力”两层状态
- 同时展示“典型服务协议”和“通用认证 / 代理协议”两组能力
- 漏洞利用类插件不纳入 `secprobe` 协议主目录范围

### 3.1 GoMap 当前基线

`GoMap secprobe` 当前默认有效支持：

- `credential`：`ftp`、`ssh`、`telnet`、`mysql`、`postgresql`、`redis`
- `unauthorized`：`redis`、`mongodb`

### 3.2 Chujiu_reload 当前默认有效支持

典型服务协议：

- `credential`：`ssh`、`ftp`、`telnet`、`mysql`、`postgresql`、`redis`、`mongodb`、`smb`、`rdp`、`vnc`、`snmp`、`smtp`、`amqp`、`mssql`、`oracle`
- `unauthorized`：`redis`、`mongodb`、`ftp`、`telnet`、`memcached`、`zookeeper`

通用认证 / 代理协议：

- `credential`：`http`、`https`、`http_proxy`、`https_proxy`、`socks5`
- `unauthorized`：`socks5`、`adb`、`jdwp`

### 3.3 Chujiu_reload 潜在可迁移能力

- 代码存在但默认禁用：`imap`、`pop3`
- 漏洞型或暴露面插件：如 `ms17010`、特定 `telnet` CVE，不纳入本次 `secprobe` 主目录协议范围

## 4. 差异清单

相对 `GoMap secprobe` 当前基线，`Chujiu_reload` 可提供的主要协议增量为：

### 4.1 典型服务协议增量

建议纳入候选的 `credential` 增量：

- `mssql`
- `oracle`
- `rdp`
- `vnc`
- `smb`
- `smtp`
- `amqp`
- `snmp`

暂不纳入本批的特例：

- `mongodb credential`
  - `Chujiu_reload` 具备实现，但 `GoMap` 当前已将 `mongodb` 放在 `unauthorized` 模型下
  - 如需支持 `mongodb credential`，建议后续单独立项，不与本批协议扩展混做

### 4.2 unauthorized 增量

建议优先纳入候选：

- `memcached`
- `zookeeper`

保留观察但不作为第一批主目录接入对象：

- `ftp unauthorized`
- `telnet unauthorized`

原因：

- 二者在语义上更接近“协议特化匿名访问”而非标准无凭证暴露
- 若直接与 `redis` / `mongodb` / `memcached` / `zookeeper` 混为一类，容易造成 `unauthorized` 语义边界模糊

### 4.3 通用认证 / 代理协议增量

保留为候选扩展层：

- `http`
- `https`
- `http_proxy`
- `https_proxy`
- `socks5`
- `adb`
- `jdwp`

原因：

- 其抽象层级与“典型服务协议”不同
- 字典需求、成功判定和证据表达方式差异较大
- 当前 `secprobe` 的协议目录、结果语义与默认装配更适合服务协议模型

## 5. 接入策略

### 5.1 分层接入原则

新增能力按三桶管理：

1. 直接纳入 `credential` 主目录
2. 直接纳入 `unauthorized` 主目录
3. 暂不进入主目录，仅保留为候选扩展层

### 5.2 直接纳入 `credential` 主目录的协议

- `mssql`
- `oracle`
- `rdp`
- `vnc`
- `smb`
- `smtp`
- `amqp`
- `snmp`

这些协议共同特点：

- 存在相对明确的认证成功判定
- 能复用现有 `credential` 语义和执行链
- 适合在 `internal/secprobe/<protocol>/prober.go` 中独立实现

### 5.3 直接纳入 `unauthorized` 主目录的协议

- `memcached`
- `zookeeper`

这些协议共同特点：

- 可以通过真实交互确认匿名访问成立
- 能复用 `redis` / `mongodb unauthorized` 的确认模型
- 不依赖用户名/密码字典

### 5.4 暂缓进入主目录的协议

- `http`
- `https`
- `http_proxy`
- `https_proxy`
- `socks5`
- `adb`
- `jdwp`
- `ftp unauthorized`
- `telnet unauthorized`

处理原则：

- 暂不纳入 `pkg/secprobe/protocol_catalog.go` 默认主目录
- 如后续业务要求很强，需先单独形成“通用认证 / 代理协议接入规范”后再评估

## 6. 接入契约

所有新增协议必须遵循当前 `secprobe` 已有契约，不为单个协议破坏公共模型。

### 6.1 结果语义

#### `credential`

- 只有在真实完成认证成功后，才允许返回命中结果
- 命中结果应进入 `confirmed`
- `FindingType` 应为 `credential-valid`

禁止行为：

- 仅因端口开放、握手成功、banner 命中而记成功

#### `unauthorized`

- 只有在真实确认未授权访问成立后，才允许返回命中结果
- 命中结果应进入 `confirmed`
- `FindingType` 应为 `unauthorized-access`

禁止行为：

- 仅因服务开放或返回非空内容而直接判定成功

### 6.2 字典策略

- 只有 `credential` 协议进入字典接线
- `unauthorized` 协议不绑定字典加载链路
- 新增 `credential` 协议必须在 `DictNames`、`app/secprobe/dicts/`、`app/assets.go` 三处完成闭环

### 6.3 catalog 边界

`pkg/secprobe/protocol_catalog.go` 仅负责：

- 标准名
- 别名
- 端口
- `DictNames`
- `ProbeKinds`
- 是否支持 enrichment

不得在 catalog 中塞入协议私有实现逻辑或特殊控制分支。

### 6.4 协议实现边界

协议私有逻辑应全部位于：

- `internal/secprobe/<protocol>/prober.go`
- `internal/secprobe/<protocol>/unauthorized_prober.go`
- `internal/secprobe/<protocol>/enrichment.go`

公共执行链不应因为单个协议需求被硬编码。

### 6.5 默认注册边界

协议只有在以下条件全部满足后，才进入 `pkg/secprobe/default_registry.go`：

- catalog 声明完成
- prober 实现完成
- 测试齐备
- `credential` 字典接线完成
- 失败分类和证据语义满足规范

不接受“半接入态协议”进入默认 registry。

## 7. 分阶段路线

### 7.1 第一阶段：高价值 `credential`

建议批次：

- `mssql`
- `rdp`
- `vnc`
- `smb`

退出条件：

- catalog 完成
- 协议实现完成
- 默认 registry 注册完成
- 至少具备成功、认证失败、超时/取消三类测试

### 7.2 第二阶段：第二批 `credential`

建议批次：

- `smtp`
- `amqp`
- `oracle`
- `snmp`

退出条件：

- 满足第一阶段全部要求
- 证据字段能体现协议特有确认依据

### 7.3 第三阶段：`unauthorized`

建议批次：

- `memcached`
- `zookeeper`

退出条件：

- 必须以真实交互确认匿名访问成立
- 不依赖 banner-only 判断
- 如支持 enrichment，确认逻辑与 enrichment 解耦

### 7.4 第四阶段：候选扩展层评估

候选：

- `http`
- `https`
- `http_proxy`
- `https_proxy`
- `socks5`
- `adb`
- `jdwp`

退出条件：

- 输出一份是否纳入 `secprobe` 主目录的评估结论
- 若决定纳入，必须先补独立接入规范，而不是直接复用当前服务协议范式

## 8. 推荐优先级

建议整体优先顺序：

1. `mssql`
2. `rdp`
3. `vnc`
4. `smb`
5. `smtp`
6. `amqp`
7. `oracle`
8. `snmp`
9. `memcached unauthorized`
10. `zookeeper unauthorized`

排序依据：

- 与当前 `secprobe` 模型的一致性
- 协议价值
- 确认语义清晰度
- 对公共链路的扰动成本

## 9. 测试与验收要求

每个新增协议至少覆盖：

- 成功命中
- 认证失败或未授权失败
- 超时
- 上下文取消
- 证据字段填写
- `Stage` 填写
- `FindingType` 填写
- `FailureReason` 或 `SkipReason` 填写

额外验收要求：

- 不修改 `pkg/secprobe` 现有对外 API
- 不破坏 CLI 参数语义
- 不因单个协议扩展而引入全局逻辑分叉

## 10. 最终建议

推荐采用“分层演进方案”：

- 先吸收 `Chujiu_reload` 中与 `GoMap secprobe` 模型高度同构的典型服务协议
- 再补 roadmap 已经自然对齐的 `unauthorized` 协议
- 最后单独评估通用认证 / 代理协议是否进入主目录

核心原则：

- 借鉴 `Chujiu_reload` 的协议覆盖面
- 不借鉴其“统一粗放注册所有协议”的组织方式
- 坚持 `GoMap secprobe` 当前已经形成的契约化扩展模式
