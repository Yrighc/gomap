# secprobe P2 HTTP/API Credential Compatibility Design

日期：2026-05-11

## 1. 背景

当前 `secprobe` 已经形成稳定主链路：

`metadata -> planner -> engine -> provider`

并且当前内置 `credential` 执行已经收口到 atomic provider：

- `planner`
  - 只负责编译能力、目标和运行参数
- `engine`
  - 只负责能力顺序、凭证循环、停止条件和结果归并
- `provider`
  - 只负责一次原子协议动作

最近一批新增协议 `imap`、`pop3`、`ldap`、`kafka` 已经证明：只要协议可以稳定抽象成“一次认证尝试”，就可以在不修改顶层架构的前提下继续扩协议。

但 `P2` 中的部分协议开始出现新的访问面：

- `activemq`
  - 仍可视为较纯的认证协议
- `zabbix`
  - 更接近 Web/API 登录
- `neo4j`
  - 既可能走协议认证，也可能走 HTTP 管理面
- `rsync`
  - 容易同时涉及匿名访问与凭证认证边界

因此 `P2` 的关键不只是“补协议”，而是要在不破坏当前架构的前提下，为 HTTP/API 登录型协议提供兼容升级路径。

## 2. 目标

本设计目标：

1. 保持当前 `secprobe` 顶层 capability 与 engine 主链路不变
2. 在 `credential provider` 下兼容 HTTP/API 登录型协议
3. 为 `zabbix`、`neo4j` 提供一套可复用但不过度抽象的实现支撑层
4. 明确 `P2` 各协议的归类和推进顺序

本设计不包含：

- 引入新的顶层 capability，例如 `web-credential`
- 将 HTTP/API 登录抽象成 YAML DSL
- 将复杂多步 Web 登录做成通用框架
- 在本轮内直接实现 `rsync` 的完整 credential + unauthorized 混合流
- 推进 `cassandra`

## 3. 核心决策

### 3.1 保持顶层 provider 模型不变

当前顶层 provider 模型继续保持为三类：

- `CredentialAuthenticator`
- `UnauthorizedChecker`
- `Enricher`

也就是说，HTTP/API 登录不是新的 capability，而是 `CredentialAuthenticator` 的一种实现风格。

升级后的心智模型：

- `credential`
  - 原生协议认证型
    - `ssh`、`mysql`、`imap`、`pop3`、`ldap`、`kafka`
  - HTTP/API 登录型
    - `zabbix`、`neo4j`
- `unauthorized`
  - 代码型确认
    - `redis`、`zookeeper`
  - 模板型确认
    - `memcached`
- `enrichment`
  - 命中后的补采

### 3.2 不新增顶层 capability

本轮不引入：

- `web-credential`
- `api-credential`
- `management-login`

原因：

- `engine` 只关心“一次尝试返回什么结果”
- `planner` 不需要理解传输层差异
- 现在就新增 capability 会扩大 `planner/engine/registry/result` 的改动面
- 对 `P2` 规模来说属于过度设计

### 3.3 HTTP/API 登录继续满足“一次 AuthenticateOnce”

即使内部包含 1-2 次 HTTP 请求，对 `engine` 来说仍然必须是一次原子认证尝试。

约束：

- 不负责凭证循环
- 不负责 capability 顺序
- 不负责是否继续下一种协议模式
- 不负责全局重试和调度

这些职责继续留在 `engine`

## 4. HTTP/API Credential 子层设计

### 4.1 设计原则

不把每个 HTTP 协议都直接散写成独立 `net/http` 逻辑，而是在 `internal/secprobe/httpauth` 下增加一个很薄的复用层。

它不是通用框架，而是“登录尝试助手”。

### 4.2 建议结构

建议新增：

- `internal/secprobe/httpauth/client.go`
  - client 构造
  - timeout 控制
  - TLS 宽松配置
  - cookie/session 保持
- `internal/secprobe/httpauth/types.go`
  - 一次 HTTP 登录尝试的输入/输出辅助结构
- `internal/secprobe/httpauth/classify.go`
  - 通用 HTTP/TLS/连接/超时类错误分类辅助

协议自身仍然保留独立 provider：

- `internal/secprobe/zabbix/auth_once.go`
- `internal/secprobe/neo4j/auth_once.go`

### 4.3 通用层负责什么

通用层统一负责：

- HTTP client 构造
- 请求发送
- cookie/session 保持
- TLS 宽松策略
- 常见连接/TLS/超时错误归类辅助

### 4.4 协议层负责什么

协议层自己负责：

- 登录入口 URL
- 请求方法
- 参数编码方式
  - JSON
  - form
  - basic auth
- 登录成功判定
- 登录失败判定
- 证据文本
- 协议特有错误映射

### 4.5 明确不做什么

本轮不做：

- 通用 Web 登录 DSL
- 多因素认证支持
- 验证码支持
- 自动表单发现
- 页面流程回放
- 通用跳转策略编排

原因：

- 一旦把成功判定、字段提取、流程分支做成通用配置层，很快就会膨胀成第二个执行引擎
- 这与当前“metadata 声明静态信息，provider 实现真实交互”的边界相冲突

## 5. 对现有架构的影响范围

### 5.1 需要修改的层

1. `internal/secprobe/httpauth`
   - 新增 HTTP/API 登录辅助层
2. `internal/secprobe/<protocol>/auth_once.go`
   - 为 `activemq`、`zabbix`、`neo4j` 增加对应 provider
3. `app/secprobe/protocols/*.yaml`
   - 补 `activemq`、`zabbix`、`neo4j` metadata
4. `pkg/secprobe/default_registry.go`
   - 注册新的 atomic credential provider

### 5.2 明确不修改的层

1. `pkg/secprobe/engine`
   - 不新增 HTTP/API 专用分支
2. `pkg/secprobe/strategy`
   - 不让 planner 感知 HTTP/TCP 登录差异
3. `pkg/secprobe/credentials`
   - 不为 HTTP/API 登录单独创建字典模型
4. `metadata schema`
   - 不增加请求体、header、成功判定 DSL

## 6. P2 协议归类

### 6.1 A 类：直接进入当前模型

#### `activemq`

建议：

- 第一版只选一个明确认证入口
- 只做 `credential`
- 不同时覆盖多协议面、多管理面

原因：

- 它更接近 `P1` 中已完成协议
- 可以直接落到现有 `CredentialAuthenticator`
- 对架构影响最小

### 6.2 B 类：适合走 HTTP/API Credential 子层

#### `zabbix`

建议：

- 第一版只做一个固定登录面
- 只做用户名/密码
- 不做控制台/API/版本差异全覆盖

#### `neo4j`

建议：

- 第一版固定一个明确访问面
- 优先按 HTTP/API 登录型 `credential` 看待
- 不同时兼容多管理面和多协议面

原因：

- 这两个协议更像“管理面登录”
- 最适合验证 `httpauth` 子层是否足够

### 6.3 C 类：先评估再实现

#### `rsync`

建议：

- 暂不和 `activemq/zabbix/neo4j` 并批实现
- 先单独做边界评估

需要先回答的问题：

- 第一版只做 `credential` 吗
- 是否要同时做匿名模块访问确认
- 模块发现是前置步骤，还是 `unauthorized` 的一部分

原因：

- 它天然跨 `credential` 与 `unauthorized`
- 很容易把 provider 写胖
- 是 `P2` 中最容易破坏模型边界的协议

## 7. P2 推荐推进顺序

我建议的顺序不是四个协议并排推进，而是：

1. `activemq`
2. `httpauth` 子层
3. `zabbix`
4. `neo4j`
5. `rsync` 边界评估
6. 视评估结果再决定是否实现 `rsync`

也就是说，`P2` 的真实结构应为：

- 一个低风险协议
- 一个复用子层
- 两个依赖该子层的协议
- 一个边界不稳定协议单列评估

## 8. 测试要求

### 8.1 通用要求

每个新增协议至少覆盖：

- 成功命中
- 认证失败
- 连接失败
- 超时
- 上下文取消
- 标准化 `ErrorCode`
- 证据文本

### 8.2 HTTP/API Credential 额外要求

`httpauth` 子层相关测试至少覆盖：

- HTTP 成功登录
- HTTPS 成功登录
- TLS 证书问题映射
- 连接拒绝 / 超时映射
- cookie/session 保持
- 协议自定义成功判定不会泄漏进通用层

## 9. 结论

本轮升级方案的核心结论是：

- 不改 `secprobe` 顶层架构
- 不新增 capability
- 不把 HTTP/API 登录做成 YAML DSL
- 只在 `credential provider` 下增加一个 `httpauth` 复用子层

因此，`P2` 的正确推进方式不是“批量补四个协议”，而是：

- 用 `activemq` 继续验证现有 atomic credential 模型
- 用 `zabbix/neo4j` 验证 `httpauth` 子层
- 用 `rsync` 做边界评估而不是仓促接入

这个方案既兼容当前 `engine-centered` 架构，也为后续 Web/API 登录型协议预留了一条可控扩展路径。
