# secprobe enrichment 第一批协议补实现设计

日期：2026-05-12

## 1. 背景

当前 `secprobe` 已经具备 enrichment 执行框架：

- 运行时开关 `EnableEnrichment`
- 协议 metadata 中的 `capabilities.enrichment`
- 统一路由入口 `pkg/secprobe/enrichment_router.go`
- 已有协议样板：`redis`、`mongodb`

但多数已支持认证探测的协议仍未补 enrichment 实现，因此在探测成功后无法给平台页面提供简短、可直接展示的补充证据。

## 2. 本次目标

本次仅在现有 enrichment 接口下补实现，不调整框架与结果结构。

范围限定为第一批 3 个协议：

- `postgresql`
- `mysql`
- `elasticsearch`

目标是让这 3 个协议在认证成功后，能够补充一条适合页面直接展示的明文证据。

## 3. 非目标

本次明确不做：

- 重构 enrichment 框架
- 修改 `SecurityResult.Enrichment` 的类型定义
- 设计新的公共 enrichment 抽象层
- 扩展到 `neo4j`、`ldap`、`smtp`
- 返回复杂结构化摘要字段
- 返回过长原始响应体
- 执行任何有副作用的查询或写操作

## 4. 设计原则

### 4.1 保持现有接口不变

`enrichment` 保持对象类型，不改为字符串。

统一使用：

```json
{
  "payload": "<request>\n\n<response>"
}
```

失败时沿用现有错误承载方式：

```json
{
  "error": "..."
}
```

### 4.2 只做最小只读验证

enrichment 的职责不是补全资产画像，而是给平台提供一条额外证据，证明认证成功后能够继续执行一条最小只读请求。

因此每个协议只做一次最小只读操作，避免：

- 过多查询
- 大结果集
- 复杂结构化返回
- 潜在副作用

### 4.3 与主探测解耦

enrichment 仅在以下条件满足时执行：

- `result.Success == true`
- `opts.EnableEnrichment == true`
- 协议 metadata 中 `capabilities.enrichment == true`

enrichment 失败不改变主探测成功状态，只写入 `enrichment.error`。

## 5. 协议级设计

### 5.1 PostgreSQL

metadata：

- 修改 `app/secprobe/protocols/postgresql.yaml`
- 将 `capabilities.enrichment` 从 `false` 改为 `true`

实现：

- 新增 `internal/secprobe/postgresql/enrichment.go`
- 认证成功后使用同一组凭证建立只读连接
- 执行：

```sql
SELECT version();
```

输出：

```json
{
  "payload": "SELECT version();\n\nPostgreSQL 16.2"
}
```

说明：

- 只返回版本字符串
- 不读取数据库列表
- 不读取 schema 或业务表

### 5.2 MySQL

metadata：

- 修改 `app/secprobe/protocols/mysql.yaml`
- 将 `capabilities.enrichment` 从 `false` 改为 `true`

实现：

- 新增 `internal/secprobe/mysql/enrichment.go`
- 认证成功后使用同一组凭证建立只读连接
- 执行：

```sql
SELECT @@version;
```

输出：

```json
{
  "payload": "SELECT @@version;\n\n8.0.36"
}
```

说明：

- 该证据足以证明认证后可继续执行 SQL
- 不额外执行 `SHOW DATABASES`
- 不读取更多数据库信息

### 5.3 Elasticsearch

metadata：

- 修改 `app/secprobe/protocols/elasticsearch.yaml`
- 将 `capabilities.enrichment` 从 `false` 改为 `true`

实现：

- 新增 `internal/secprobe/elasticsearch/enrichment.go`
- 认证成功后使用同一组凭证发起只读 HTTP 请求
- 执行：

```http
GET /_security/_authenticate
```

输出：

```json
{
  "payload": "GET /_security/_authenticate\n\n200 OK\nusername: elastic"
}
```

说明：

- 只提取少量稳定信息
- 不返回整段 JSON 响应
- 不额外请求更多 API

## 6. Router 设计

修改 `pkg/secprobe/enrichment_router.go`，在现有 `redis`、`mongodb` 路由基础上增加：

- `postgresql`
- `mysql`
- `elasticsearch`

路由仍保持按服务名直接分派，不引入新的注册机制。

## 7. 错误处理

统一错误处理约定：

- enrichment 内部失败时：
  - 返回原始 `result`
  - 写入 `result.Enrichment = map[string]any{"error": err.Error()}`
- 不覆盖：
  - `success`
  - `probe_kind`
  - `finding_type`
  - `evidence`

## 8. 输出格式约束

`payload` 使用统一样式：

- 第一段：请求摘要
- 空一行
- 第二段：响应摘要

示例：

```text
SELECT version();

PostgreSQL 16.2
```

```text
GET /_security/_authenticate

200 OK
username: elastic
```

约束：

- 内容保持短小
- 不返回大对象
- 不输出敏感凭证
- 如需截断，优先截断响应段

## 9. 测试设计

### 9.1 Router 测试

扩展 `pkg/secprobe/enrichment_test.go`：

- PostgreSQL 路由到 PostgreSQL enricher
- MySQL 路由到 MySQL enricher
- Elasticsearch 路由到 Elasticsearch enricher

### 9.2 协议单测

分别新增协议级 enrichment 测试，覆盖：

- 成功返回 `enrichment.payload`
- 失败返回 `enrichment.error`
- 不改变原始成功态

### 9.3 运行态测试

复用现有 `pkg/secprobe/enrichment_test.go` 风格，确保：

- `EnableEnrichment=false` 时不执行 enrichment
- 主探测失败时不执行 enrichment
- enrichment 错误不影响主 finding

## 10. 文件清单

### 修改

- `app/secprobe/protocols/postgresql.yaml`
- `app/secprobe/protocols/mysql.yaml`
- `app/secprobe/protocols/elasticsearch.yaml`
- `pkg/secprobe/enrichment_router.go`
- `pkg/secprobe/enrichment_test.go`

### 新增

- `internal/secprobe/postgresql/enrichment.go`
- `internal/secprobe/mysql/enrichment.go`
- `internal/secprobe/elasticsearch/enrichment.go`
- 对应协议 enrichment 测试文件

## 11. 风险与控制

风险：

- enrichment 查询超时导致页面无补充信息
- 某些服务端响应内容过长
- HTTP/SQL 响应格式差异导致字符串证据不稳定

控制：

- 全部复用 `opts.Timeout`
- 仅执行单条最小只读请求
- 仅提取短摘要，不保留完整响应体
- enrichment 错误仅作为附加错误，不影响主结果

## 12. 结论

本次采用最小增量方案：

- 不改 enrichment 框架
- 只补第一批 3 个协议
- 输出统一为 `enrichment.payload`
- 目标是为平台页面提供一条清晰、短小、可直接展示的补充证据

该方案与当前 `redis`、`mongodb` enrichment 的执行语义保持一致，同时把实现范围控制在最适合一次迭代落地的边界内。
