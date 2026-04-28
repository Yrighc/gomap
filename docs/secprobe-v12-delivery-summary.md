# GoMap secprobe v1.2 交付总结

日期：2026-04-22

## 1. 文档目的

本文用于总结 `secprobe v1.2` 的实际交付结果，方便后续做：

- 版本回顾
- 团队同步
- 后续 roadmap 拆分
- 测试与验收对照

## 2. 本次交付目标

`v1.2` 的核心目标不是继续堆“账号口令尝试”，而是把 GoMap 的弱认证能力升级为统一弱认证探测层。

本次目标包括：

- 在 `pkg/secprobe` 内同时支持：
  - `credential`
  - `unauthorized`
- 首批接入：
  - Redis 未授权访问探测
  - MongoDB 未授权访问探测
- 为成功 finding 增加可选 enrichment
- 保持统一 CLI 入口：
  - `gomap weak`
  - `gomap port -weak`
- 保持默认行为保守：
  - 默认不开启未授权探测
  - 默认不开启 enrichment

## 3. 已完成能力

### 3.1 探测模型升级

已经完成从单一 `credential` 探测到双类型探测模型升级：

- 新增 `ProbeKind`
  - `credential`
  - `unauthorized`
- 新增 `FindingTypeUnauthorizedAccess`
- `SecurityResult` 已能统一表达：
  - 凭证命中
  - 未授权访问
  - enrichment 结果

### 3.2 secprobe 执行链路升级

`pkg/secprobe` 现在具备：

- kind-aware registry lookup
- 按候选和配置选择 probe kind
- 统一默认 finding 补齐
- credential 失败后可回退到 unauthorized
- 成功 finding 后的可选 enrichment pass

### 3.3 候选归一化增强

已补齐弱认证相关服务别名：

- `postgres` -> `postgresql`
- `pgsql` -> `postgresql`
- `mongo` -> `mongodb`
- `redis/tls` -> `redis`
- `redis/ssl` -> `redis`
- `27017` 端口回退识别为 `mongodb`

### 3.4 未授权访问能力

已接入：

- Redis unauthorized
  - 通过 `INFO server` 验证匿名访问
- MongoDB unauthorized
  - 通过 `ListDatabaseNames` 验证匿名访问

### 3.5 Enrichment 能力

已支持：

- Redis enrichment
  - 返回裁剪后的 `INFO` 摘要
- MongoDB enrichment
  - 返回数据库列表

并且已经明确：

- enrichment 只对成功 finding 生效
- enrichment 失败不会改变主 finding 成败
- enrichment 错误写入 `result.Enrichment.error`

### 3.6 CLI 能力

`gomap weak` 已支持：

- `-enable-unauth`
- `-enable-enrichment`

`gomap port -weak` 已支持：

- `-weak-enable-unauth`
- `-weak-enable-enrichment`

默认行为保持兼容：

- 默认只跑 credential
- 默认不跑 enrichment

### 3.7 文档与示例

已同步更新：

- `README.md`
- `examples/library/main.go`

## 4. 实际交付文件范围

本次交付重点涉及：

- `pkg/secprobe/run.go`
- `pkg/secprobe/types.go`
- `pkg/secprobe/candidates.go`
- `pkg/secprobe/enrichment_test.go`
- `internal/secprobe/core/types.go`
- `internal/secprobe/core/registry.go`
- `internal/secprobe/redis/unauthorized_prober.go`
- `internal/secprobe/redis/enrichment.go`
- `internal/secprobe/mongodb/prober.go`
- `internal/secprobe/mongodb/enrichment.go`
- `internal/secprobe/testutil/testcontainers.go`
- `cmd/main.go`
- `cmd/main_test.go`
- `README.md`
- `examples/library/main.go`

## 5. 交付提交记录

本轮拆成了 6 个独立提交：

1. `3bb8a22`
   - `feat(secprobe): add probe kind routing skeleton`
2. `7187816`
   - `feat(secprobe): expand candidate service normalization`
3. `4471d95`
   - `feat(secprobe): add redis and mongodb unauthorized probers`
4. `10d0998`
   - `feat(secprobe): add optional finding enrichment`
5. `3b25b11`
   - `feat(cli): add unauth and enrichment weak flags`
6. `34a389f`
   - `docs(secprobe): document v1.2 weak auth flags`

这种拆分方式的价值是：

- 每一步边界清晰
- 便于 review
- 便于后续回滚和定位问题

## 6. 验证结果

本次已实际通过：

- `go test -count=1 ./pkg/secprobe ./cmd ./internal/secprobe/...`
- `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb -v`
- `go test ./...`
- `go test ./examples/library -run '^$'`

说明：

- `secprobe` 相关单测和容器集成测试已经覆盖
- CLI 路径已覆盖默认行为与正向开关转发
- 全仓库测试本轮也已通过

## 7. 当前能力边界

`v1.2` 已完成的是“统一弱认证探测层”基础升级，但还不是最终形态。

当前边界包括：

- 未授权协议当前只支持：
  - Redis
  - MongoDB
- enrichment 当前只支持：
  - Redis
  - MongoDB
- 仍未引入更复杂的执行治理：
  - 目标级熔断
  - 喷洒保护
  - 速率治理
  - 更细粒度 stop policy
- 仍未引入更稳定的对外输出契约与外部集成配套能力

## 8. 当前已知限制

### 8.1 结果层面

- `SecurityResult` 虽已支持 enrichment，但证据结构仍然偏轻量
- 还没有统一的风险等级、可读/可写能力表达

### 8.2 协议层面

- 未授权能力还没有扩展到：
  - Elasticsearch
  - Memcached
  - Zookeeper
  - Kafka

### 8.3 治理层面

- 还没有批量任务保护策略
- 还没有更细的速率控制与多目标保护
- 还没有独立的审计输出层

## 9. 对后续工作的建议

建议后续不要回退成“大一统扫描器”，继续保持：

- `assetprobe` 负责资产发现
- `secprobe` 负责协议安全探测
- `port -weak` 负责显式串联

下一步建议重点转向：

- 执行治理
- 结果表达增强
- 更多未授权协议接入
- 更稳定的输出契约与外部集成复用能力

## 10. 结论

`secprobe v1.2` 已经完成了从“弱口令尝试功能”到“统一弱认证探测层”的关键升级。

它的意义不只是多接了两个协议，而是把后续继续演进所需要的基础骨架搭起来了：

- 探测类型分流
- 统一结果模型
- CLI 控制面
- enrichment 后处理能力

这意味着后续的 `v1.3` 和 `v2.0` 可以在更清晰的边界上继续推进，而不需要回头重做底层模型。
