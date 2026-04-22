# GoMap secprobe v1.3 交付总结

日期：2026-04-22

## 1. 文档目的

本文用于总结 `secprobe v1.3` 的实际交付结果，方便后续做：

- 版本回顾
- 团队同步
- roadmap 衔接
- 测试与验收对照

## 2. 本次交付目标

`v1.3` 的定位不是继续扩协议，也不是引入批量治理，而是在 `v1.2` 已具备统一弱认证探测层的基础上，把单目标探测流程做得更稳、更准、更容易被后续集成使用。

本次目标包括：

- 增强 `secprobe` 内部结果状态表达
- 补齐单目标执行链的阶段推进语义
- 增强跳过、失败、确认不足等结构化分类
- 对高价值协议做定点确认逻辑加固：
  - Redis unauthorized
  - MongoDB unauthorized
  - SSH credential
  - Redis credential
- 保持 CLI 与 JSON 输出兼容
- 不新增复杂参数和平台化概念

## 3. 已完成能力

### 3.1 内部结果模型升级

`internal/secprobe/core.SecurityResult` 已增强为可表达更清晰的内部状态语义，新增：

- `Stage`
  - `matched`
  - `attempted`
  - `confirmed`
  - `enriched`
- `SkipReason`
- `FailureReason`
- `Capabilities`
- `Risk`

这些字段当前只服务于：

- 内部执行逻辑
- 测试断言
- 后续演进预留

不会直接进入当前对外 JSON 结构。

### 3.2 公共兼容边界收口

`pkg/secprobe` 已恢复为显式的公开结果模型与适配层，而不是直接别名内部结构。

本次已经明确：

- 内部状态保持内部准确语义
- 对外输出继续走兼容映射
- `RunWithRegistry` 在边界处把内部结果导出为公开结果
- 公共 `Prober` / `Registry` 仍可在 `pkg/secprobe` 层独立实现，不依赖 `internal`

### 3.3 单目标执行链状态增强

`pkg/secprobe/run.go` 已补齐更清晰的阶段推进与分类逻辑：

- 候选命中后可进入 `matched`
- 发起真实探测后进入 `attempted`
- 确认 finding 后进入 `confirmed`
- enrichment 实际补采成功后进入 `enriched`

同时补齐了结构化跳过与失败分类，包括：

- `SkipReasonProbeDisabled`
- `SkipReasonUnsupportedProtocol`
- `SkipReasonNoCredentials`
- `FailureReasonConnection`
- `FailureReasonAuthentication`
- `FailureReasonTimeout`
- `FailureReasonCanceled`
- `FailureReasonInsufficientConfirmation`

### 3.4 高价值协议确认逻辑加固

本次只对 4 个高价值协议点做了定点增强，没有扩散到更多协议。

已完成：

- Redis unauthorized
  - 先做 `PING`
  - 再做 `INFO server`
  - 仅在返回包含 `redis_version:` 时确认成功
  - 成功后补充 `Enumerable` / `Readable` 能力
- MongoDB unauthorized
  - 通过 `ListDatabaseNames` 做未授权确认
  - 成功后补充 `Enumerable` 能力
- SSH credential
  - 明确 `ProbeKindCredential`
  - 成功进入 `StageConfirmed`
  - 区分认证失败、连接失败、超时、取消
- Redis credential
  - 明确 `ProbeKindCredential`
  - 成功进入 `StageConfirmed`
  - 区分认证失败、连接失败、超时、取消

### 3.5 状态准确性修正

在协议加固过程中，已经额外修正一处关键状态偏差：

- `unauthorized` prober 不再在进入函数时就提前标记 `StageAttempted`
- 只有真正开始网络探测后才进入 `attempted`
- 如果探测前上下文已取消，结果会保留空阶段并标记 `FailureReasonCanceled`

这保证了 `Stage` 与实际执行语义一致。

### 3.6 CLI 与示例兼容说明

本次已补齐文档与测试，明确以下边界：

- CLI / JSON 输出结构保持兼容
- `Stage` / `FailureReason` / `Capabilities` 等内部字段不会出现在公开 JSON 中
- `weak` / `port -weak` 不新增复杂显示控制参数
- `examples/library` 继续通过 `ToJSON` 输出兼容结果结构，便于外部平台集成

## 4. 实际交付文件范围

本次交付重点涉及：

- `internal/secprobe/core/types.go`
- `pkg/secprobe/types.go`
- `pkg/secprobe/registry.go`
- `pkg/secprobe/run.go`
- `pkg/secprobe/run_state_test.go`
- `internal/secprobe/redis/unauthorized_prober.go`
- `internal/secprobe/redis/unauthorized_prober_test.go`
- `internal/secprobe/mongodb/prober.go`
- `internal/secprobe/mongodb/prober_test.go`
- `internal/secprobe/ssh/prober.go`
- `internal/secprobe/ssh/prober_test.go`
- `internal/secprobe/redis/prober.go`
- `internal/secprobe/redis/prober_test.go`
- `cmd/main_test.go`
- `README.md`
- `examples/library/main.go`

## 5. 交付提交记录

本轮核心交付对应 3 个阶段提交：

1. `f2e0768`
   - `feat(secprobe): 完成 v1.3 结果模型与公开适配层`
2. `2238dfc`
   - `feat(secprobe): 增强 v1.3 执行链状态归类`
3. `a71e713`
   - 协议加固与兼容文档已合并在该提交中

说明：

- 原计划中 Task 3 与 Task 4 预期拆成两个提交
- 实际收口时由于一次本地 git 提交并发冲突，最终合并落在同一个提交中
- 代码内容是完整的，但该提交的本地显示信息出现过终端编码污染
- 从交付内容角度看，不影响代码与文档本身

## 6. 验证结果

本次已实际通过：

- `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb ./internal/secprobe/ssh ./pkg/secprobe`
- `go test -count=1 ./cmd ./pkg/secprobe ./internal/secprobe/...`
- `go test ./...`

补充说明：

- 在一次全仓测试中，MySQL 集成用例出现过容器型偶发波动
- 随后对 `./internal/secprobe/mysql -run TestMySQLProberFindsValidCredential -v` 单独复跑通过
- 第二次执行 `go test ./...` 已完整通过

因此，本轮应视为：

- `secprobe v1.3` 改动已通过目标验证
- 当前仓库全量测试在最终验证时已通过

## 7. 当前能力边界

`v1.3` 已完成的是“单目标稳定性与结果表达增强”，不是更大范围的探测治理版本。

当前边界包括：

- 不引入多目标并发治理
- 不引入批量喷洒防护或平台控制逻辑
- 不扩展大量新协议
- 不增加过多 CLI 显示控制参数
- 不把内部状态字段直接稳定为对外契约

## 8. 当前已知限制

### 8.1 协议范围

本次只对以下高价值点做了增强：

- Redis unauthorized
- MongoDB unauthorized
- SSH credential
- Redis credential

其他协议还没有统一补齐同等级别的确认与失败分类语义。

### 8.2 能力表达仍属内部增强

`Capabilities`、`Risk` 等字段已经具备内部承载能力，但当前仍未作为稳定公开输出契约对外暴露。

### 8.3 MongoDB 未授权确认仍保持当前保守策略

当前实现仍把“列库成功但无可见数据库”视为确认不足，而不是直接判定未授权成功。

这属于本轮为保证边界稳定而保留的保守策略点，是否调整可放入后续版本再评估。

## 9. 对后续工作的建议

建议后续继续保持当前工程定位：

- GoMap 作为引擎端 / 即时工具端
- 为上层扫描器平台或运营平台提供能力集成
- 不在当前项目中引入平台概念

在此基础上，后续建议重点衔接 `docs/secprobe-v13-v20-roadmap.md` 中的后续版本工作：

- 继续补强更多协议的确认与失败分类一致性
- 评估 MongoDB 未授权确认边界是否需要调整
- 在 `v2.0` 之后再评估多目标治理与并行策略
- 逐步演进更稳定的对外结果契约

## 10. 结论

`secprobe v1.3` 已经完成了从“统一弱认证探测层可用”到“单目标流程更稳、结果表达更准、公共兼容边界更清晰”的升级。

它的核心价值不在于新增了多少协议，而在于把后续继续做深所需的几个基础点补齐了：

- 内部状态模型
- 执行链阶段语义
- 高价值协议确认逻辑
- 对外兼容边界
- 文档与测试回归保护
