# GoMap secprobe center SDK 集成方案 v1 设计

日期：2026-04-23

## 1. 背景

截至 `secprobe v1.4`，GoMap 已完成两件关键工作：

- `v1.3` 已把单目标认证探测链路的状态表达、失败分类和高价值协议确认逻辑做稳
- `v1.4` 已把 `secprobe` 的协议扩展模式、协议目录元数据、默认装配边界和扩展开发指南整理清楚

这意味着当前 GoMap 在 `secprobe` 方向上，已经基本具备“继续作为引擎端被外部系统稳定复用”的前提。

同时，当前外部系统的真实集成场景也已经比较明确：

- 扫描器平台 `center` 已经以 SDK 形式集成 GoMap 的资产探测能力
- 对应 worker 侧已有固定集成模式，主要位于 `zvas/internal/worker`
- worker 当前不持久化业务数据
- worker 更适合消费 center 下发的标准任务，再执行本地引擎并回传结果

在这个前提下，下一步更合适的工作，不是把 GoMap 改造成平台服务，也不是把 `secprobe` 直接暴露成一组松散底层函数，而是为 center 增加一条稳定的 `secprobe` SDK 集成入口，使其可以按照与资产探测类似的方式，被 worker 本地调用。

本设计聚焦 `v1`：

- center 显式下发已识别服务列表
- worker 本地调用 GoMap `secprobe`
- worker 不持久化，不回查资产结果
- 先完成账号口令探测主链路
- 为后续 `unauthorized` 类探测预留字段位，但不在 `v1` 强推完整能力

## 2. 目标与非目标

### 2.1 目标

- 为 GoMap `secprobe` 设计一条面向 center / worker 的稳定 SDK 集成入口
- 保持 GoMap 继续作为引擎端 / 工具端，而不是平台端
- 让 `zvas` worker 可以沿用当前：
  - `listener -> process -> mapper`
  的模块组织方式集成 `secprobe`
- 明确 center 下发任务的 `payload` 契约
- 明确 worker 对外回传的稳定结果契约
- 将 `center` 与 `pkg/secprobe` 当前仍会继续演进的内部实现细节解耦

### 2.2 非目标

- 本次不把 GoMap 改造成常驻 HTTP / gRPC 服务
- 本次不引入任务编排、分布式状态存储、平台治理等控制面能力
- 本次不要求 worker 回查资产扫描结果或持久化中间结果
- 本次不把 `Stage`、`FailureReason`、`Capabilities`、`Risk` 稳定为平台对接契约
- 本次不同时解决多目标并发治理和批量喷洒策略
- 本次不新增大量 CLI 控制项
- 本次不要求 `v1` 立即覆盖完整未授权访问探测能力

## 3. 当前上下文与约束

### 3.1 GoMap 当前定位

当前 GoMap 的合理定位已经比较清晰：

- 作为引擎端能力组件
- 对外提供资产探测、首页识别、目录识别、协议安全探测等 SDK 能力
- 接受上层平台或 center 的任务编排
- 返回结果，不承担平台侧的调度和治理职责

### 3.2 `zvas` 当前集成模式

参考 `zvas/internal/worker` 现有实现，GoMap 资产能力的集成已经形成较稳定模式：

- `listener` 负责标准化任务单元
- `process` 负责从 `ScanUnit.Payload` 构造本地请求
- 本地调用 GoMap SDK
- 再将结果映射为 `map[string]any`

对应参考代码包括：

- `zvas/internal/worker/engines/assets/process/gomap_adapter.go`
- `zvas/internal/worker/engines/assets/process/gomap_port.go`
- `zvas/internal/worker/engines/module/spec.go`

同时，现有外部弱扫引擎的接入方式也说明了攻击域任务的一般组织方式：

- `listener` 负责 topic / stage / task type 规范化
- `process` 负责任务执行与结果摘要
- `mapper` 负责把引擎结果转成平台结果

对应参考代码包括：

- `zvas/internal/worker/engines/attack/weakscan/listener/weak_scan_task.go`
- `zvas/internal/worker/engines/attack/weakscan/process/weak_scan.go`
- `zvas/internal/worker/engines/attack/weakscan/mapper/summary.go`

### 3.3 `v1` 关键约束

`v1` 已明确采用以下约束：

- center 优先采用 `A` 模式：
  - 显式下发已识别服务列表
- worker 不持久化数据
- worker 不负责回查资产扫描结果
- 集成方式继续采用 SDK，本地调用 GoMap，而不是远端服务调用

## 4. 方案对比

### 方案 A：center 直接调用 `pkg/secprobe` 现有入口

做法：

- center 或 worker 直接调用：
  - `secprobe.Run`
  - `secprobe.BuildCandidates`
  - `CredentialProbeOptions`

优点：

- 接入最快
- 短期改动最少

缺点：

- center 会直接依赖当前 `pkg/secprobe` 的内部输入组织方式
- 后续一旦 `BuildCandidates`、options、结果细节调整，外部会被迫跟着改
- 不利于形成面向平台的稳定契约

### 方案 B：在 GoMap 中新增一层稳定集成 facade，再由 worker 调用

做法：

- GoMap 内新增面向 center / worker 的集成入口
- center 按稳定 request / result 契约与该入口交互
- facade 内部再调用现有 `pkg/secprobe`

优点：

- 保持 GoMap 的引擎定位
- 能隔离 `pkg/secprobe` 现有内部演进细节
- 便于后续协议扩展时保持 center 无感
- 更符合当前 `zvas` 的 process / mapper 封装风格

缺点：

- 需要新增一层 request/result 映射代码
- 需要补一套新的 facade 测试

### 方案 C：直接把 GoMap 演化成 secprobe 常驻服务

做法：

- 将 `secprobe` 暴露为本地 HTTP / gRPC 服务
- worker 通过 RPC 调用

优点：

- 后续跨语言调用扩展性更强

缺点：

- 过早引入服务生命周期、鉴权、错误码、启动依赖等复杂度
- 容易把 GoMap 拉向平台底座方向
- 与当前已存在的 SDK 集成路径不一致

### 结论

选择方案 B。

即：

- GoMap 新增一层稳定的 `secprobe` 集成 facade
- worker 继续采用本地 SDK 调用
- center 面向稳定任务契约构造请求
- worker 面向稳定结果契约回传结果

## 5. 总体设计

### 5.1 总体架构

`v1` 的推荐调用链如下：

1. center 基于已完成的资产识别结果，构造弱口令任务
2. center 将任务下发到 worker
3. worker listener 对任务做标准化
4. worker process 从 `payload` 构造 GoMap `secprobe` facade 请求
5. worker 本地调用 GoMap facade
6. facade 内部转调现有 `pkg/secprobe`
7. worker mapper 将结果映射为平台侧稳定返回结构

整体原则：

- center 负责准备输入
- worker 负责执行与映射
- GoMap 负责探测引擎本身

### 5.2 GoMap 侧新增层次

建议在 GoMap 中新增一层面向集成的稳定入口，统一落在：

- `pkg/secprobe/integration`

该层职责应明确为：

- 定义稳定的 request / result 模型
- 校验 `services[]`
- 转换为内部 `SecurityCandidate` 和 `CredentialProbeOptions`
- 调用现有 `secprobe.Run`
- 将结果收敛为稳定输出

该层不负责：

- 协议实现
- registry 扩展逻辑
- 平台任务编排
- 外部持久化

### 5.3 `zvas` 侧模块落位

建议在 `zvas/internal/worker/engines/attack` 下新增一套独立的本地 secprobe engine，而不是复用现有外部弱扫引擎 process。

推荐目录结构：

- `zvas/internal/worker/engines/attack/secprobe/process/modules.go`
- `zvas/internal/worker/engines/attack/secprobe/process/gomap_secprobe.go`
- `zvas/internal/worker/engines/attack/secprobe/process/request.go`
- `zvas/internal/worker/engines/attack/secprobe/mapper/result.go`
- `zvas/internal/worker/engines/attack/secprobe/listener/secprobe_task.go`

原因：

- `secprobe` 是本地同步 SDK 调用
- 不是远端 HTTP 异步扫描任务
- 任务对象也不是以 URL 为核心，而是以：
  - host / ip
  - service list
  - probe policy
  为核心

### 5.4 topic / task type 边界

不建议复用现有外部 `weakscan` 的 topic / task type。

建议为 `secprobe` 单独定义：

- 独立 `task_type`
- 独立 `stage`
- 独立 `topic`

原因：

- 站点弱点扫描与认证探测不是同一类任务
- 请求模型不同
- 返回结果语义不同
- 后续协议扩展和未授权扩展也需要保持独立演进

## 6. 请求模型设计

### 6.1 总体原则

`v1` 请求模型采用“两层输入”的思路：

1. 主输入：
   - 稳定的 `ScanRequest`
2. 适配输入：
   - 将 center 的任务 `payload` 转为 `ScanRequest`

不建议让 center 或 worker 直接操作：

- `SecurityCandidate`
- `BuildCandidates`
- `CredentialProbeOptions`

### 6.2 `v1` 主输入建议

建议由 center 下发如下核心请求结构：

```json
{
  "target": "192.168.1.10",
  "services": [
    {
      "host": "192.168.1.10",
      "port": 22,
      "service": "ssh"
    },
    {
      "host": "192.168.1.10",
      "port": 6379,
      "service": "redis"
    }
  ],
  "probe_policy": {
    "kinds": ["credential", "unauthorized"],
    "enable_enrichment": false,
    "stop_on_success": true
  },
  "dict_policy": {
    "use_builtin": true
  },
  "timeout_ms": 3000
}
```

### 6.3 `services[]` 设计

`services[]` 是 `v1` 的主输入。

每个 service 最小字段建议为：

- `host`
- `port`
- `service`

可选字段建议预留：

- `tls`
- `source`
- `metadata`

字段含义：

- `host`
  - 执行认证探测的主机地址
- `port`
  - 目标服务端口
- `service`
  - center 已识别出的标准服务名
- `tls`
  - 用于表达 `redis/tls`、`postgresql/ssl` 一类变体，避免协议变体全部压在字符串别名中
- `source`
  - 表示该 service 来源于端口识别、画像推送或人工补充
- `metadata`
  - 仅做透传补充，不作为强契约

### 6.4 `probe_policy` 设计

`v1` 只建议保留少量高价值控制项：

- `kinds`
  - 允许值：
    - `credential`
    - `unauthorized`
- `enable_enrichment`
- `stop_on_success`
- `protocol_allowlist`
- `per_target_timeout_ms`

其中：

- `credential`
  是 `v1` 主能力
- `unauthorized`
  在请求模型中先保留字段位；`v1` 实现阶段可选择忽略该值，或在显式请求时返回“当前版本未启用该能力”的稳定错误
- `enable_enrichment`
  建议 `v1` 默认关闭

### 6.5 `dict_policy` 设计

`v1` 字典策略建议只支持两类能力：

- `use_builtin`
- 显式下发 `credentials[]`

也可选支持：

- `dict_dir`

但不建议在 `v1` 过度扩展复杂字典策略。

原因：

- 用户理解成本高
- 容易把 center 和 worker 都拖入大量参数治理
- 与当前“先把主链路跑稳”的目标不一致

### 6.6 为什么选择 center 显式下发 `services[]`

`v1` 采用该模式的原因包括：

- worker 不持久化数据
- worker 不应回查资产探测结果
- center 已具备资产识别能力和结果上下文
- 显式输入更便于任务重放、排障和审计
- 能减少 worker 内部的二次候选重建逻辑

## 7. 结果模型设计

### 7.1 总体原则

worker 的结果分为两层：

1. 任务摘要层
2. finding 明细层

任务摘要层用于平台快速判断：

- 是否执行成功
- 尝试了多少服务
- 命中了多少条 finding

finding 明细层用于：

- 入库
- 展示
- 告警
- 人工研判

### 7.2 建议输出结构

建议收敛为如下风格：

```json
{
  "engine": "gomap-secprobe",
  "target": "192.168.1.10",
  "service_count": 2,
  "attempted_count": 2,
  "matched_count": 1,
  "findings": [
    {
      "host": "192.168.1.10",
      "port": 22,
      "service": "ssh",
      "probe_kind": "credential",
      "finding_type": "credential_valid",
      "username": "root",
      "password": "root",
      "evidence": "ssh auth succeeded",
      "enrichment": {}
    }
  ]
}
```

### 7.3 建议稳定暴露的摘要字段

建议稳定暴露：

- `engine`
- `target`
- `service_count`
- `attempted_count`
- `matched_count`
- `findings`
- `error`
- `partial_result`

这些字段可作为 worker 与平台之间的稳定结果摘要层。

### 7.4 建议稳定暴露的 finding 字段

建议 `findings[]` 中稳定保留：

- `host`
- `port`
- `service`
- `probe_kind`
- `finding_type`
- `username`
- `password`
- `evidence`
- `enrichment`

说明：

- `probe_kind`
  用于表达：
  - `credential`
  - `unauthorized`
- `finding_type`
  用于表达更稳定的 finding 语义，例如：
  - `credential_valid`
  - `unauthorized_access`
- `username` / `password`
  在命中时直接保留，便于平台闭环处置
- `enrichment`
  只作为附加信息，不建议在 `v1` 作为强依赖字段

### 7.5 不建议直接外露的内部字段

`v1` 不建议把以下字段直接稳定为平台契约：

- `Stage`
- `FailureReason`
- `Capabilities`
- `Risk`

原因：

- 它们当前仍偏向内部执行语义与后续演进预留
- 若 center 直接依赖，会把 GoMap 内部状态机硬绑定为平台契约
- 后续继续扩协议或收敛状态语义时，回滚成本会明显增加

更稳的做法是：

- GoMap 内部继续保留这些字段
- worker 内部可用它们辅助日志、调试和本地分类
- 对平台只输出收敛后的稳定摘要和 finding 结果

## 8. worker 侧执行流程设计

### 8.1 listener 职责

listener 负责：

- 校验任务基本身份信息
- 规范化：
  - `topic`
  - `stage`
  - `task_type`
  - `task_subtype`
- 保证 `payload` 至少具备：
  - `target`
  - `services[]`

listener 不负责：

- 候选重建
- secprobe 执行
- 结果映射

### 8.2 process 职责

process 负责：

- 从 `ScanUnit.Payload` 解析请求
- 调用 GoMap `secprobe` facade
- 处理执行时错误
- 生成任务级摘要结果

process 的组织方式更应对齐现有本地 SDK 型 process，例如：

- `gomap-port`

而不是外部 HTTP 型 process。

### 8.3 mapper 职责

mapper 负责：

- 将 GoMap facade 返回的稳定结果
  转成平台侧 `map[string]any`
- 对 finding 进行必要字段收口
- 保证平台侧结果结构在 `v1` 中稳定

mapper 不应承担：

- 协议语义推导
- 字典策略判断
- secprobe 内部状态机解释

## 9. 错误处理与边界

### 9.1 输入错误

对于以下情况，应尽早返回任务失败：

- `services[]` 为空
- `host` 为空
- `port` 非法
- `service` 为空
- `payload` 中 `kinds` 不合法

### 9.2 执行错误

执行中出现以下情况时，应由 facade 或 worker 做摘要化处理：

- 整体调用失败
- 单 service 探测失败
- 字典装载失败
- 上下文超时 / 取消

处理原则：

- 允许任务级错误与 finding 结果并存
- 如有部分结果可返回，则标记 `partial_result=true`
- 不要求逐条透传所有内部失败明细

### 9.3 未命中结果

未命中不应视为任务错误。

建议语义：

- `attempted_count > 0`
- `matched_count = 0`
- `findings = []`
- `error` 为空

## 10. 测试设计

### 10.1 GoMap 侧

GoMap facade 建议覆盖：

- 请求校验测试
- `services[]` 到内部 candidate 的映射测试
- `probe_policy` 到 `CredentialProbeOptions` 的映射测试
- 结果收敛测试
- 对 `Stage` / `FailureReason` 等内部字段不外泄的边界测试

### 10.2 `zvas` worker 侧

worker 建议覆盖：

- listener 规范化测试
- payload 解析测试
- process 调用 facade 的请求构造测试
- mapper 摘要结果映射测试
- 空结果 / 部分结果 / 执行失败测试

### 10.3 集成测试

建议至少补一类端到端集成测试：

- center 构造 `services[]`
- worker 执行本地 secprobe facade
- 返回稳定结果摘要

重点验证：

- 不依赖 worker 持久化
- 不依赖资产结果回查
- 与现有 worker 模块风格保持一致

## 11. `v1` 范围收口

`v1` 建议明确只做以下范围：

- center 显式下发 `services[]`
- worker 本地同步调用 GoMap secprobe facade
- 以 `credential` 探测为主
- 为 `unauthorized` 预留字段位
- 支持内置字典或显式凭证
- 返回稳定摘要与 finding 结构

`v1` 不做：

- worker 本地持久化
- worker 回查资产扫描结果
- 平台化任务治理
- 多目标并发治理策略
- 大量细碎控制参数
- 把内部状态字段直接暴露为平台契约

## 12. 结论

在 `secprobe v1.4` 已经完成扩展模式整改的前提下，当前最合适的下一步，不是继续把 GoMap 往平台方向推，而是为 center / worker 增加一条稳定的 SDK 集成路径。

`v1` 推荐采用：

- center 显式下发已识别服务列表
- worker 沿用现有 `listener -> process -> mapper` 模式
- GoMap 通过新增 facade 提供稳定的 `secprobe` 集成入口

这样可以同时满足几件事：

- 延续当前 GoMap 作为引擎端的定位
- 与 `zvas` 已有的 GoMap 资产集成模式保持一致
- 降低 center 对 `pkg/secprobe` 内部细节的依赖
- 为后续继续扩协议和补 `unauthorized` 能力保留稳定演进空间
