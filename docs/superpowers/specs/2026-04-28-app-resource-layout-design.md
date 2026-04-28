# GoMap app 资源目录整改设计

日期：2026-04-28

## 1. 背景

当前仓库的 `app/` 目录同时承载了多类静态资源：

- `assetprobe` 服务识别探针
- `assetprobe` 服务映射
- `assetprobe` 目录爆破字典
- `secprobe` 协议弱口令字典
- 运行配置 YAML

这些文件目前全部平铺在 `app/` 根目录下，并且命名风格不统一：

- 目录爆破字典采用 `dict-simple.txt`、`dict-normal.txt`、`dict-diff.txt`
- 弱口令字典采用 `secprobe-ssh.txt`、`secprobe-redis.txt` 这一类前缀风格
- 服务探针和服务映射则继续沿用 `gomap-service-probes`、`gomap-services`

这种结构在功能较少时还能接受，但随着 `secprobe` 增长，问题已经比较明显：

- 不同扫描引擎的资源混在一起，阅读和维护成本高
- 新增协议时，很难一眼看出字典该放在哪里
- 文档中的资源路径和命名约定不够统一
- 自定义 `dict-dir` 当前同时兼容 `<protocol>.txt` 和 `secprobe-<protocol>.txt`，外部约定不清晰

本次整改目标是把 `app/` 目录重组为按引擎分层的结构，并把命名统一到更清晰、可扩展的形式。

## 2. 目标与非目标

### 2.1 目标

- 按扫描引擎拆分 `app/` 资源目录
- 统一内置资源命名规则
- 统一 `secprobe` 外部自定义字典目录命名规则
- 保持 `pkg/assetprobe` 与 `pkg/secprobe` 的对外 API 不变
- 同步更新 README、升级说明和扩展文档，避免后续继续沿用旧路径

### 2.2 非目标

- 不重写 `assetprobe` / `secprobe` 的资源加载架构
- 不新增资源注册中心、配置中心或插件化能力
- 不保留旧命名兼容层
- 不调整 YAML 配置文件本身的语义
- 不顺带做与资源结构无关的重构

## 3. 方案对比

### 方案 A：只分目录，不改命名

做法：

- 把字典和探针搬到子目录
- 保留 `secprobe-ssh.txt`、`dict-simple.txt` 这类旧命名

优点：

- 代码改动最小
- 历史文档修改量较少

缺点：

- 目录虽然清晰了，但命名仍然杂糅
- `secprobe` 的命名风格仍与 `assetprobe` 不一致
- 新增协议时仍然容易延续前缀式命名

### 方案 B：目录分层 + 命名统一

做法：

- 按扫描引擎拆目录
- `assetprobe` 目录爆破字典统一为 `simple.txt|normal.txt|diff.txt`
- `secprobe` 字典统一为 `<protocol>.txt`
- 外部自定义 `dict-dir` 也只接受 `<protocol>.txt`

优点：

- 目录和命名同时清晰
- 后续新增协议、字典和文档都有一致约定
- 代码变更集中在资源入口层，行为边界可控

缺点：

- 需要同步更新 embed 路径、字典查找逻辑和文档
- 对外自定义字典目录会发生不兼容变化

### 方案 C：彻底抽象资源注册层

做法：

- 把当前 `app/assets.go` 上提为资源注册或元数据管理层
- 所有资源按类型动态注册和解析

优点：

- 长期扩展性最好

缺点：

- 超出本次“整理目录和命名”的需求范围
- 会引入额外复杂度，改动面不成比例

### 结论

选择方案 B。

## 4. 目标结构

整改后的目标结构如下：

```text
app/
├── assetprobe/
│   ├── probes/
│   │   └── gomap-service-probes
│   ├── services/
│   │   └── gomap-services
│   └── dicts/
│       ├── simple.txt
│       ├── normal.txt
│       └── diff.txt
├── secprobe/
│   └── dicts/
│       ├── ftp.txt
│       ├── mysql.txt
│       ├── postgresql.txt
│       ├── redis.txt
│       ├── ssh.txt
│       └── telnet.txt
├── application.yml
├── gomap-kafka-dev.yml
└── gomap-kafka-prod.yml
```

结构约束：

- `app/assetprobe/` 只放 `assetprobe` 资源
- `app/secprobe/` 只放 `secprobe` 资源
- `dicts/` 目录中的文件名必须体现单一维度，不再混入引擎前缀
- YAML 配置文件继续留在 `app/` 根目录，不与扫描资源混放在同一命名体系中

## 5. 命名规范

### 5.1 内置 `assetprobe` 资源

- 服务探针：`app/assetprobe/probes/gomap-service-probes`
- 服务映射：`app/assetprobe/services/gomap-services`
- 目录爆破字典：
  - `app/assetprobe/dicts/simple.txt`
  - `app/assetprobe/dicts/normal.txt`
  - `app/assetprobe/dicts/diff.txt`

说明：

- `simple|normal|diff` 已经是逻辑层级名，不需要再保留 `dict-` 前缀

### 5.2 内置 `secprobe` 资源

- 统一为 `app/secprobe/dicts/<protocol>.txt`

示例：

- `app/secprobe/dicts/ssh.txt`
- `app/secprobe/dicts/redis.txt`
- `app/secprobe/dicts/postgresql.txt`

说明：

- 不再使用 `secprobe-<protocol>.txt`
- 文件所在目录已经表达了资源归属，不需要文件名前缀重复表达

### 5.3 外部自定义 `dict-dir` 约定

本次整改后，外部自定义弱口令字典目录只支持一种命名规则：

- `<protocol>.txt`

示例：

- `/data/secprobe-dicts/ssh.txt`
- `/data/secprobe-dicts/mysql.txt`

不再兼容：

- `secprobe-ssh.txt`
- `secprobe-mysql.txt`

这是一次明确的直接切换，不提供双轨兼容期。

## 6. 代码调整范围

### 6.1 `app/assets.go`

`app/assets.go` 继续作为仓库唯一的内置资源入口，但读取路径改为新结构。

需要调整：

- `go:embed` 路径列表
- `ServiceProbes()` 读取路径
- `Services()` 读取路径
- `Dict(level)` 读取路径
- `SecprobeDict(protocol)` 读取路径

边界要求：

- 对外函数名不变
- 调用方不感知 `app/` 内部目录变化

### 6.2 `pkg/assetprobe`

`pkg/assetprobe` 继续通过 `appassets.ServiceProbes()`、`appassets.Services()`、`appassets.Dict()` 获取资源。

预期调整：

- 无需改动调用语义
- 仅依赖 `app/assets.go` 的新路径实现

### 6.3 `pkg/secprobe`

`pkg/secprobe/assets.go` 继续通过 `appassets.SecprobeDict()` 获取内置字典。

`pkg/secprobe/dictionaries.go` 需要从双轨候选：

- `<protocol>.txt`
- `secprobe-<protocol>.txt`

收敛为单轨候选：

- `<protocol>.txt`

边界要求：

- 只改自定义目录命名规则
- 不在运行时保留旧规则兜底

## 7. 文档调整范围

需要同步更新以下内容：

- `README.md`
- `UPGRADE.md`
- `docs/secprobe-protocol-extension-guide.md`

更新重点：

- `app/` 目录树
- 资源路径示例
- `secprobe` 内置字典命名规范
- 自定义 `dict-dir` 的新命名规范
- 新增协议时的资源落点说明

文档要求：

- 不再继续主推旧路径或旧命名
- 明确写出这是一次不保留兼容层的切换

## 8. 测试策略

本次整改属于资源结构重组，核心风险不是算法错误，而是资源加载静默失效。因此测试重点放在资源读取与字典查找行为。

### 8.1 读取入口验证

覆盖以下行为：

- `ServiceProbes()` 可读取新的探针路径
- `Services()` 可读取新的服务映射路径
- `Dict(simple|normal|diff)` 可读取新的目录爆破字典路径
- `SecprobeDict(protocol)` 可读取新的弱口令字典路径

### 8.2 自定义字典规则验证

调整 `pkg/secprobe/dictionaries_test.go`，确保：

- 只生成 `<protocol>.txt`
- 不再生成 `secprobe-<protocol>.txt`
- 别名协议仍能正确映射到规范文件名集合

### 8.3 回归验证

至少执行以下范围的测试：

- `go test ./app ./pkg/secprobe ./pkg/assetprobe ./cmd`

如果某些包不包含测试文件，也允许按实际情况改为覆盖相关包的更小范围命令，但必须覆盖：

- 内置资源 embed 入口
- `secprobe` 字典候选逻辑
- `cmd` 中依赖字典规则的测试

## 9. 落地顺序

1. 先调整或补齐测试，锁定目标行为
2. 新建目录并迁移资源文件
3. 修改 `app/assets.go`
4. 修改 `pkg/secprobe/dictionaries.go`
5. 删除旧命名文件，确保仓库只保留新结构
6. 更新 README、UPGRADE 和协议扩展文档
7. 跑验证命令，确认没有静默断链

## 10. 风险与取舍

### 10.1 外部自定义字典不兼容

风险：

- 依赖 `secprobe-*.txt` 的外部用户会在升级后加载失败

取舍：

- 本次明确选择直接切换，不保留兼容层
- 通过文档和升级说明明确告知新规范

### 10.2 文档残留旧路径

风险：

- 后续开发会继续按旧路径新增资源

取舍：

- 本次必须同步修正文档中的主路径示例
- 对明显会误导开发的设计文档引用，也应一并修正

### 10.3 资源迁移后的 embed 失效

风险：

- 编译通过，但运行时读取内置资源失败

取舍：

- 通过入口读取测试和相关包测试兜底
- 不依赖人工检查文件位置来判断完成

## 11. 验收标准

- `app/` 目录完成按引擎分层
- `secprobe` 内置字典文件统一为 `app/secprobe/dicts/<protocol>.txt`
- `assetprobe` 目录爆破字典统一为 `app/assetprobe/dicts/<level>.txt`
- `pkg/secprobe/dictionaries.go` 仅支持 `<protocol>.txt`
- 仓库文档已更新到新结构和新命名
- 相关测试与验证命令通过
