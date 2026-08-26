# GoMap 主动 Web 应用指纹能力设计

日期：2026-08-26
状态：已确认

## 1. 背景

GoMap 当前已经具备主动服务识别能力。TCP fingerprint stage 会发送 nmap 风格 probe、HTTP/TLS 请求及少量协议专用请求，主要入口是：

- `pkg/assetprobe/scanner.go` 的 `fingerprintTCPPort`、`detectTCPServiceWithBudget`
- `internal/tcpservices/tcpservices.go` 的 `TcpPortServer`

但 GoMap 的 Web 能力当前只负责采集 `HomepageResult`，包括 Title、Header、Body、状态码、HTML MD5 和 favicon MD5，没有应用产品规则、主动应用路径探测和结构化应用指纹结果。

本设计参考两套现有实现：

1. `burp-finger@107d20dd42b179d1e76853415283db78e6f10ad0`：提供“被动响应匹配 + 主动 GET 路径 + 父目录深度识别”的实现证据，但其主动/被动 matcher 语义不一致，缺少版本、证据、可靠取消和总预算，且规则混入敏感文件与漏洞探测。详见 `docs/research/2026-08-26-burp-finger-reference.md`。
2. `zvas@818aab6344ff2f863a583f800a0ec2bbaa39fc30`：已有静态 Web 指纹表达式和匹配流程，支持布尔表达式、字符串/正则/数值比较、产品内 OR 和多产品输出。该流程当前位于 zvas Center，不属于 GoMap。详见 `docs/research/2026-08-26-zvas-static-fingerprint-reference.md`。

本设计把 zvas 已验证的静态匹配方式收敛到 GoMap，并在同一个 matcher 外增加受限主动 GET 和父目录深度识别。当前任务只扩展 GoMap，不修改 zvas。

## 2. 目标与非目标

### 2.1 目标

- 在 `pkg/assetprobe.Scanner` 上提供独立的 Web 应用指纹方法。
- 由 GoMap 完成首页采集、静态匹配、主动路径规划、深度识别、HTTP 执行、结果聚合和证据生成。
- 复用 zvas 已验证的表达式形式和组合语义。
- 静态响应和主动响应使用同一个 matcher。
- 从固定版本的 burp-finger 规则中筛选纯产品指纹，建立 GoMap 自有内置规则库。
- 主动探测只允许安全、无状态的 GET 请求。
- 所有额外请求受 context、并发、RPS、单请求超时、总请求数和 body 大小限制。
- 返回产品名称、类别和可定位的最小证据。
- 保持现有端口扫描、`Scanner.Scan` 和 `ScanResult` 不变。

### 2.2 非目标

- 不修改、迁移或退役 zvas 的代码、规则表、任务路由、消息、数据库或前端。
- 不提供 zvas 兼容投影字段。
- 不新增 CLI 子命令。
- 不修改 TCP/UDP 服务指纹。
- 不识别应用版本。
- 不提供置信度评分。
- 不探测漏洞、敏感文件、备份、日志、配置或数据库文件。
- 不引入爬虫，不发现未知子目录。
- 不支持 POST、认证、自定义请求 Header 或 Body。
- 不支持在线规则更新、数据库规则、运行时热加载或自定义规则文件。
- 不建立通用 HTTP 模板 DSL。
- 不新增 benchmark 或外部样本复现实验。

## 3. 方案选择

### 3.1 方案 A：复用 zvas matcher 语义并增加主动规则外壳

做法：

- 把 zvas 已验证的表达式和产品聚合语义实现到 GoMap。
- 用 GoMap 自有版本化 JSON 包裹产品、类别、静态表达式和主动路径。
- 把筛选后的 burp-finger 规则转换为 GoMap 规则。
- 静态首页与主动响应共用一个 evaluator。

优点：

- 复用已有实现事实，不重新发明 matcher。
- 避免 burp-finger 主动/被动语义分叉。
- GoMap 对调用方只暴露一个深模块接口。

### 3.2 方案 B：zvas 保留静态匹配，GoMap 只执行主动请求

该方案会长期保留两套 matcher、两套规则真值和跨系统结果合并，违背“GoMap 负责探测”的职责选择，因此拒绝。

### 3.3 方案 C：GoMap 重新设计通用 HTTP 模板引擎

该方案接近重新实现简化版 Nuclei，扩展面远超应用指纹，违反最小范围，因此拒绝。

最终选择方案 A。

## 4. 公开接口

GoMap 只新增一个公开方法：

```go
func (s *Scanner) DetectApplications(
    ctx context.Context,
    req ApplicationScanRequest,
) (*ApplicationScanResult, error)
```

调用该方法本身即表示执行完整应用指纹流程，不额外增加 `Active` 开关。

### 4.1 请求模型

```go
type ApplicationScanRequest struct {
    URL          string
    Depth        int
    Concurrency  int
    RateLimit    int
    Timeout      time.Duration
    MaxRequests  int
    MaxBodyBytes int64
}
```

默认值：

| 字段 | 默认值 | 语义 |
|---|---:|---|
| `Depth` | `0` | 只使用输入 URL 所在基准目录 |
| `Concurrency` | `10` | 主动 HTTP 请求最大并发 |
| `RateLimit` | `10` | 单次 `DetectApplications` 调用的主动 HTTP 请求总 RPS |
| `Timeout` | `5s` | 单个 HTTP 请求超时 |
| `MaxRequests` | `100` | 单次调用最多主动请求数 |
| `MaxBodyBytes` | `2 MiB` | 每个响应最多读取的 body |

约束：

- `URL` 必须是包含 host 的 `http` 或 `https` URL，且不得包含 userinfo；fragment 在请求前移除。
- `Depth` 不得小于 0。
- `Concurrency`、`RateLimit`、`Timeout`、`MaxRequests`、`MaxBodyBytes` 为零时使用默认值，为负数时返回参数错误。
- 并发、RPS、请求数和 body 上限不能被设置为无限制。
- 调用方只能调整执行预算，不能传入探针步骤或 matcher 细节。

### 4.2 结果模型

```go
type ApplicationScanResult struct {
    URL      string
    Homepage HomepageResult
    Products []ApplicationProduct
}

type ApplicationProduct struct {
    ID       string
    Name     string
    Category string
    Evidence ApplicationEvidence
}

type ApplicationEvidence struct {
    RuleID     string
    Source     ApplicationEvidenceSource
    URL        string
    StatusCode int
    Matches    []ApplicationMatch
}

type ApplicationMatch struct {
    Field    string
    Operator string
    Expected string
    Observed string
}
```

`ApplicationEvidenceSource` 首版只有：

- `passive`
- `active`

结果明确不包含：

- Meta 或执行统计；
- zvas 兼容字段；
- 应用版本；
- 置信度；
- 完整主动响应 Header/Body；
- 主动请求失败列表。

## 5. 深模块与 seam

公开 seam 位于 `pkg/assetprobe.Scanner.DetectApplications`。调用方只需要理解 URL、深度、预算和返回结果。

新增 `internal/appfingerprint` 深模块，内部封装：

```text
内置规则加载与编译
        ↓
输入 URL 首页采集
        ↓
HomepageResult -> ResponseRecord
        ↓
静态 matcher
        ↓
主动 probe planner
        ↓
受限 HTTP executor
        ↓
Response -> ResponseRecord
        ↓
同一 matcher
        ↓
产品聚合与证据生成
```

loader、compiler、matcher、planner 和 executor 都是内部实现，不暴露到 `pkg/assetprobe`。

HTTP 传输可以在模块内部保留测试 seam，使生产 HTTP adapter 和测试 adapter 复用同一执行逻辑；该 seam 不进入公开接口。

规则运行时继续采用当前阶段可接受的进程级不可变单例，不设计热加载、原子替换或多租户规则集。

## 6. 规则资产与 schema

### 6.1 文件位置

首版使用单一内置 JSON：

```text
app/assetprobe/fingerprints/gomap-web-fingerprints.json
```

burp-finger 固定基线的完整 JSON 约 112 KiB，GoMap 当前 `gomap-service-probes` 和 `gomap-services` 合计约 3.4 MiB。筛选后的单 JSON 不构成存储或加载问题，因此首版不按类别拆分。

### 6.2 schema

```json
{
  "schema_version": 1,
  "products": [
    {
      "id": "spring-boot-actuator",
      "name": "Spring Boot Actuator",
      "category": "framework",
      "rules": [
        {
          "id": "spring-boot-actuator-home",
          "source": "passive",
          "expression": "header=\"x-application-context\" || body=\"spring boot\""
        },
        {
          "id": "spring-boot-actuator-health",
          "source": "active",
          "path": "/actuator/health",
          "expression": "status=\"200\" && body=\"status\""
        }
      ]
    }
  ]
}
```

主动规则固定为安全 GET，因此首版不增加 `method`、request Header、request Body 或可执行 risk 配置。

### 6.3 matcher 字段

首版只支持有明确数据来源的字段：

- `header`
- `body`
- `server`
- `title`
- `path`
- `body_hash`
- `favicon_md5`
- `status`
- `content_type`
- `protocol`
- `port`

不保留：

- 当前没有输入来源的 `cert`；
- zvas 的特殊 `type=service`；
- 算法语义不明确的旧 `icon_hash`。

### 6.4 operator 与组合语义

复用 zvas 已验证的表达式方式：

- `!`、`&&`、`||` 和括号；
- 优先级为 `! > && > ||`；
- `=`：大小写不敏感包含；
- `==`：大小写不敏感完整相等；
- `!=`：大小写不敏感不包含；
- `~=`：Go RE2 大小写不敏感正则；
- `status`、`port` 支持 `=`、`==`、`!=`、`>=`、`<=` 数值比较；
- 同产品多条规则为 OR；
- 不同产品允许同时命中。

静态与主动响应必须使用同一个 evaluator。

`path` 在 expression 中只代表当前响应对应的请求 path，不负责生成主动请求。主动请求地址只来自 `source=active` 规则的独立 `path` 字段。

### 6.5 加载约束

`NewScanner` 初始化时一次性完成：

- schema version 校验；
- product ID 和 rule ID 全局唯一性校验；
- product name/category 非空校验；
- expression 完整解析；
- regex 预编译；
- passive 规则禁止设置主动 `path` 字段；active 规则必须设置以 `/` 开头、且不含 scheme、host、query 或 fragment 的主动 `path`；
- active path 规范化和安全校验；
- 禁止路径穿越、敏感文件和纯 status 规则；
- 禁止只包含否定条件的规则；
- 要求每个产品至少有一条有效规则。

任何内置规则非法都使初始化失败，不在运行时静默跳过。

## 7. 执行流程

### 7.1 基准目录

输入 URL 的 path 转换为基准目录：

- `/` -> `/`
- `/app/` -> `/app`
- `/app/login` -> `/app/login`
- `/app/index.php` -> `/app`

最后一段包含文件扩展名时按文件处理并取父目录；否则按目录处理。

### 7.2 深度语义

`Depth` 表示从输入 URL 所在基准目录向上回溯的父目录级数：

```text
URL: /a/b/index.php
Depth=0 -> /a/b
Depth=1 -> /a/b, /a
Depth=2 -> /a/b, /a, /
```

到根目录后停止，不发现未知子目录。

### 7.3 数据流

```text
校验请求
  ↓
请求输入 URL 一次，生成 HomepageResult
  ↓
HomepageResult 转统一 ResponseRecord
  ↓
执行全部 passive 规则
  ↓
排除已确认产品
  ↓
按基准目录 × active path 生成探针计划
  ↓
按完整 URL 去重
  ↓
受限并发执行安全 GET
  ↓
每个响应转为同一种 ResponseRecord
  ↓
使用同一 matcher 执行 active expression
  ↓
按 ProductID 聚合并选择证据
```

同一个主动 URL 只请求一次，其响应可以供多个产品规则匹配。

### 7.4 主动请求约束

首版主动请求必须满足：

- 固定使用 GET；
- 与输入 URL 使用相同 scheme、host 和 port；
- 首页和主动请求最多跟随 5 次同 origin 重定向；跨 origin 重定向不跟随；
- 不跨 origin；
- 不携带认证信息；
- 只有首页请求保留输入 URL query，主动请求不继承 query；
- 不执行路径穿越、备份下载、日志、配置文件或漏洞验证路径；
- 不携带自定义 request Body；
- 所有请求继承 caller `context.Context`；
- 每个请求受单请求 timeout、body 上限、并发和 RPS 控制；
- body 达到 `MaxBodyBytes` 后停止继续读取，已读取内容仍可用于正向匹配。

### 7.5 规划与停止

- passive 已确认的产品不再生成该产品的 active probes。
- 其余 active probes 在网络执行前一次性按“产品顺序、规则顺序、基准目录顺序”生成确定计划，并按完整 URL 合并。
- 达到 `MaxRequests` 后按上述确定顺序截断计划。
- active 执行过程中不再按命中结果动态撤销请求；这避免网络完成顺序改变最终产品或证据。
- 请求和规则顺序必须确定，网络完成顺序不得改变最终结果。

## 8. 结果与证据

### 8.1 聚合

- 每个 `ProductID` 最多返回一次。
- passive 证据优先于 active。
- 同来源多条规则命中时，选择规则文件顺序最前的证据。
- `Products` 最终按 `ProductID` 排序。
- 并发响应完成顺序不得影响产品或证据选择。

### 8.2 证据

- `RuleID` 必须可以定位到内置 JSON。
- `URL` 是产生证据的真实请求 URL。
- `StatusCode` 保存该响应状态。
- `Matches` 保存使规则成立的原子条件。
- `Observed` 最多保留 256 字节。
- keyword/exact 保存实际命中片段。
- regex 保存正则实际匹配文本。
- hash/status/port 保存实际值。
- 不返回完整主动响应 Header 或 Body。

每条规则必须包含至少一个正向产品特征；否定条件和 HTTP status 只能作为辅助条件。

## 9. 错误语义

整体返回错误：

- URL 非法或 scheme 不是 HTTP(S)；
- 请求参数非法；
- 内置规则加载或编译失败；
- 输入 URL 首次请求失败；
- caller context 取消或超时。

不返回整体错误：

- 单个主动请求连接失败、超时或响应读取失败；
- 某条主动规则未命中；
- 达到 `MaxRequests`。

以上局部情况只表现为对应产品未识别，不额外输出 Meta。

## 10. 初始规则来源与筛选

规则来源固定为：

```text
238469/burp-finger
commit 107d20dd42b179d1e76853415283db78e6f10ad0
```

允许导入：

- 能明确识别产品的 Header、Body、Title 特征；
- favicon MD5；
- 安全 GET 路径；
- active 规则包含产品专属 keyword、regex 或 hash；
- 能无歧义转换为 GoMap expression 的规则。

禁止导入：

- 仅凭 HTTP 200；
- `.git`、`.svn`、备份、日志、数据库、配置文件；
- Actuator 环境变量等敏感内容；
- 路径穿越和漏洞验证；
- 可能触发状态变更的端点；
- 依赖 burp-finger 隐式正则歧义的规则；
- 重名或无法确定产品归属的规则。

不设规则数量目标，以规则可解释、可校验和符合安全范围为准。

规则目录同时保留 burp-finger MIT 许可证声明，例如：

```text
app/assetprobe/fingerprints/LICENSE.burp-finger
```

许可证文件不进入 JSON schema。

## 11. 测试设计

### 11.1 规则资产测试

- 内置 JSON 可解析。
- product/rule ID 唯一。
- expression 和 regex 可编译。
- active path 满足安全约束。
- 不存在 status-only、纯否定或高风险规则。
- 每个产品至少有一条有效规则。

### 11.2 matcher 测试

在 GoMap 仓库内独立锁定：

- contains、exact、not 和 regex；
- `! > && > ||` 优先级及括号；
- status/port 数值比较；
- 产品内 OR；
- 多产品同时命中；
- 大小写语义；
- 确定排序；
- evidence 生成及 256 字节限制。

测试不 import、不启动、也不修改 zvas。

### 11.3 执行测试

使用本地 `httptest.Server` 验证：

- 首页只请求一次；
- passive 命中后不发送该产品 active 请求；
- 相同 active URL 合并；
- `Depth=0/N` 路径正确；
- 不跨 origin、不继承 query；
- 并发、RPS、超时和最大请求数；
- context 取消；
- 单探针失败不影响其他探针；
- 响应完成顺序不改变最终结果。

### 11.4 回归验证

```bash
go test ./...
```

当前项目已完成过大数据量对比，且不具备重新对比条件，因此本任务不增加 benchmark、样本集或复现实验作为前置条件。

## 12. 最终设计结论

本设计在 GoMap 中新增一个独立、深的 Web 应用指纹模块：

- 对外只有 `Scanner.DetectApplications`；
- 内部复用 zvas 已验证的静态表达式方式；
- 使用 GoMap 自有版本化 JSON；
- 从经过安全和语义筛选的 burp-finger 规则建立初始资产；
- 首页静态响应与主动响应共享同一 matcher；
- 主动探测固定为受预算控制的安全 GET；
- 深度只沿输入 URL 父目录向上回溯；
- 返回产品、类别和最小可复核证据；
- 不修改现有端口扫描，也不涉及 zvas 集成。
