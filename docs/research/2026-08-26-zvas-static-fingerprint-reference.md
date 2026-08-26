# zvas 静态 Web 指纹流程：GoMap 主动指纹 SDK 的兼容基线

- 研究日期：2026-08-26
- zvas 源码基线：`818aab6344ff2f863a583f800a0ec2bbaa39fc30`（`dev`）
- zvas 使用的 GoMap：`github.com/yrighc/gomap v0.4.8`，本地 tag commit `d4629e481142382e623f6930ae293b56c83e8024`
- GoMap 当前工作树基线：`e41cb62efc03ed8916306ef2c81a31c966571df0`
- burp-finger 对照基线：`107d20dd42b179d1e76853415283db78e6f10ad0`，详见 `docs/research/2026-08-26-burp-finger-reference.md`
- 方法：严格只读检查 zvas 的源码、测试、设计文档、迁移和本地 git 历史；未构建、未启动服务、未运行测试、未连接或查询数据库/队列/外部服务。
- 工作树说明：研究开始时 zvas 已有用户改动 `config/worker/application-dev.yml`；本文未读取其内容，也未修改 zvas。本文涉及 zvas 文件时，路径均为 **zvas repo-relative**。

本文使用：

- **[现行事实]**：当前 zvas commit 的代码或测试直接证明；
- **[历史事实]**：设计文档或 git 历史直接证明，但不一定仍是现行行为；
- **[推断/约束]**：由现行事实推出的迁移边界，不冒充既有实现。

## 0. 先给证据边界

1. **[现行事实] zvas 的真实静态匹配不是独立 worker stage，而是 Center 在持久化成功的 `http_probe.homepage` 结果时内联执行。** Worker 的独立 `fingerprint-web` process 仍注册，但只返回 `{"stub": true}`，不读取 HTTP 响应、不加载规则、不匹配。`internal/center/repo/task_repo_postgres.go:506-522,603-611`；`internal/worker/engines/assets/process/fingerprint_web.go:40-81`。
2. **[现行事实] zvas 没有随仓库发布任何生产 Web 指纹规则资产。** 基线迁移创建空表，迁移契约明确断言 `web_fingerprint_rule` 初始行数为 0；规则只能在运行期经数据库/API 导入。`internal/platform/migration/000001_init_schema.up.sql:848-858`；`internal/platform/migration/migration_sql_test.go:2660-2667`。
3. **[现行事实] 已验证且应复用的是“GoMap 首页响应标准化 → Record → 编译规则 → 多产品排序去重 → `task_unit_http_result.fingerprints`”这条静态流程，不是规则资产质量，也不是主动探测机制。** 当前仓库没有足够资产证明误报率、覆盖率或版本识别能力。
4. **[现行事实] matcher 只输出产品名字符串。** 数据库规则 ID、表达式、命中字段、证据、分类、版本、置信度和风险均丢失。`internal/center/webfingerprint/matcher.go:50-65`；`internal/center/repo/task_unit_http_structured.go:43-78`。
5. **[约束] GoMap 新能力必须保留 zvas 的静态表达式行为作为兼容基线；active/depth 只能在其外部扩展。** 不能以“新 schema 更合理”为由静默改变单等号、大小写、路径、产品内 OR、多产品输出等既有语义。

## 1. HTTP 响应进入 matcher 到落库/输出的完整数据流

### 1.1 调用链

```text
Center 创建/调度 http_probe.homepage task_unit
  -> Worker GomapHomepageProcess.Run
     -> buildHomepageURL(unit)
     -> assetprobe.NewScanner(Options{Timeout})
     -> Scanner.DetectHomepageWithOptions(ctx, URL,
          IncludeHeaders=true, MaxBodyBytes=2 MiB)
     -> homepageResultToPayload
        原始：首页 URL/title/header/body/status/server/html/favicon/ICP
        派生：path/protocol/port/banner/header_string/body_hash
  -> Worker 发布 UnitResultEvent{Result: map[string]any}
  -> CenterService.HandleUnitResult
  -> TaskRepoPostgres.ApplyUnitResult（事务）
     -> 识别 route_code=http_probe.homepage
     -> matchHTTPFingerprints(event)
        -> 标准字段组装 webfingerprint.Record
        -> loadWebFingerprintMatcher
           -> 查询启用规则 max(updated_at)+count
           -> 命中进程内缓存，或全量 SELECT + NewMatcherFromModels
        -> Matcher.Match(record)
        -> 产品名 trim/去空/精确去重/排序
     -> buildStructuredHTTPResultRow(..., fingerprints)
     -> task_unit.result_json 写首页摘要
     -> UPSERT task_unit_http_result.fingerprints
     -> 写 snapshot/pool site asset 的 extra/detail
  -> 任务记录列表、详情、资产详情和关键字搜索输出 fingerprints
```

入口证据：

- `internal/worker/engines/assets/process/gomap_homepage.go:73-116`：`Run` 以 task timeout 包装首页检测，成功后调用 `homepageResultToPayload`。
- `internal/worker/engines/assets/process/homepage_detector.go:14-57`：构造 GoMap scanner，调用 `DetectHomepageWithOptions`，固定 `IncludeHeaders=true`、`MaxBodyBytes=2*1024*1024`。
- `internal/platform/contracts/events.go:46-60`：消息契约 `UnitResultEvent.Result map[string]any`。
- `internal/center/runtime/server.go:60-69`、`internal/center/app/service.go:177-180`：Center 订阅结果事件并转交 repo。
- `internal/center/repo/task_repo_postgres.go:411-427,506-522`：`ApplyUnitResult` 开事务，仅成功 HTTP probe 调用 `matchHTTPFingerprints`。

### 1.2 Worker 标准化：GoMap 结果到消息 payload

`homepageResultToPayload` 的核心映射位于 `internal/worker/engines/assets/process/gomap_adapter.go:346-410`：

```go
headerString := strings.TrimSpace(homepage.Response.HeaderMap)
body := homepage.Response.Body
banner := strings.TrimSpace(homepage.Response.Header.Server)
payload := map[string]any{
    "site_url":       probeURL,
    "title":          homepage.Title,
    "status_code":    homepage.Response.Header.StatusCode,
    "server":         homepage.Response.Header.Server,
    "html_hash":      homepage.HTMLHash,
    "favicon_hash":   homepage.FaviconHash,
    "path":           path,
    "protocol":       protocol,
    "port":           port,
    "banner":         banner,
    "header_string":  headerString,
    "body_hash":      md5Hex([]byte(body)),
    "content_type":   homepage.Response.Header.ContentType,
    "response_body":  body,
}
```

精确语义：

- `site_url` 是 **探测请求 URL** `homepageURL`，不是 GoMap 返回的 `homepage.URL`；两者不同时，后者另存 `response_site_url`。`gomap_adapter.go:346-348,410-412`。
- `path/protocol/port` 从 `homepage.URL` 解析；无 path 时 `/`，无显式端口时 HTTP/HTTPS 分别补 80/443。`gomap_adapter.go:349-368`。但 GoMap v0.4.8 的 `DetectHomepageWithOptions` 把 `HomepageResult.URL` 赋为入参 `rawURL`，并未写入 redirect 后 URL；所以真实运行时通常仍是请求 path。adapter 测试通过手工构造不同 URL 锁定了映射函数，却不能证明 SDK 会提供 final URL。`github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/scanner.go:468-485`；`gomap_adapter_test.go:257-304`。
- `banner` 当前等于 `Server`；`body_hash` 是返回给 zvas 的 body 的 MD5 hex。`gomap_adapter.go:369-370,389-390`。
- 适配测试锁定上述映射、构造的 `homepage.URL` path、默认端口、header string 和 MD5；它是 adapter 单测，不覆盖 v0.4.8 重定向 URL 行为。`internal/worker/engines/assets/process/gomap_adapter_test.go:257-332`。

### 1.3 Center Record 映射

`internal/center/repo/task_unit_http_fingerprint.go:17-41` 是静态匹配唯一运行入口：

| Record 字段 | `event.Result` 来源（按优先顺序） | 备注 |
|---|---|---|
| `URL` | `site_url` / `homepage_url` / `target` | 当前 matcher 不消费 `URL` |
| `Path` | `path` | `HomepageResult.URL` 派生 path；v0.4.8 实际通常是请求 path；不生成主动请求 |
| `Title` | `title` | trim |
| `Server` | `server` | trim |
| `HeaderString` | `header_string` / `response_header_text` / `response_header_map` | `stringFromAny` 后匹配 |
| `Body` | `response_body` | 不 trim |
| `BodyHash` | `body_hash` / `html_hash` | 通常是 MD5 hex |
| `IconHash` | `icon_hash` / `favicon_hash` | 见 4.3 的算法/类型不兼容 |
| `StatusCode` | `status_code` | 解析失败为 0 |
| `ContentType` | `content_type` | trim |
| `TLS` | `cert` | 当前 GoMap 首页 payload 不提供 |
| `Banner` | `banner` / `server` | trim |
| `Port` | `port` | 解析失败为 0 |
| `Protocol` | `protocol` | trim |

仅当 `URL/Path/Title/Body/Server` 五者全空时跳过；因此只有 status/header/hash 的手工事件也可能被这道前置判断挡掉。加载或编译 matcher 出错时返回空结果，**错误被吞掉且没有日志**。`task_unit_http_fingerprint.go:34-41`。

### 1.4 规则加载、缓存与并发

`loadWebFingerprintMatcher` 的缓存键是启用且未删除规则的：

```sql
select coalesce(max(updated_at), to_timestamp(0)), count(*)
from web_fingerprint_rule
where status = 1 and deleted_at is null
```

每次首页匹配都会先执行这条数据库查询；缓存只省掉全量 SELECT 和重新编译，不省掉热路径数据库 round trip。`internal/center/repo/task_unit_http_fingerprint.go:44-61`。

缓存失配后再按 `product_name asc, updated_at desc` 加载全部启用规则并编译。`task_unit_http_fingerprint.go:64-90`。

并发行为：

- `TaskRepoPostgres` 保存 `sync.RWMutex + cachedWebFingerprintMatcher{stamp,count,matcher}`。`internal/center/repo/task_repo_postgres.go:29-42`。
- 读缓存和写缓存受锁保护；已构建的 matcher 只有只读 map/slice，可供并发 Match。
- “检查缓存 → 查全量规则 → 编译”不在互斥区内；多个并发 miss 可重复查询和编译，最后一个写入覆盖前者，但不会产生 map 数据竞争。`task_unit_http_fingerprint.go:57-99`。
- `max(updated_at)+count` 不是内容摘要：若绕开正常 API 修改规则且保持二者不变，缓存不会失效。正常 CRUD 会更新 `updated_at`，因此常规路径可刷新。`internal/center/repo/web_fingerprint_rule_repo.go:25-56`。
- 设计文档曾要求 CRUD 后显式 `InvalidateFingerprintCache()`；现行代码没有该 API，而是上述数据库 stamp 轮询。属于文档与实现差异。`docs/superpowers/specs/2026-04-28-web-fingerprint-inline-homepage-design.md` 的 “Cache Design”；现行 `task_unit_http_fingerprint.go:44-99`。

### 1.5 匹配、去重与落库/输出

`Matcher.Match` 按 product 遍历：同一 product 任一 expression 为真即 `break`，每个 product 最多输出一次；不同 product 可同时输出；最终字典序排序。`internal/center/webfingerprint/matcher.go:50-65`。

Center 又执行一层 `normalizeStringSlice`：trim、去空、按 **大小写敏感的完整字符串** 去重、排序。`internal/center/repo/task_unit_http_structured.go:270-288`。所以 `nginx` 与 `Nginx` 是两个产品，完全相同的产品名才折叠。

持久化有三处：

1. `task_unit.result_json`：只保存 `task_type/task_subtype/target/site_url/probe_status/probe_error/status_code/title/fingerprints` 摘要；不保存完整规则命中证据。`internal/center/repo/task_repo_postgres.go:506-522`。
2. `task_unit_http_result.fingerprints`：JSONB 数组，按 `task_unit_id` UPSERT。`internal/center/repo/task_unit_http_structured.go:43-78`；表契约见 `internal/platform/migration/000001_init_schema.up.sql:501-551`。
3. 扩展 site asset：初次构造时把 `fingerprints` 写入 `ExtraPayload`；Pool site 详情查询又从 `task_unit_http_result` 映射为 `Detail["fingerprints"]`。`task_unit_http_structured.go:185-256`；`internal/center/repo/scan_task_record_repo.go:536-587`。

公开读取：

- 任务详情 `TaskRecordHTTPResult.Fingerprints []string`。模型和 detail mapper 虽定义/读取 request/header/body 展示字段，但成功 HTTP probe 的 `task_unit.result_json` 实际只保存摘要字段，不含这三类原始数据；正常主链因此不能依靠详情重建匹配证据。`internal/platform/model/task.go:488-508`；`internal/center/repo/scan_task_record_detail_repo.go:75-87,218-233`；`internal/center/repo/task_repo_postgres.go:506-522`。
- 任务列表把 fingerprints 放入 detail，并允许对 `fingerprints::text` 做关键字过滤。`internal/center/repo/scan_task_record_repo.go:122-132,208-224`。
- 摘要显示 `指纹 nginx, wordpress`。`internal/center/repo/task_unit_http_structured.go:160-181`。

失败边界：

- 只有 `UnitStatusSucceeded` 的 HTTP probe 会匹配并写结构化 HTTP 行；失败事件只写通用 result。`task_repo_postgres.go:506-528,603-611`。
- “不可达”在 worker 中可被包装为成功 observation；其 payload 没有 title/body/server/path，通常触发 Record 全空跳过，最终 `fingerprints=[]`。`internal/worker/engines/assets/process/gomap_homepage.go:101-114,132-151`。
- matcher 失败不会阻止首页事实落库，但现行代码也不记录失败原因；这满足可用性降级，不满足可观测性。

## 2. 规则 schema：全部字段与真实语义

### 2.1 持久化/API schema

`model.WebFingerprintRule` 和表只有六个字段。`internal/platform/model/web_fingerprint_rule.go:5-16`；`internal/platform/migration/000001_init_schema.up.sql:848-858`。

| 字段 | 真实语义 |
|---|---|
| `id bigint` | 数据库规则行 ID；CRUD/API 可见；编译后和 match 输出中丢失 |
| `product_name text` | product 分组键和最终输出标签；trim 后不能为空；无稳定 product ID、无唯一产品约束 |
| `rule_content text` | 一条表达式，或含 `rule/rules` 的旧 YAML item；原文保存 |
| `status integer` | 仅 0/1；1 启用，0 禁用；不是 HTTP status、风险或审核状态 |
| `updated_at timestamptz` | CRUD 更新；同时参与 matcher 缓存 stamp |
| `deleted_at timestamptz?` | 软删除；加载只读 `deleted_at is null` |

活动记录的 `(product_name, rule_content)` 有部分唯一索引，比较按数据库文本语义且不做大小写归一。软删除后允许重建同一对。`000001_init_schema.up.sql:856-858`。

HTTP 管理 DTO 也只暴露 `id/product_name/rule_content/status/updated_at`；upsert 只收 `product_name/rule_content/status`。`internal/center/http/handler/task.go:59-104`。

当前 API 路径是：

- `GET/POST /api/v1/fingerprints`
- `GET/PUT/DELETE /api/v1/fingerprints/:id`
- `POST /api/v1/fingerprints/import`，JSON body `{content: string}`
- `GET /api/v1/fingerprints/export`

全部要求 `settings:manage`。`internal/center/http/router.go:142-148`。早期设计文档中的 `/web-fingerprint-rules` 和 multipart 多文件导入不是现行契约。

### 2.2 表达式容器与组合

`RuleContent` 的提取顺序位于 `internal/center/webfingerprint/parser.go:9-47`：

1. 尝试 YAML `[]map[string]any`，只提取每个 item 的 `rule`/`rules`；
2. 尝试 YAML `[]string`；
3. 若仍为空且原文含 `- `，按行剥离 `- `；
4. 最后把整段非空文本当一个 expression。

`rule`/`rules` 可为字符串或数组。数组中的每个字符串成为 **独立 expression（OR）**，不是隐式 AND。`parser.go:50-72`。

导入支持：

- 简单 map：`product_name -> string | []string`，每个 expression 建一行；
- 旧对象数组：读取顶层 `name`，把整个 YAML item 保存为一行，再由 matcher 提取内部 `rule/rules`。

`internal/center/usecase/web_fingerprint_rule_usecase.go:165-253`。导入逐行查询精确重复并逐行插入，无事务批量原子性；中途失败会保留先前成功行。`web_fingerprint_rule_usecase.go:73-92`。

### 2.3 可匹配字段

Record 定义位于 `internal/center/webfingerprint/types.go:3-19`；实际 switch 位于 `matcher.go:68-124`。

| 表达式 key | 输入 | 比较类型 | 重要边界 |
|---|---|---|---|
| `header` | `HeaderString` | 字符串 | 整块格式化 header 文本 |
| `body` | `Body` | 字符串 | 当前首页响应体 |
| `server` | `Server` | 字符串 | Server 头摘要 |
| `title` | `Title` | 字符串 | 页面标题 |
| `cert` | `TLS` | 字符串 | switch 支持，但当前 GoMap payload 不供值 |
| `path` | `Path` | 字符串 | `HomepageResult.URL` 派生 path；v0.4.8 通常是请求 path；默认 `=` 是 contains，不是 active path |
| `body_hash` | `BodyHash` | 字符串 | 通常 MD5 hex；仍遵循字符串 operator |
| `content_type` | `ContentType` | 字符串 | 默认 contains |
| `banner` | `Banner` | 字符串 | 当前等于 server |
| `port` | `Port` | 整数 | `= / == / != / >= / <=` |
| `status` | `StatusCode` | 整数 | HTTP 状态码 |
| `icon_hash` | `IconHash` | **十进制整数** | GoMap favicon MD5 hex 无法 `Atoi`，见 4.3 |
| `protocol` | `Protocol` | 枚举式大小写不敏感全等/不等 | 不做 contains/regex/range |
| `type` | 无 Record 字段 | 特例 | 只要 value 大小写不敏感等于 `service` 就为真；代码忽略 operator |

`Record.URL` 没有对应 `url` case，当前完全不参与匹配。未知 key 固定 false。`matcher.go:77-116`。

### 2.4 不存在的 schema 能力

以下字段或语义 **不存在**：

- 产品分类/category、技术标签；
- product ID/namespace；
- 结构化 version 或正则捕获组提取；
- priority/order/weight/score/confidence；
- 稳定 rule ID 输出或命中 evidence；
- risk/safety/method/request headers/request body/active depth；
- schema version、规则集版本、来源、许可证、作者、校验和；
- per-rule disable reason、审核状态或过期时间。

注意：site asset 的 `expanded_confidence_level` 是“资产观测可信度”，不是指纹规则置信度。`internal/center/repo/task_unit_http_structured.go:103-125`。

### 2.5 规则资产数量与质量

**仓库内生产资产：0。**

- 基线 SQL 只建表、不 insert Web 指纹规则。`000001_init_schema.up.sql:848-858`。
- 迁移测试把 `web_fingerprint_rule` 列入“初始必须为 0 行”的表。`migration_sql_test.go:2660-2667`。
- 仓库没有 fingerprints YAML/JSON 规则包、seed 或 embed；唯一表达式语料来自测试和设计示例。

测试语料仅覆盖 `wordpress/nginx/jenkins/demo-app` 等演示产品，不能代表真实规则质量。`internal/center/webfingerprint/matcher_test.go:10-82`；`internal/center/repo/task_unit_http_structured_test.go:345-440`。

**因此不能从源码诚实给出运行数据库规则数量或误报/漏报质量。** 本研究按用户约束未查询数据库；任何“zvas 有 N 条高质量规则”的说法都没有当前 repo 第一手证据。

## 3. matcher 的确定行为

### 3.1 operator

原子语法由 `getRuleData` 的字符串扫描实现，不是 parser generator。它只寻找连续的 `="`，回看一个字符确定 operator。字段名扫描只接受小写 ASCII `a-z` 和 `_`；值必须双引号包围；field/operator/quote 之间不能插空格。大写 field、无引号值或 `body = "x"` 都不属于兼容语法。结束引号按“前一字节不是反斜杠 `\`”识别，随后由字符串比较层把 `\"` 还原为 `"`。`internal/center/webfingerprint/matcher.go:250-293,315-317`。

| 表达式 | 字符串字段 | 整数字段 |
|---|---|---|
| `field="x"` | 大小写不敏感 contains | 等于 |
| `field!="x"` | 不 contains | 不等于 |
| `field=="x"` | 大小写不敏感全文等于 | 等于 |
| `field~="x"` | Go regexp | 不支持 |
| `field>="x"` | 不支持 | 大于等于 |
| `field<="x"` | 不支持 | 小于等于 |

字符串实现先对 source 和 rule 执行 `strings.ToLower`，再 contains/equal/regex；规则中的 `\"` 还原为 `"`。正则因此是在 **已小写文本** 上执行 Go RE2 语义，不自动 DOTALL。非法 regex 不报加载错误，只返回 false。`matcher.go:310-330`。

整数实现位于 `matcher.go:332-345`。规则值 `Atoi` 失败只使该原子为 false，不使规则加载失败。`matcher.go:88-108`。

缺失值不是三态 `unknown`，而是参与比较：空字符串对非空规则的 `!=`/`!contains` 可为 true，缺失 port/status 在 Record 映射时成为 0，`port!="443"` 也可为 true；`protocol!="https"` 对空 protocol 同样为 true。唯一不同的是 `icon_hash`：source 不能转十进制整数时，连 `!=` 也固定 false，因为求值先要求两次 `Atoi` 均成功。`task_unit_http_fingerprint.go:17-33`；`matcher.go:88-108,315-345`。这意味着迁移时不能擅自把缺失字段改成“所有 operator 都 false”。

### 3.2 布尔表达式

支持 `!`、`&&`、`||`、括号，优先级 `! > && > ||`。每个原子先替换为 `T/F`，再由栈式 `boolEval` 求值。`matcher.go:68-124,128-247`。

必须保持的现行组合语义：

- 单 expression 内按显式布尔式组合；
- 同一 `product_name` 的多个 expression 是 OR；
- 第一个命中的 expression 结束该 product 的评估；
- 不结束其他 product，最终可多命中；
- 输出不保留“第几个 expression 命中”。

### 3.3 path、header、body 与 hash

- `path` 没有特殊路径规范化；与其他字符串完全同语义。`path="/admin"` 是大小写不敏感 contains，只有 `path=="/admin"` 才全等。zvas adapter 从 `HomepageResult.URL` 取 path，不含 query；GoMap v0.4.8 实际把该字段设为请求 `rawURL`，不是 redirect 后 URL。`gomap_adapter.go:346-368`；`github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/scanner.go:468-485`；`matcher.go:98-101`。
- Header 不是 map-aware matcher。GoMap v0.4.8 先按 header key 排序，格式为首行 `HTTP <status>\n`，随后每个值一行 `<Key>: <Value>\n`。`github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/scanner.go:1415-1436`。规则在这整个字符串上匹配。
- matcher 自己不截断 body。zvas 请求 GoMap 返回最多 2 MiB。GoMap v0.4.8 的公开 options 会在返回前切片，但更底层 crawler 已用 `http.MaxBytesReader(..., 2 MiB)`，且 read error 直接使首页 fetch 失败；没有 `truncated` 标记。`homepage_detector.go:14-46`；`github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/scanner.go:461-496`；`github.com/yrighc/gomap@v0.4.8/internal/crawlweb/crawlweb.go:75-99`。
- `body_hash` 是 zvas 对 `homepage.Response.Body` 算的 MD5；`html_hash` 是 GoMap crawler 对读取 body 算的 MD5。Center 优先用 `body_hash`。`gomap_adapter.go:369-390`；`task_unit_http_fingerprint.go:24-26`。
- `icon_hash` matcher 只接受十进制整数，而 GoMap v0.4.8 `FaviconHash` 是 MD5 hex。若消息没有另给十进制 `icon_hash`，该原子必为 false。`matcher.go:102-105`；`github.com/yrighc/gomap@v0.4.8/internal/crawlweb/crawlweb.go:179-190`。

### 3.4 首次命中、多命中与顺序

- Product map 的 Go 遍历顺序不稳定，但最终 `sort.Strings`，所以返回顺序确定。`matcher.go:55-65`。
- 同 product 首次 expression 命中即停止；同 product 不重复。
- 不同 product 全部评估，可同时命中。
- Center 再排序/去重，因此落库顺序同样确定。`task_unit_http_structured.go:270-288`。
- 没有规则优先级；“首次”只影响性能和丢失哪条命中证据，不影响产品布尔结果。

### 3.5 错误规则处理：现行代码与设计承诺不同

现行行为：

- 空 product/model 被跳过。`matcher.go:22-29`。
- 非空 expression 若一个原子都解析不出，`NewMatcherFromModels` 立即报错，**整批 matcher 构建失败**。`matcher.go:30-46`。
- 该错误在 `matchHTTPFingerprints` 被吞掉，当前首页得到空 fingerprints；旧缓存也不会被退回使用。`task_unit_http_fingerprint.go:37-40,87-90`。
- CRUD/import 只校验 product/rule 非空、status 为 0/1、完全重复；不调用 parser，不预编译 regex。`web_fingerprint_rule_usecase.go:137-162`。
- 非法 regex、非法数字、未知字段、括号/布尔求值错误通常只是该 expression false；不会在加载期报告。
- parser 不做完整 token 校验；表达式含至少一个可解析原子即可进入 matcher，剩余非操作符字符在 `boolEval` 中不会形成明确错误。`matcher.go:140-247,250-308`。

历史设计要求“单条非法规则跳过并记录日志；所有规则失败才构建失败”。现行实现没有做到。`docs/superpowers/specs/2026-04-28-web-fingerprint-inline-homepage-design.md` 的 “Error Handling”；对照 `matcher.go:36-39` 和 `task_unit_http_fingerprint.go:37-40`。

### 3.6 测试实际锁定了什么

| 测试 | 已锁定 | 未锁定/弱证据 |
|---|---|---|
| `TestMatcherSupportsStringIntAndRegexOperators` | body contains、title regex 的基本用法；status/port 数值等于；protocol 全等；多产品排序 | 没覆盖 `!=/==/>=/<=`、括号、OR、非法 regex；测试名比断言范围宽 |
| `TestMatcherExtractsRulesFromYAML` | 旧对象数组的 `rule: []` 能提取 | Record 同时满足两个 expression，未单独证明列表项 OR |
| `TestMatcherSupportsNegationAndPath` | `!body="..."` 布尔非、path contains、content-type contains | 未覆盖 `body!="..."` operator 与 path exact |
| `TestHomepageResultToPayload` | GoMap 结果到 payload 的 path/protocol/port/header/body MD5 | 使用假的非数值 favicon hash，没有 matcher favicon 断言 |
| `TestApplyTaskUnitHTTPResultMatchesFingerprintsInline` | 成功 HTTP 结果内联匹配、两产品落 JSON、详情读取、摘要排序 | 是数据库集成测试，需要外部 test DB；不覆盖缓存并发/失效或错误规则 |

证据路径：`internal/center/webfingerprint/matcher_test.go:10-82`；`internal/worker/engines/assets/process/gomap_adapter_test.go:257-332`；`internal/center/repo/task_unit_http_structured_test.go:345-440`。

当前没有测试锁定：header 格式兼容、2 MiB 边界、icon hash、缺失值参与 `!=`、cert/banner/type、缓存并发、同 stamp/count 更新、坏规则降级、case-variant product 去重、规则 CRUD/import 编译校验、命中证据。

## 4. zvas 如何调用 GoMap，以及可直接复用的字段

### 4.1 调用方式

zvas 不是通过 HTTP/RPC 调 GoMap，而是在 worker 进程中直接 import SDK：`go.mod:20` 固定 `github.com/yrighc/gomap v0.4.8`。

调用链：

- `NewGomapHomepageProcess` 注入 `newHomepageDetector()`。`internal/worker/engines/assets/process/gomap_homepage.go:54-70`。
- `assetprobeHomepageDetector.DetectHomepage` 创建 `assetprobe.Scanner`，把 task deadline 换算成 `Options.Timeout`，调用 `DetectHomepageWithOptions`。`homepage_detector.go:25-57`。
- zvas 外层 goroutine/select 能按 ctx 提前返回；GoMap v0.4.8 的 `DetectHomepageWithOptions` 只在进入时检查 ctx，底层 crawler 使用自己的 HTTP client/background timeout。因此取消传播不是严格端到端，但底层请求有 5 秒 client timeout。`homepage_detector.go:31-57`；`github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/scanner.go:461-469`；`github.com/yrighc/gomap@v0.4.8/internal/crawlweb/crawlweb.go:121-154`。

### 4.2 GoMap `HomepageResult` 可直接供 matcher 使用的字段

GoMap v0.4.8 公开模型见 `github.com/yrighc/gomap@v0.4.8/pkg/assetprobe/types.go:207-249`。

可直接使用：

| GoMap 字段 | zvas/matcher 用途 |
|---|---|
| `HomepageResult.URL` | 派生 path/protocol/port；v0.4.8 当前值为请求 `rawURL`，可作为 attempted URL evidence，但不能当作 redirect 后 final URL |
| `Title` | `title` |
| `HTMLHash` | `body_hash` fallback；MD5 hex |
| `FaviconHash` | favicon MD5 hex，但不能直接喂现行整数 `icon_hash` operator |
| `Response.HeaderMap` | `header` |
| `Response.Header.StatusCode` | `status` |
| `Response.Header.ContentLength` | 结果展示；现行 matcher 不消费 |
| `Response.Header.ContentType` | `content_type` |
| `Response.Header.Server` | `server`、当前 `banner` |
| `Response.Header.RedirectChain` | 可作 evidence；现行 zvas payload/Record 未消费 |
| `Response.Body` | `body`，并派生 `body_hash` |
| `ICP` | 资产展示；现行 matcher 不消费 |

zvas 已验证的适配层应视为兼容 fixture，而非在 GoMap 新建第二套字段翻译。最直接的复用点是让 GoMap matcher 接受自身 `HomepageResult`，并用 golden/compat tests 证明它产生与当前 zvas `Record` 相同的静态结果。

### 4.3 现有字段缺口

- `cert/TLS`：Record 和 matcher 支持，但当前 GoMap 首页结果/adapter 不提供。
- `favicon`：GoMap 是 MD5 hex；zvas `icon_hash` 是 decimal int。迁移不能把两者叫同一个 hash 而静默转换。
- `URL`：zvas Record 有但 matcher 未使用；新 evidence 可保留，兼容 matcher 不应突然让 `url=` 生效。
- `body truncated`：没有标志，无法区分“确定不命中”和“特征位于截断之后”。
- `version/category/confidence/evidence/rule_id`：GoMap 首页模型和 zvas match 输出都没有；而且 zvas 成功 HTTP 结果只持久化摘要，header/body/request 也不足以事后复算 evidence。
- `active request`：现有 payload 只有首页 GET 的展示性 `request_message`，不是可执行 probe DSL。`gomap_adapter.go:393-409,415-438`。

### 4.4 资产/网页结果映射约束

`task_unit_http_result` 是每个 HTTP probe unit 一行的首页事实表，`fingerprints` 是其增强字段，不是独立 finding 表。`000001_init_schema.up.sql:501-551`。

迁入 GoMap 后，zvas 仍需将 GoMap 输出映射到：

- task unit summary；
- `task_unit_http_result.fingerprints`；
- task record detail；
- snapshot/pool site asset 的 fingerprints；
- 关键字搜索。

若 GoMap 新增丰富 findings，zvas 可以另行决定是否扩展存储，但不能让原有 `[]string fingerprints` 消失或变成对象数组，否则现有数据库查询、DTO、前端和测试都会破约。

## 5. 职责迁入 GoMap 后的退役面与必须保持的契约

本节只列迁移约束，不给完整新方案。

### 5.1 应退役的 zvas 重复实现

当 GoMap 已能用同一静态语义处理 `HomepageResult` 后，以下代码会形成平行 matcher，应退役：

- `internal/center/webfingerprint/types.go`
- `internal/center/webfingerprint/parser.go`
- `internal/center/webfingerprint/matcher.go`
- `internal/center/repo/task_unit_http_fingerprint.go` 中规则加载、编译、Match 部分
- `TaskRepoPostgres.webFingerprintMatcherMu/webFingerprintMatcher` 缓存字段，`internal/center/repo/task_repo_postgres.go:29-42`

独立 runtime shell 也应在兼容窗口后退役，而不是承载新 active DSL：

- `internal/worker/engines/assets/process/fingerprint_web.go`
- process/listener module 中 `fingerprint-web` 注册：`internal/worker/engines/assets/process/modules.go:38-49`、`internal/worker/engines/assets/listener/modules.go:31-40`
- `RouteCodeWebFingerprint -> fingerprint-web` 绑定和空参数 validator：`internal/center/usecase/task_route_process_binding.go:15-22`、`engine_task_config_validator.go:62-70,128-134`

但这些不能无条件一次删除：当前 route catalog、历史 scan plan/snapshot、engine config 和已排队 task unit 仍可能引用它们。默认模板已经由测试锁定为不包含 standalone route。`internal/center/usecase/scan_task_usecase_test.go:1442-1455`。

### 5.2 必须保持或显式迁移的数据库契约

1. **必须保持** `task_unit_http_result.fingerprints jsonb not null default []` 及其 `[]string` 语义。`000001_init_schema.up.sql:501-551`。
2. **必须保持** `task_unit.result_json.fingerprints` 摘要兼容，至少旧消费者继续读到字符串数组。`task_repo_postgres.go:509-519`。
3. **必须保持** task/detail/asset DTO 的 `fingerprints []string`。`internal/platform/model/task.go:488-508`；`scan_task_record_repo.go:536-587`。
4. `web_fingerprint_rule` 是运行期用户数据，**不能直接 drop**。若 GoMap 接管规则资产，必须先定义导出、稳定 ID 补齐、校验、迁移状态和回滚；在此之前 CRUD/API 仍有数据所有权。
5. 当前 DB schema 没有 category/version/risk/confidence/rule ID result。新增列/表可以扩展，但不能把旧 product-name 数组解释成结构化证据。

### 5.3 必须保持或版本化的消息契约

`UnitResultEvent` 顶层字段必须保持。对于 `http_probe.homepage` 的 `Result`，至少保持：

`site_url/title/status_code/content_length/server/html_hash/favicon_hash/icp/path/protocol/port/banner/header_string/body_hash/content_type/request_message/response_header_text/response_header_map/response_body/expanded_asset_kind/expanded_display_name/expanded_normalized_key/expanded_source_type/expanded_confidence_level`，以及 URL 不同时才出现的 `response_site_url`。

来源证据：`internal/platform/contracts/events.go:46-60`；`internal/worker/engines/assets/process/gomap_adapter.go:346-412`。

若 GoMap 在 worker 内返回静态/主动结果，兼容键应仍为 `fingerprints: []string`；丰富 finding 应放在新、版本化字段中，不能替换旧键。Center 当前不会信任 event 中的 fingerprints，而是自行重算；迁移时必须明确单一权威来源并删除重算，避免结果分叉。

历史 standalone 契约 `stage/task_type/route_code = web_fingerprint`、topic `scan.fingerprint.web`、process `fingerprint-web` 仍存在于 `pkg/taskroute/task_route.go:15-20,38-45,88-115,198-217`。默认任务不再使用，不等于历史消息/配置可以无迁移删除。

### 5.4 必须保持或正式弃用的 API 契约

现行 `/api/v1/fingerprints*` 管理 API 和 DTO 已被前端生成客户端消费。`internal/center/http/router.go:142-148`；`web/src/api/generated/sdk.ts:5776` 起。

如果规则所有权迁入 GoMap：

- 不能悄悄把该 API 改成 GoMap probe 配置编辑器；
- 可保持为 legacy rule 管理/迁移入口，或经过正式版本化弃用；
- 导入导出必须保留当前 Chujiu 文本的往返能力，直到用户数据完成迁移；
- API 中的 `status` 仍是 enabled，不得复用为 HTTP status/risk。

### 5.5 禁止形成 zvas → GoMap 探针 DSL

**[约束] zvas 不应把数据库表达式拆解为“对哪个 path 发什么请求、用什么 matcher”的自定义 payload 再交给 GoMap。** 那会产生：

- zvas parser/validator 与 GoMap parser/validator 两套真值；
- active/passive operator 分叉；
- zvas route snapshot 固化 GoMap 内部执行细节；
- 每次 GoMap schema 演进都要求 zvas 消息迁移；
- 无法由其他 GoMap SDK 调用方复用同一规则执行链。

允许的边界是“高层扫描意图/预算 + 规则资产引用或标准规则输入 + HomepageResult”，由 GoMap 内部统一完成规则校验、静态匹配、active plan 和执行。zvas 只负责任务编排、授权、持久化和兼容输出。若传规则，传的是 GoMap 自己版本化的规则 schema/asset，不是 zvas 生成的 probe steps。

## 6. 对照 burp-finger passive + active + depth

对照事实均来自 `docs/research/2026-08-26-burp-finger-reference.md` 所固定的第一方源码链接。

### 6.1 可直接复用 zvas 流程的部分

| 能力 | zvas 已验证流程 | 对 GoMap 的约束 |
|---|---|---|
| Passive 输入 | 一次首页响应标准化为 title/header/body/hash/status/path 等 | 直接消费 `HomepageResult`，不要再次抓首页 |
| 规则加载 | 规则资产 → expressions → compiled matcher | loader/compile 与执行分离；兼容 importer 只做一次转换 |
| 组合 | expression 内显式布尔；产品内 any；产品间多命中 | 作为 legacy static profile 固化测试 |
| 确定输出 | product 去重并字典序排序 | 保持 `[]string` 兼容投影 |
| 结果主链 | 首页事实 + fingerprints 同步落库/输出 | GoMap 返回结果，zvas 保持现有映射 |
| 缓存思想 | 编译结果复用 | GoMap 可实现更深缓存，但缓存键必须是规则内容/版本，不应只用时间/count |

burp-finger 的被动响应 matcher 与 zvas 目的相同，但 operator 不同：burp-finger passive 把 `match` 当大小写不敏感 DOTALL regex，zvas 明确区分 contains/equal/regex。不能用 burp 行为覆盖 zvas 兼容语义。

### 6.2 最小扩展缺口

相对 zvas 静态流程，支持 burp-finger 风格 active+depth 至少缺：

1. **active rule metadata**：安全路径、method（MVP 可只 GET）、期望 status、匹配条件、risk；zvas `path` 当前只是 response path matcher，不能直接重解释为“发送请求”。
2. **probe planner**：从未被 passive 满足且允许 active 的规则生成请求；按规范化请求签名合并，一份响应喂给多个规则。
3. **depth/base-path 规则**：burp-finger 从触发 path 向父目录回溯；zvas 没有该概念。必须是显式新配置，不能改变 legacy `path=`。
4. **bounded executor**：caller context、单请求 timeout、整体 deadline、concurrency、RPS、max requests、max bytes、取消；burp-finger 自身缺总预算和严格 timeout，不能照搬。
5. **统一响应模型**：active 响应也转换成与 passive 相同的 matcher input，不能另写一个大小写/regex 不同的 active matcher。
6. **去重层**：目标/请求签名/probe plan/result evidence 的确定去重；不能照搬 burp-finger 进程全局、Clear 才清空的 Set。
7. **evidence/result**：至少保留 source(passive/active)、rule ID、URL/method/status、field/operator/pattern/hash；同时投影出旧 `[]string`。
8. **risk gate**：burp-finger 规则混有 `.git`、备份、日志和 traversal；不能默认纳入“应用指纹”安全流量。

### 6.3 不能凭空改动的既有 zvas 语义

以下是兼容 profile 的硬边界：

- 字符串 `=` 是大小写不敏感 contains，不是 exact 或隐式 regex；
- `~=` 才是 Go regex，且当前在 lowercased source/pattern 上执行；
- `protocol=` 是大小写不敏感全等；
- `path=` 是对当前 response path 的 contains；不是 active URL；
- expression 内显式 `! && || ()`；同 product 多 expression OR；
- 多 product 全部返回，产品名排序去重；
- `status=1` 是规则启用状态，expression 中 `status="200"` 才是 HTTP status；
- current output 是 product name，不得用新 category/version 替代；
- legacy `icon_hash` 是 decimal int 语义，即使它与当前 GoMap favicon MD5 不兼容，也应通过明确的新算法字段修复，不能静默改同名字段。

active 规则应是显式新 clause/schema 或经版本标识的扩展；不能根据“某条 legacy expression 出现 path”就自动发请求。

## 7. 文档、设计记录与 git 历史：事实、遗留、推断

### 7.1 已确认的历史决策

- `bd9691d042774181b9434872e5ffc4312bff5515`（2026-04-28）新增 inline homepage 设计：选择 Option C，即 worker 采集、Center 内联匹配；明确 active path、JS 跳转、独立结果表、rule ID/命中明细为 non-goals。`docs/superpowers/specs/2026-04-28-web-fingerprint-inline-homepage-design.md`。
- `71271f08b22241298fa85491b95d992d2ba1b583`（2026-04-29）一次提交落地 matcher、规则表/API、GoMap payload 标准化、Center cache、inline persistence 和测试。当前 `git blame` 显示 `task_unit_http_fingerprint.go` 全文件仍来自该提交。
- `cf128ac0b8cb46b17c2a21c47edd9f7e1740df4f`（2026-04-29）新增 `docs/design/19-web-fingerprint-matcher.md`，记录单等号 contains、大小写不敏感、布尔优先级和 product OR。
- 独立 `fingerprint-web` stub 早于 inline matcher：其主体可追溯到 `b6f1e8f90bb9dfc6df36f342e9c7e09376f14818`（2026-03-26）。`6800fde34eee57e63c98351e3cfab86c68d1479a`（2026-08-02）只给它增加空 `engine_params` 解码，并未实现匹配。

### 7.2 现行代码事实

- 默认任务模板/route plan 已由测试锁定不包含 `web_fingerprint`。`internal/center/usecase/scan_task_usecase_test.go:1442-1455`。
- route catalog、seed 分支、listener/process/topic 和 engine config 仍保留；自定义/历史 route 仍可调度 stub。`internal/center/repo/task_route_seed.go:65-74`；`task_route_seed_runtime.go:106-111`；`pkg/taskroute/task_route.go:198-217`。
- 静态 matcher 在 Center 生效；独立 worker process 不生效。
- 规则库在 Git 中为空，运行规则来自 DB/API。

### 7.3 历史设计与现行实现不一致处

| 设计/计划 | 现行代码 |
|---|---|
| 单条坏规则跳过并日志 | 坏 expression 可让整批编译失败，Center 静默空结果 |
| CRUD 后显式缓存失效 | 每次 match 查 DB `max(updated_at)+count` |
| API `/web-fingerprint-rules`、multipart import | API `/fingerprints`、JSON `{content}` |
| cert 是否支持留待 worker 稳定提供 | matcher switch 已支持，但 payload 不提供 |
| standalone route 从默认主链移除、仅兼容保留 | 已满足默认移除，但可配置 runtime shell 仍完整注册且只返回 stub |
| 测试覆盖所有 operator/YAML/cache invalidation | 当前只有 3 个 matcher 单测和 1 个主要 inline 集成测试，覆盖不足 |

### 7.4 只能作为推断的设计约束

- **[推断]** `fingerprint-web` 的存在是历史任务路由兼容壳，不是“未来 active 必须走 zvas 独立 DSL stage”的架构决定；现行默认模板和 stub 行为反而证明它没有业务实现。
- **[推断]** 把静态 matcher 迁入 GoMap 符合原始“一次采集、单一事实链”的目标，只要 zvas 不再重算且保持结果契约。
- **[推断]** 规则所有权迁移比 matcher 代码移动更难：当前用户规则只存在运行数据库，且没有 stable IDs/category/version/risk。应先盘点/验证真实 DB 资产；源码不能替代该数据迁移调查。
- **[推断]** active SDK 的兼容基线应由 zvas 测试语义生成一组 GoMap cross-implementation fixtures；不能把 `docs/design/19` 当完整规范，因为它未记录 `type` 特例、坏规则整批失败、favicon 类型不兼容和缓存行为。

## 8. 面向后续设计评审的硬约束清单

1. 只允许一个 matcher/operator 真值实现；迁移完成后 zvas 不保留平行 parser/evaluator。
2. GoMap 直接消费 `HomepageResult`；passive 不重复发首页请求。
3. legacy 静态语义必须版本化冻结，并以 zvas cross-tests 验证。
4. active 是显式 opt-in；legacy `path` 不自动生成请求。
5. probe 规划、去重、预算、取消和风险控制归 GoMap SDK；zvas 不生成探针 DSL。
6. GoMap 丰富 finding 必须能稳定投影为 zvas 现有、排序去重的 `fingerprints []string`。
7. `task_unit_http_result.fingerprints`、消息标准字段和 `/fingerprints` 用户数据契约必须保持或经过正式迁移/弃用。
8. hash 必须带算法；不得把 favicon MD5 hex 与 decimal Murmur/legacy `icon_hash` 混用。
9. body 截断/读取上限必须成为显式 evidence 状态；否则负匹配不可靠。
10. 规则加载时必须能报告具体 rule ID/错误；但在决定新错误策略前，不能声称它与 zvas 当前“整批失败且静默降级”兼容。
11. 不能承诺 category/version/confidence/risk 已由 zvas 验证；这些都是新扩展字段。
12. 在读取真实 `web_fingerprint_rule` 数据并做离线兼容评估前，不能宣称迁移完成或规则质量达标。
