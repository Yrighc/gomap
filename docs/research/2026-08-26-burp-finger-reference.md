# burp-finger 对 GoMap 主动应用指纹能力的源码参考研究

- 研究日期：2026-08-26
- 研究对象：[`238469/burp-finger`](https://github.com/238469/burp-finger)
- 固定基线：[`107d20dd42b179d1e76853415283db78e6f10ad0`](https://github.com/238469/burp-finger/tree/107d20dd42b179d1e76853415283db78e6f10ad0)
- GoMap 对照基线：[`e41cb62efc03ed8916306ef2c81a31c966571df0`](https://github.com/Yrighc/gomap/tree/e41cb62efc03ed8916306ef2c81a31c966571df0)
- 方法：临时目录只读克隆；静态阅读 README、Java 源码、内置 JSON 规则和 Git 提交；未运行 Maven、测试、构建脚本、JAR 或插件。

本文用以下标记严格区分结论性质：

- **[事实]**：可由固定 commit 的第一方文件直接验证。
- **[推断]**：从多处源码行为推导，但项目没有明确承诺。
- **[建议]**：面向 GoMap 的设计选择，不代表 burp-finger 的行为。

## 结论摘要

1. **[事实]** burp-finger 是“Burp Proxy 请求/响应上的被动匹配器 + 被响应流量触发的路径字典式主动 GET 探测器”，不是独立扫描器，也没有学习/生成新指纹的能力。扩展只注册 Montoya Proxy request/response handler；主动扫描由代理响应触发。[`FingerExtension.java:28-47`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/FingerExtension.java#L28-L47) [`PassiveScanner.java:49-101`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L49-L101)
2. **[事实]** 它能输出产品/类别标签和命中规则描述，但没有产品版本字段、捕获组提取、置信度模型或可复核的原始证据模型；“版本判断”没有系统实现。[`Fingerprint.java:9-31`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L9-L31) [`MatchResult.java:6-21`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchResult.java#L6-L21)
3. **[事实]** 固定基线内置库静态计数为 **560 个 fingerprint、779 条 rule**，而 README 声称“2000+ 指纹规则”；应以实际 JSON 为准。779 条中 `hash/body/header` 分别为 `517/239/23`，96 条带 `path`，40 条带 `status`，8 条带 `description`。[内置规则文件](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json) [README 声明](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/README.md#L24-L35)
4. **[事实]** 同一个 `match` 在被动引擎中一律被当作大小写不敏感、DOTALL 正则；主动引擎却做大小写敏感的字面 `contains`。这不是可直接照搬的稳定规则语义。[`MatchingEngine.java:126-194`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L126-L194) [`ActiveScanner.java:330-359`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L330-L359)
5. **[建议]** GoMap 的最小可行接入点不是 TCP fingerprint stage 内部，而是 `pkg/assetprobe.Scanner` 上新增独立的应用指纹入口：先纯函数匹配现有 `HomepageResult`，再按规则生成受 `context.Context`、并发、RPS、单请求超时、总请求数和风险级别约束的 HTTP 探测；结果保持为独立 `ApplicationScanResult`，不要塞入 `PortResult`。

## 1. 项目真实能力边界

### 1.1 被动匹配

- **[事实] 流量来源仅为 Burp Proxy。** 扩展注册 `ProxyRequestHandler` 和 `ProxyResponseHandler`，没有注册 Burp Scanner/Audit、Repeater 或通用 HTTP handler。[`FingerExtension.java:32-47`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/FingerExtension.java#L32-L47)
- **[事实] 请求和响应都会被送入同一个 `MatchingEngine`。** 请求匹配请求 headers/body/path；响应匹配响应 headers/body/bytes/status/path。[`PassiveScanner.java:49-79`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L49-L79) [`MatchingEngine.java:23-58`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L23-L58)
- **[事实] 响应按完整 URL 会话内去重，请求没有对应去重。** `scannedUrls` 只在 `handleResponseReceived` 查询和写入；README 的“同一 URL 仅一次匹配”不能无条件套到请求处理。[`PassiveScanner.java:35-39`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L35-L39) [`PassiveScanner.java:68-76`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L68-L76)
- **[事实] 带 `path` 的规则也可被动命中。** 路径限定会在匹配前执行，因此“带 path = 纯主动规则”只是规则管理 UI 的分类约定，不是匹配引擎隔离。[`MatchingEngine.java:60-72`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L60-L72) 项目曾提交、后删除的第一方规格也明确称 `path` 可用于主动/被动：[`docs/rules-spec.md@d80ab7c:21-28`](https://github.com/238469/burp-finger/blob/d80ab7ca96cdd4783597e63f3660ffdf7184b285/docs/rules-spec.md#L21-L28)。

### 1.2 主动探测

- **[事实] 主动探测并非端口发现或爬虫。** 它从当前 Proxy 响应的 `HttpService + path` 出发，枚举当前目录及父目录，再把规则的 `path` 拼接到这些基准目录；hash 规则默认探测 `/favicon.ico`。[`PassiveScanner.java:81-101`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L81-L101) [`ActiveScanner.java:97-145`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L97-L145) [`ActiveScanner.java:156-179`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L156-L179)
- **[事实] 请求固定为 GET。** 请求行、Host、固定 Chrome UA 和 `Connection: close` 被硬编码；schema 无 method/body/request headers 字段。[`ActiveScanner.java:181-212`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L181-L212)
- **[事实] 主动路径覆盖敏感文件、管理端点和漏洞测试。** 例如 `/.git/HEAD`、备份文件、Actuator，以及编码后的路径穿越 payload；它不只是无害“应用识别”。[`fingerprints.json:6710-6791`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json#L6710-L6791)
- **[推断]** 因此项目更准确的边界是“应用/组件识别 + 敏感面暴露探测”的混合体；GoMap 若只设计应用指纹，不应默认引入漏洞 payload 和仅凭 200 的敏感文件规则。

### 1.3 指纹提取与版本判断

- **[事实] 指纹提取仅指从命中规则映射出静态 `name/type`。** `MatchResult` 只持有 `Fingerprint` 与 `matchedRule`；没有从响应学习新规则、提取特征模板或聚类的代码。[`MatchResult.java:6-21`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchResult.java#L6-L21)
- **[事实] 没有版本判断模型。** fingerprint 顶层仅 `name/type/rules`，rule 仅 `location/field/path/match/status/hash/description`；正则只调用 `find()`，不读取捕获组。[`Fingerprint.java:9-31`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L9-L31) [`Rule.java:11-56`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Rule.java#L11-L56) [`MatchingEngine.java:176-194`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L176-L194)
- **[推断]** 指纹名称中偶尔携带版本文本不等于版本识别；下游无法把产品与版本拆成稳定字段。

## 2. 规则 schema 与真实命中语义

### 2.1 固定基线规则库静态画像

以下数字由固定 SHA 的 `fingerprints.json` 进行 JSON 解析后计数；它们不是 README 宣传数字：

| 项目 | 数量/取值 |
|---|---:|
| fingerprint | 560 |
| rule | 779 |
| `location=hash` | 517 |
| `location=body` | 239 |
| `location=header` | 23 |
| 带 `path` | 96（95 个唯一字符串） |
| 带 `status` | 40，全部为 200 |
| 带 `description` | 8 |
| status-only rule | 32 |
| `location=status` | 0 |
| hash rule 显式 `path` | 0（517 条均回退 `/favicon.ico`） |

**[事实]** 实际 JSON 中 rule 没有模型之外的未知字段；顶层均为 `name/type/rules`。固定文件可定位于：[规则文件全量](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json)。

### 2.2 字段

| 层级 | 字段 | 实际语义 |
|---|---|---|
| Fingerprint | `name` | 输出标签、更新合并键；代码未强制全局唯一。内置库实际存在重名 `Jenkins`、`GraphQL`。 |
| Fingerprint | `type` | 展示分类，无枚举校验。实际库以 CMS 为主。 |
| Fingerprint | `rules` | rule 之间 OR；实现会返回每一条命中的 rule，展示时再按 fingerprint name 压缩。 |
| Rule | `location` | 匹配 `header/body/hash/status`；`path` 不是引擎 switch 的 location，而是前置限定/主动探测地址。 |
| Rule | `field` | header 名；为空时逐个匹配完整 `Header.toString()`。 |
| Rule | `path` | 被动时为当前 path 限定；主动时为 GET 探测路径。 |
| Rule | `match` | 单字符串或数组；数组内 AND。被动与主动的 operator 不一致，见下文。 |
| Rule | `status` | 对响应状态做 AND；请求匹配时状态码传 0，因而校验被跳过。 |
| Rule | `hash` | 期望的 Shodan 风格 MurmurHash3 十进制字符串或 MD5 hex。 |
| Rule | `description` | 仅作为展示说明/风险文本，不参与匹配。 |

字段定义和 OR/AND 注释见 [`Fingerprint.java:26-31`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L26-L31)、[`Rule.java:11-56`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Rule.java#L11-L56)。真实 switch 只接受 `header/body/hash/status`：[`MatchingEngine.java:74-93`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L74-L93)。

### 2.3 AND、OR、路径和状态

- **[事实] rule 列表是 OR，单条 rule 的条件是 AND。** 一个 fingerprint 的任一 rule 命中即可产出结果；同一 rule 中 path、status、所有 match 或 hash 必须通过。[`Fingerprint.java:26-31`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L26-L31) [`MatchingEngine.java:30-37`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L30-L37)
- **[事实] 多个 match 是 AND。** header 的多个 pattern 可分别命中同名 header 的不同实例；不要求落在同一行。body 则都要在整段 body 中找到。[`MatchingEngine.java:126-174`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L126-L174)
- **[事实] path 被动匹配是去 query、补前导 `/`、去尾 `/` 后大小写不敏感的精确相等。** 不是前缀、glob 或 regex。[`MatchingEngine.java:96-111`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L96-L111)
- **[事实] 请求侧的 status 语义有漏洞。** 请求进入引擎时 status=0，前置 status 检查明确跳过；若自定义规则使用 `location=status`，它会在请求上无条件命中。内置库没有 `location=status`，但扩展 schema 允许用户添加。[`MatchingEngine.java:44-53`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L44-L53) [`MatchingEngine.java:69-90`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L69-L90)

### 2.4 正则、关键词与 hash

- **[事实] 被动 matcher 没有显式 `operator`。** 每个 `match` 都先按 Java regex 编译，flags 为 `CASE_INSENSITIVE | DOTALL`；只有编译异常才回退到大小写敏感 `contains`。[`MatchingEngine.java:132-194`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L132-L194)
- **[事实] 主动 matcher 对同一字段只做大小写敏感 `body.contains`，完全不执行 regex，也不按 `location=header` 读取响应头。** [`ActiveScanner.java:330-359`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L330-L359)
- **[事实] 内置规则已经暴露该歧义。** 例如 ASP.NET 的 `.+` 明显依赖 regex，而 Git Exposure 的 `[core]` 在被动 Java regex 中表示“任一 c/o/r/e 字符”，主动 `contains` 才表示字面 `[core]`。[`fingerprints.json:48-66`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json#L48-L66) [`fingerprints.json:6524-6535`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json#L6524-L6535)
- **[事实] hash 对整个当前响应 body 计算。** 先比较 Shodan 风格的 Base64+换行 MurmurHash3_32 十进制，再比较 MD5；被动模式不会先确认当前响应是 favicon。[`MatchingEngine.java:114-123`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchingEngine.java#L114-L123) [`HashUtils.java:12-54`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/utils/HashUtils.java#L12-L54)

### 2.5 置信度与命中语义

- **[事实] 没有 score/confidence/severity/negative matcher。** 命中是二值的“一条 rule 全部条件成立”；不同 rule 没有权重，多个 rule 同时命中不会提高置信度。[`Fingerprint.java:26-31`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L26-L31) [`MatchResult.java:6-21`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/engine/MatchResult.java#L6-L21)
- **[事实] status-only 规则把“HTTP 200”直接当作命中。** 内置 Backup Files、日志、数据库文件等大量规则只要求目标路径返回 200；这无法排除通用 200 fallback，仅靠全局 body 黑名单和空 body 过滤降噪。[`fingerprints.json:6730-6759`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/fingerprints.json#L6730-L6759) [`ActiveScanner.java:214-234`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L214-L234)

## 3. 请求流量、主动请求生成、去重与资源控制

### 3.1 流程图

```text
Burp Proxy request
  -> MatchingEngine(request headers/body/path)
  -> UI + finger_results.json

Burp Proxy response
  -> exact URL 会话去重
  -> MatchingEngine(response headers/body/hash/status/path)
  -> UI + finger_results.json
  -> active enabled?
     -> HttpService + normalized triggering path 去重
     -> current path 向父目录回溯并按 scanDepth 筛选
     -> 每个 base directory 构建 unique rule-path map
        -> hash 无 path => /favicon.ico（仅 root）
        -> 其他 path => base + rule.path
     -> fixed thread pool + global RateLimiter
     -> 固定 GET
     -> 全局过滤 -> 对该 path 的相关 rules 逐条匹配
     -> UI + finger_results.json
```

### 3.2 生成与去重

- **[事实] 三层扫描去重：**
  1. 被动响应 `scannedUrls`: 完整 URL；
  2. 触发层 `scannedActivePaths`: `HttpService + 去 query/尾斜杠 path`；
  3. 主动层 `alreadyScannedPaths`: `base URL + parent/base path`。
  另有 UI 级 `host + fingerprint name + matchedField` 去重。[`PassiveScanner.java:35-39`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L35-L39) [`PassiveScanner.java:68-101`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L68-L101) [`ActiveScanner.java:31-32`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L31-L32) [`FingerTableModel.java:10-29`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/FingerTableModel.java#L10-L29)
- **[事实] 相同探测路径会在一个 base 上合并成一次 HTTP 请求。** `Map<String,List<Fingerprint>>` 按 path 分组；固定库根目录理论上生成 95 个唯一显式 path 加 `/favicon.ico`，即最多 96 个唯一请求路径（过滤和缓存前）。[`ActiveScanner.java:160-184`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L160-L184)
- **[事实] 去重集合只在用户 Clear 时清空。** Clear 同时清 UI 和扫描缓存。[`PassiveScanner.java:168-181`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L168-L181) [`FingerTabPanel.java:35-43`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/FingerTabPanel.java#L35-L43)
- **[事实] cache 在深度校验前写入。** 超出当前 scanDepth 的 base 也被标记已扫，随后提高深度不会自动补扫，除非 Clear。[`ActiveScanner.java:127-145`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L127-L145)

### 3.3 调度、限速、超时和停止

| 能力 | 实际实现 | 边界/缺口 |
|---|---|---|
| 并发 | `Executors.newFixedThreadPool(threadCount)`，默认 10 | 外层 scan task 和内层 probe task 共用同一池；无队列上限。 |
| 限速 | 单个 Guava `RateLimiter`，每次实际请求前 `acquire()`，默认 10 RPS | 进程/ActiveScanner 级，不是 per-host；阻塞式 acquire。 |
| 请求超时 | `api.http().sendRequest(request)` | 主动扫描代码未配置单请求 timeout/deadline。 |
| 总预算 | 无 | 无 max requests、max bytes、total deadline。 |
| 规则停止 | 无 | 命中后不会停止同产品或同目标剩余 probes。 |
| UI 开关 | 只在 Proxy 响应触发前检查 | 关闭后已排队/运行任务不会取消。 |
| 卸载 | `shutdown()`，等待 5 秒后 `shutdownNow()` | 没有 `context.Context`；底层 Montoya 调用能否响应线程中断不由本项目保证。 |

证据：线程池、rate limiter 和卸载逻辑见 [`ActiveScanner.java:41-84`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L41-L84)；请求前限速及无显式 timeout 的发送点见 [`ActiveScanner.java:181-212`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L181-L212)；默认值见 [`ScannerConfig.java:16-34`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/ScannerConfig.java#L16-L34)。

## 4. 规则加载、更新与扩展

### 4.1 加载顺序

- **[事实]** 外部规则固定为 JAR 同目录的 `fingerprints.json`；无法取得 JAR 路径时退回当前工作目录。[`RuleLoader.java:33-46`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/rules/RuleLoader.java#L33-L46)
- **[事实]** 外部文件存在且成功解析时完全取代内置库；外部不存在、解析失败或为空时读取 classpath `/rules/fingerprints.json`，并写出为外部文件。[`RuleLoader.java:53-94`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/rules/RuleLoader.java#L53-L94)
- **[事实]** `rules.index` 仅包含 `fingerprints.json`，但源码没有读取它；loader 直接硬编码资源路径，因此它不是实际扩展机制。[`rules.index`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/resources/rules/rules.index) [`RuleLoader.java:73-83`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/rules/RuleLoader.java#L73-L83)

### 4.2 更新和本地扩展

- **[事实]** UI 支持导入（直接 append）、导出、文本 JSON 新增/编辑/删除，并立即整体覆写外部文件；新增/编辑只校验 name 非空，没有 schema、正则、路径或唯一性验证。[`RuleManagerPanel.java:286-320`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/RuleManagerPanel.java#L286-L320) [`RuleManagerPanel.java:457-515`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/RuleManagerPanel.java#L457-L515)
- **[事实]** 在线更新 URL 可配置，GET 使用 10 秒 connect timeout 和 30 秒 request timeout。合并以 fingerprint `name` 精确匹配：远端同名整体替换本地，远端新增则 append，远端不存在的本地 name 保留。[`RuleManagerPanel.java:322-399`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/RuleManagerPanel.java#L322-L399)
- **[事实]** 更新没有签名、checksum、schema version、规则来源、原子临时文件/回滚或重复 name 冲突策略；未知 JSON 字段因 `@JsonIgnoreProperties(ignoreUnknown=true)` 被静默忽略。[`Fingerprint.java:9-10`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Fingerprint.java#L9-L10) [`Rule.java:11-12`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/model/Rule.java#L11-L12)
- **[建议]** GoMap 若支持在线规则更新，应把“获取、验签/校验、编译、原子切换、回滚”与扫描热路径分离；MVP 更适合先做随二进制发布的版本化内置规则 + 显式本地文件覆盖，不做运行时远端更新。

### 4.3 提交记录提供的成熟度证据

- **[事实]** 主体实现和测试最初集中进入提交 [`1713370`](https://github.com/238469/burp-finger/commit/17133705067487e615aeeef16773c96c015dccf8)。
- **[事实]** 正则、风险描述和规则规格在提交 [`d80ab7c`](https://github.com/238469/burp-finger/commit/d80ab7ca96cdd4783597e63f3660ffdf7184b285) 加入；该提交同时删除 `MatchingEngineTest`、`ActiveScannerTest`、`HashUtilsTest`。
- **[事实]** 紧随其后的 [`1652245`](https://github.com/238469/burp-finger/commit/1652245f03deec033a6d1e187c580e7620cd86b7) 又删除了全部 docs；固定基线当前树没有测试源码。
- **[推断]** 这些记录不能证明代码错误，但说明正则/主动语义缺乏仓库内持续回归证据；GoMap 不应把该实现行为当作经过验证的兼容规范。

## 5. 输出模型与证据保留

### 5.1 实际输出

- **[事实] UI 明细模型**：`url/name/type/method/matchedField/timestamp`；`method` 为 Active、Passive(Request)、Passive(Response)，`matchedField` 是拼出的规则位置/字段/pattern/path/description 文本。[`ScanResult.java:5-29`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/ScanResult.java#L5-L29) [`PassiveScanner.java:103-151`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L103-L151) [`ActiveScanner.java:247-282`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L247-L282)
- **[事实] UI 聚合模型**：按 origin 聚合 fingerprint/type/method；明细去重键为 `host + name + matchedField`。[`FingerTableModel.java:10-60`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/ui/FingerTableModel.java#L10-L60)
- **[事实] 文件持久化**：当前工作目录 `finger_results.json`，每次 append `url/timestamp/fingerprints[{name,type}]`。不保存 method、matched rule、status、headers/body/hash、请求或错误。[`ResultPersistence.java:15-61`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/utils/ResultPersistence.java#L15-L61)

### 5.2 证据边界

- **[事实]** UI 只保留规则描述，不是“响应中实际命中的值”。同 fingerprint 多条 rule 命中时，`processMatches` 按 name 只展示循环中的第一条；文件层更进一步只保留 name/type。[`PassiveScanner.java:116-151`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L116-L151)
- **[推断]** 对误报复核、版本提取、规则质量统计、扫描重放和审计而言，该输出不足。
- **[建议]** GoMap finding 至少保留：稳定 `rule_id`、产品 ID/name/category、可选 version、confidence、passive/active、请求 method+URL、response status、location/field/operator、期望 pattern/hash、受长度限制的实际命中片段或实际 hash、response body hash、时间以及 probe error。默认不要持久化完整敏感 body；证据片段应限长并可关闭。

## 6. GoMap 可复用与不应照搬的部分

### 6.1 可复用的设计思想

1. **[建议] 统一规则，分离 passive matcher 与 active scheduler。** 同一产品可同时有首页证据和专用路径证据，但两条执行路径必须共享完全一致的 matcher operator 语义。
2. **[建议] 按规范化请求签名分组。** burp-finger 按 path 合并一次请求；GoMap 应扩展为 `scheme/host/port/method/path/query/body-hash/headers-profile`，一份响应供多个 rule 评估。
3. **[建议] rule 内 all、产品内 any。** 这是简单可解释的 MVP；以后再显式增加 `all/any/not` 组合树，而不是依赖数组层级猜语义。
4. **[建议] favicon 同时兼容 MD5 与 Shodan Murmur。** burp-finger 的 Murmur 算法实现可作为互操作参考，但 GoMap 应在证据中标明算法。[`HashUtils.java:12-54`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/utils/HashUtils.java#L12-L54)
5. **[建议] 内置规则 + 本地覆盖。** 概念可复用；规则必须有 schema version、稳定 ID、验证器和来源元数据。
6. **[事实] 许可证允许使用/修改/分发，但要求保留版权和许可声明。** [`LICENSE:1-21`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/LICENSE#L1-L21)

### 6.2 Burp 专属

以下部分不能直接进入 GoMap SDK：

- Montoya `InterceptedRequest/InterceptedResponse/HttpService/api.http()`；
- Proxy handler 注册和“浏览流量触发扫描”的生命周期；
- Swing UI、Burp extension persistence、右键生成 Nuclei 命令；
- 会话内全局 Set cache 和插件卸载线程池语义。

这些依赖在入口和 scanner 中直接出现：[`FingerExtension.java:32-47`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/FingerExtension.java#L32-L47)、[`PassiveScanner.java:27-47`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/PassiveScanner.java#L27-L47)、[`ActiveScanner.java:20-46`](https://github.com/238469/burp-finger/blob/107d20dd42b179d1e76853415283db78e6f10ad0/src/main/java/com/finger/burp/scanner/ActiveScanner.java#L20-L46)。

### 6.3 不应照搬

- **隐式正则**：必须显式 `operator: keyword|regex|md5|murmur3`，加载时预编译并报错；不能“正则失败再 contains”。
- **主动/被动语义不一致**：同 rule 在两种模式必须得到同样结果。
- **status-only=产品命中**：最多作为 low-confidence availability evidence，并要求 soft-404/基线响应差异判断。
- **高风险 path 默认启用**：路径穿越、备份下载、日志/配置暴露应放入独立 risk class，默认关闭并要求显式授权。
- **无取消/无总预算**：GoMap 必须让每个请求继承 caller `context.Context`，并有 per-request timeout、overall deadline、RPS、concurrency、max probes、max body bytes。
- **无证据结果**：不能只输出 product name。
- **以 name 做更新主键**：应使用稳定、命名空间化 rule/product ID。
- **全量搬规则库**：除实现语义问题外，仓库没有逐条规则来源/质量元数据；即使项目整体为 MIT，也应逐批审查、测试、保留归属，而不是无差别导入 517 个 hash 和敏感 payload。

## 7. 对照 GoMap 现状与最小可行接入点

### 7.1 `HomepageResult` 已有可直接消费的被动特征

**[事实]** GoMap SDK 已将首页结果建模为 URL、Title、HTML MD5、favicon hash、ICP、状态、Content-Length、Content-Type、Server、redirect chain、可选完整 HeaderMap 和 Body。[`types.go:207-249`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/types.go#L207-L249)

**[事实]** `DetectHomepageWithOptions` 已把 crawler 采集结果转换为该公开模型；`IncludeHeaders` 决定完整 HeaderMap，`MaxBodyBytes` 决定返回 body 截断。[`scanner.go:455-498`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/scanner.go#L455-L498)

**[事实]** 底层首页请求已具备 HTTP client 超时、2 MiB body 上限、响应头采集、HTML MD5 和 favicon MD5；但它通过 `http.NewRequest`/内部 `context.Background()`，没有把 SDK caller 的 context 传到底层请求。[`crawlweb.go:41-116`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/internal/crawlweb/crawlweb.go#L41-L116) [`crawlweb.go:145-194`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/internal/crawlweb/crawlweb.go#L145-L194)

由此得到：

- **[建议]** 第一阶段被动 matcher 直接消费 `HomepageResult`，不要再次请求首页。
- **[建议]** 启用 header rule 时由应用指纹入口内部确保首页采集 `IncludeHeaders=true`；body matcher 应记录输入是否被截断，避免把“未命中”误当作确定否定。
- **[建议]** GoMap 当前 `FaviconHash` 是原始 icon MD5，不是 burp-finger 的 Shodan Murmur；MVP 可直接支持 MD5，若兼容 Murmur 规则则需在 crawler 内保留 icon bytes/另算 Murmur，不能把两个值混作同一种 hash。[`crawlweb.go:179-190`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/internal/crawlweb/crawlweb.go#L179-L190)

### 7.2 TCP fingerprint stage 是边界参照，不是应用规则插入点

**[事实]** GoMap TCP 流程先并发发现开放端口，再选取至多 `MaxFingerprintPorts` 个开放端口执行深度服务识别；结果写入 `PortResult.Service/Version/Banner/TLS evidence`，并记录已识别/跳过数量。[`scanner.go:202-220`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/scanner.go#L202-L220) [`scanner.go:699-790`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/scanner.go#L699-L790) [`types.go:177-205`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/types.go#L177-L205)

- **[建议]** 借鉴它的 stage 思路：先廉价采集/被动匹配，再对确认是 HTTP(S) 的资产做有上限的主动应用 fingerprint stage。
- **[建议]** 不要把 HTTP 应用 finding 放入 `PortResult`。TCP stage 回答“端口上的服务/版本”；应用 stage 回答“某个 origin/path 暴露的产品及证据”，生命周期和 cardinality 都不同。
- **[建议]** 若未来由端口扫描自动衔接，只在 `PortResult.Service` 为 `http/https` 或明确允许的端口上构造 origin，然后调用独立应用 API；不要让 TCP worker 自己发几十个 HTTP 路径请求，否则会破坏 `PortConcurrency/PortRateLimit/MaxFingerprintPorts` 的可解释性。

### 7.3 SDK 边界

**[事实]** `pkg/assetprobe` 自述为可被其他 Go 项目直接 import 的导出库，公开入口是可复用 `Scanner`；`Options` 和 request types 承载并发、速率、超时等调用契约。[`pkg/assetprobe/README.md:1-22`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/README.md#L1-L22) [`types.go:69-145`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/types.go#L69-L145)

**[事实]** 现有目录爆破虽已有 worker pool 和首页 HTMLHash fallback 去重，但它不接收 context/RPS/timeout，且 `PathResult` 不保留 body/header/matcher evidence，因此不能原样充当主动指纹 executor。[`scanner.go:1330-1412`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/scanner.go#L1330-L1412) [`types.go:250-290`](https://github.com/Yrighc/gomap/blob/e41cb62efc03ed8916306ef2c81a31c966571df0/pkg/assetprobe/types.go#L250-L290)

### 7.4 推荐的最小可行接入

**[建议] 公共入口：** 在 `pkg/assetprobe` 的 `Scanner` 上增加一个独立方法，而不是修改 `Scan`/`PortResult`：

```go
func (s *Scanner) DetectApplications(
    ctx context.Context,
    req ApplicationScanRequest,
) (*ApplicationScanResult, error)
```

最小 `ApplicationScanRequest` 应包含：

- `URL`；
- 可选已有 `Homepage *HomepageResult`（避免调用链重复抓首页）；
- `Active`（默认 false，显式开启才发额外流量）；
- `Concurrency`、`RateLimit`、`Timeout`、`MaxRequests`、`MaxBodyBytes`；
- `RiskPolicy`（MVP 仅 `safe`，不允许 traversal/backup/log-download）；
- 可选本地 `RulesFile`，不做在线更新。

最小 `ApplicationScanResult` 应与 TCP/目录模型分离：

```text
URL / Homepage
Findings[]:
  ProductID, Name, Category, Version?, Confidence
  Evidence[]:
    RuleID, Source(passive|active), Method, URL, Status
    Location, Field, Operator, Pattern, MatchedSnippet?, ActualHash?
Meta:
  Planned, Sent, Matched, Skipped, Failed, StoppedReason
```

**[建议] 内部执行顺序：**

1. 若 request 带 `Homepage`，直接使用；否则调用可传播 caller context 的首页 fetch，并采集 headers/body/favicon MD5。
2. 纯函数 `matchHomepage(home, compiledRules)` 完成零增量流量的 passive findings。
3. 仅从仍需确认且 risk=safe 的 active clauses 生成 probe plan；按完整请求签名去重，一次响应喂给所有相关 clauses。
4. 统一 bounded HTTP executor：继承 ctx，单请求 timeout，固定全局 concurrency/RPS/max requests/max bytes；ctx 取消立即停止排队任务。
5. 命中产品的高置信规则后可按规则策略停止该产品剩余 probes，但不能误停其他共享同响应的 matcher。
6. 返回 findings 和 probe meta；不在库层写文件、不依赖 UI，由 CLI/SDK caller 决定序列化。

### 7.5 MVP 规则子集和 schema 决策

**[建议] 第一版只支持：**

- passive：`header/body/favicon_md5`；
- active：`GET + normalized absolute path + expected status + header/body keyword|regex|md5`；
- 组合：clause 内 `all`，product 内 `any`；
- version：可选、显式 `extract` regex group；没有 extraction 就返回空，不从 product name 猜；
- confidence：规则静态等级（例如 low/medium/high）并在 finding 中保留，不做不透明加权；status-only 不能高于 low；
- 每条规则必须有 `schema_version/rule_id/product_id/source/risk`；operator 显式，正则加载时编译。

**[建议] 第一版明确不支持：**

- Proxy 流量监听、父目录递归、任意 POST/body、动态在线规则更新；
- 路径穿越、备份/日志/数据库下载等高风险 payload；
- 仅凭 200 的“产品确认”；
- 将所有无 path hash 规则对任意响应 body 计算；
- 从 burp-finger 全量导入规则。

这条接入线最大化复用 GoMap 已有首页特征和 `Scanner/context/result` SDK 形态，同时把主动流量预算、证据与 TCP 服务识别保持为可测试的独立 stage。

## 8. 最终判断

- **[事实]** burp-finger 提供了一个紧凑可定位的参考实现：代理流量触发、统一 JSON 产品规则、路径分组、线程池、RPS、favicon hash 和本地/在线规则管理。
- **[事实]** 它不提供可直接移植的版本识别、置信度、证据留存、请求 timeout/cancel、风险分级或一致 matcher 语义；当前规则库还混合了应用识别与敏感/漏洞探测。
- **[推断]** 其最大参考价值是“需要哪些模块和控制面”的负样本/原型证据，而不是可直接作为 GoMap 规则协议或扫描核心的成熟实现。
- **[建议]** GoMap 先交付“现有 HomepageResult 被动匹配 + 少量 safe active GET + 完整 evidence + bounded scheduler”的 SDK 能力；待误报率、取消语义和规则验证稳定后，再扩展版本提取、更多 method 和受控风险探测。
