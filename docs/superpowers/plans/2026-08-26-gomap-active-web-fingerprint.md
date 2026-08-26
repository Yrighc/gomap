# GoMap Active Web Fingerprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 GoMap 中新增独立的 `Scanner.DetectApplications` 能力，完成首页静态匹配、受限主动 GET、父目录深度识别和最小证据返回。

**Architecture:** `pkg/assetprobe` 只暴露请求、结果和单一方法；规则编译、表达式求值、路径规划、HTTP 调度和产品聚合全部收敛到 `internal/appfingerprint` 深模块。静态首页与主动响应转换为同一种 `Record`，并由同一个表达式引擎匹配；`internal/crawlweb` 只增加 context-aware 的受限抓取能力，不改变端口扫描主链。

**Tech Stack:** Go 1.24.6、标准库 `encoding/json`/`net/http`/`regexp`、`golang.org/x/time/rate`、`embed.FS`、`httptest.Server`。

## Global Constraints

- 当前实施范围只修改 GoMap；不得修改、启动、测试或依赖 `../zvas`。
- 实施必须在 `feat/*` 隔离 worktree 分支进行；开发与任务复审子代理固定使用 `gpt5.6-terra`。
- 不修改 `Scanner.Scan`、`ScanResult`、TCP/UDP 服务指纹和端口扫描成本。
- 公开结果只包含 `URL`、`Homepage`、`Products`；不得增加 Meta、zvas 兼容投影、应用版本或置信度。
- 主动请求只允许同 origin、无认证、无 request body 的安全 GET；不得支持漏洞、敏感文件、备份、日志、配置和数据库探测。
- `Depth=0` 只扫描输入 URL 基准目录；`Depth=N` 最多向上回溯 N 级父目录，不发现未知子目录。
- 静态和主动响应必须共享同一个 matcher；不得实现第二套 active matcher。
- 默认值固定为：`Depth=0`、`Concurrency=10`、`RateLimit=10 RPS`、`Timeout=5s`、`MaxRequests=100`、`MaxBodyBytes=2 MiB`。
- 所有网络请求必须继承 caller `context.Context`；首页失败返回整体错误，单个主动请求失败按未命中处理。
- 规则只使用单一内置 JSON，不支持数据库、在线更新、热加载或自定义规则文件。
- 规则运行时使用进程级不可变单例；本轮不设计 reload。
- 不新增 CLI 子命令、benchmark、样本集或外部复现实验。
- 每项提交使用 Conventional Commits，提交说明使用中文。

---

## File Structure

### New files

- `internal/appfingerprint/types.go`：内部 `Record`、规则来源、匹配证据、产品结果和执行请求/结果。
- `internal/appfingerprint/expression.go`：表达式 lexer、parser、AST、字段/operator 校验和编译。
- `internal/appfingerprint/expression_test.go`：zvas 兼容表达式语义测试。
- `internal/appfingerprint/catalog.go`：JSON schema、目录编译、规则校验、产品聚合。
- `internal/appfingerprint/catalog_test.go`：schema、ID、安全路径、status-only 和产品 OR 测试。
- `internal/appfingerprint/path.go`：基准目录、Depth 和主动 URL 去重规划。
- `internal/appfingerprint/path_test.go`：路径语义和确定顺序测试。
- `internal/appfingerprint/http_fetcher.go`：把 context-aware crawlweb 抓取适配为内部 fetch seam。
- `internal/appfingerprint/engine.go`：passive → plan → bounded active → aggregate 主流程。
- `internal/appfingerprint/engine_test.go`：fake fetcher/limiter 下的调度、取消、失败隔离和确定结果测试。
- `internal/crawlweb/crawlweb_test.go`：context、body 上限、同 origin 重定向测试。
- `pkg/assetprobe/application_types.go`：公开请求、产品和证据类型。
- `pkg/assetprobe/application.go`：`Scanner.DetectApplications` 及内部结果映射。
- `pkg/assetprobe/application_test.go`：公开 SDK 的 `httptest` 集成测试。
- `app/assetprobe/fingerprints/gomap-web-fingerprints.json`：版本化内置规则。
- `app/assetprobe/fingerprints/LICENSE.burp-finger`：固定基线原始许可证。
- `app/assetprobe/fingerprints/SOURCES.md`：ProductID 与固定基线原始规则的审计映射。

### Modified files

- `app/assets.go`：embed Web 指纹 JSON，并提供读取函数。
- `app/assets_test.go`：验证 Web 指纹和许可证资产存在。
- `internal/crawlweb/crawlweb.go`：新增 context-aware 受限抓取入口，并保持旧入口兼容。
- `pkg/assetprobe/scanner.go`：在 `initAssets` 中编译不可变指纹目录。
- `pkg/assetprobe/json.go`：为 `ApplicationScanResult` 增加 `ToJSON`。
- `pkg/assetprobe/README.md`：补充 SDK 使用方式与主动请求约束。
- `README.md`：能力列表与库调用示例补充应用指纹。
- `go.mod` / `go.sum`：将现有间接依赖 `golang.org/x/time` 作为直接依赖使用。

---

### Task 1: 实现表达式编译与统一 matcher

**Files:**
- Create: `internal/appfingerprint/types.go`
- Create: `internal/appfingerprint/expression.go`
- Create: `internal/appfingerprint/expression_test.go`

**Interfaces:**
- Consumes: 无。
- Produces:
  - `CompileExpression(raw string) (*Expression, error)`
  - `(*Expression).Match(record Record) (bool, []Match)`
  - `(*Expression).HasPositiveEvidence() bool`
  - `Record`、`Match`、`SourcePassive`、`SourceActive`

- [ ] **Step 1: 写表达式语义失败测试**

创建 `internal/appfingerprint/expression_test.go`，至少包含以下测试主体：

```go
package appfingerprint

import "testing"

func TestExpressionMatchesStringBooleanAndEvidence(t *testing.T) {
    expr, err := CompileExpression(`header="x-powered-by: php" && (body="wordpress" || title~="wp[- ]admin")`)
    if err != nil {
        t.Fatal(err)
    }
    ok, matches := expr.Match(Record{
        Header: "HTTP 200\nX-Powered-By: PHP\n",
        Body:   "WordPress login",
        Title:  "home",
    })
    if !ok {
        t.Fatal("expected expression to match")
    }
    if len(matches) != 2 {
        t.Fatalf("expected two positive matches, got %#v", matches)
    }
    if matches[0].Field != "header" || matches[0].Observed != "X-Powered-By: PHP" {
        t.Fatalf("unexpected header evidence: %#v", matches[0])
    }
}

func TestExpressionUsesZVASOperatorPrecedence(t *testing.T) {
    expr, err := CompileExpression(`body="alpha" || body="beta" && !body="blocked"`)
    if err != nil {
        t.Fatal(err)
    }
    ok, _ := expr.Match(Record{Body: "beta blocked"})
    if ok {
        t.Fatal("expected ! > && > || precedence")
    }
}

func TestExpressionMatchesNumericFields(t *testing.T) {
    expr, err := CompileExpression(`status>="200" && status<="299" && port!="8080"`)
    if err != nil {
        t.Fatal(err)
    }
    ok, matches := expr.Match(Record{StatusCode: 200, Port: 443})
    if !ok || len(matches) != 3 {
        t.Fatalf("unexpected numeric result: ok=%v matches=%#v", ok, matches)
    }
}

func TestExpressionRejectsMalformedOrUnknownPredicates(t *testing.T) {
    cases := []string{
        `body = "x"`,
        `unknown="x"`,
        `status~="2.."`,
        `body="unterminated`,
        `(body="x"`,
    }
    for _, raw := range cases {
        if _, err := CompileExpression(raw); err == nil {
            t.Fatalf("expected compile error for %q", raw)
        }
    }
}

func TestExpressionRequiresPositiveEvidence(t *testing.T) {
    expr, err := CompileExpression(`!body="error" && status="200"`)
    if err != nil {
        t.Fatal(err)
    }
    if expr.HasPositiveEvidence() {
        t.Fatal("status and negative predicates must not count as product evidence")
    }
}
```

同一测试文件再增加 table-driven cases，覆盖 `server/title/path/body_hash/favicon_md5/content_type/protocol`、string `==/!=/~=`、regex 实际匹配 evidence、OR 左分支确定选择，以及 256 字节 UTF-8 安全截断。

- [ ] **Step 2: 运行测试确认失败**

Run:

```bash
go test ./internal/appfingerprint -run 'TestExpression' -count=1
```

Expected: FAIL，缺少 `Record`、`CompileExpression` 或对应实现。

- [ ] **Step 3: 定义内部记录和证据类型**

在 `types.go` 定义：

```go
package appfingerprint

import "time"

type Source string

const (
    SourcePassive Source = "passive"
    SourceActive  Source = "active"
)

type Record struct {
    URL         string
    Header      string
    Body        string
    Server      string
    Title       string
    Path        string
    BodyHash    string
    FaviconMD5  string
    StatusCode  int
    ContentType string
    Protocol    string
    Port        int
}

type Match struct {
    Field    string
    Operator string
    Expected string
    Observed string
}

type Request struct {
    URL          string
    Depth        int
    Concurrency  int
    RateLimit    int
    Timeout      time.Duration
    MaxRequests  int
    MaxBodyBytes int64
}
```

- [ ] **Step 4: 实现 lexer、parser 和 AST 求值**

`expression.go` 使用以下完整 grammar；不使用 zvas 当前的字符串替换求值器：

```text
expression := orExpr
orExpr     := andExpr { "||" andExpr }
andExpr    := unaryExpr { "&&" unaryExpr }
unaryExpr  := "!" unaryExpr | "(" expression ")" | predicate
predicate  := identifier operator quotedString
operator   := "=" | "==" | "!=" | "~=" | ">=" | "<="
```

实现约束：

```go
type Expression struct {
    raw  string
    root expressionNode
}

func CompileExpression(raw string) (*Expression, error)
func (e *Expression) Match(record Record) (bool, []Match)
func (e *Expression) HasPositiveEvidence() bool
```

字段/operator 矩阵固定为：

| 字段 | 类型 | 允许 operator |
|---|---|---|
| header/body/server/title/path/body_hash/favicon_md5/content_type/protocol | string | `=` `==` `!=` `~=` |
| status/port | int | `=` `==` `!=` `>=` `<=` |

求值规则：

- string `=`：大小写不敏感 contains，并返回原文中的命中片段。
- string `==`：大小写不敏感完整相等。
- string `!=`：大小写不敏感 not-contains，不产生正向 evidence。
- string `~=`：编译为 `(?i)` Go RE2，返回实际匹配片段。
- numeric operator 在编译期解析 expected 整数。
- 与已验证 zvas 语义一致，predicate 内 identifier/operator/quotedString 之间不接受空白；布尔 operator 和括号周围可有空白。
- `AND` 成立时合并左右正向 evidence。
- `OR` 左侧成立时只使用左侧 evidence，否则使用右侧 evidence。
- `NOT` 成立时不产生正向 evidence。
- status/port 只作为辅助条件，不计入 `HasPositiveEvidence`。
- `Observed` 在生成时截断到 256 字节，并保证截断结果仍为合法 UTF-8。

- [ ] **Step 5: 运行表达式测试**

Run:

```bash
gofmt -w internal/appfingerprint/types.go internal/appfingerprint/expression.go internal/appfingerprint/expression_test.go
go test ./internal/appfingerprint -run 'TestExpression' -count=1
```

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/appfingerprint/types.go internal/appfingerprint/expression.go internal/appfingerprint/expression_test.go
git commit -m "feat(assetprobe): 新增 Web 指纹表达式引擎"
```

---

### Task 2: 实现规则 schema、编译校验和内置资产

**Files:**
- Create: `internal/appfingerprint/catalog.go`
- Create: `internal/appfingerprint/catalog_test.go`
- Create: `app/assetprobe/fingerprints/gomap-web-fingerprints.json`
- Create: `app/assetprobe/fingerprints/LICENSE.burp-finger`
- Create: `app/assetprobe/fingerprints/SOURCES.md`
- Modify: `app/assets.go:8-26`
- Modify: `app/assets_test.go:10-55`

**Interfaces:**
- Consumes: Task 1 的 `CompileExpression`、`Expression`、`Source`、`Record`、`Match`。
- Produces:
  - `CompileCatalog(raw []byte) (*Catalog, error)`
  - `LoadBuiltin() (*Catalog, error)`
  - `(*Catalog).MatchPassive(record Record) []ProductResult`
  - `(*Catalog).MatchRules(rules []RuleRef, record Record) []ProductResult`
  - `(*Catalog).ActiveRules(excluded map[string]struct{}) []RuleRef`
  - `(*Catalog).ProductIDs() []string`
  - `appassets.WebFingerprints() ([]byte, error)`

- [ ] **Step 1: 写 catalog 失败测试**

创建 `catalog_test.go`，使用内联 JSON 固定 schema 和校验语义：

```go
package appfingerprint

import (
    "reflect"
    "testing"
)

const validCatalogJSON = `{
  "schema_version": 1,
  "products": [
    {
      "id": "wordpress",
      "name": "WordPress",
      "category": "cms",
      "rules": [
        {"id":"wordpress-home","source":"passive","expression":"body=\"wp-content/\""}
      ]
    },
    {
      "id": "spring-boot-actuator",
      "name": "Spring Boot Actuator",
      "category": "framework",
      "rules": [
        {"id":"spring-health","source":"active","path":"/actuator/health","expression":"status=\"200\" && body=\"status\""}
      ]
    }
  ]
}`

func TestCompileCatalogAndMatchPassive(t *testing.T) {
    catalog, err := CompileCatalog([]byte(validCatalogJSON))
    if err != nil {
        t.Fatal(err)
    }
    got := catalog.MatchPassive(Record{URL: "https://example.test/", Body: `<link href="/wp-content/a.css">`})
    if len(got) != 1 || got[0].ID != "wordpress" || got[0].Evidence.RuleID != "wordpress-home" {
        t.Fatalf("unexpected products: %#v", got)
    }
}

func TestCompileCatalogRejectsInvalidRules(t *testing.T) {
    cases := map[string]string{
        "duplicate rule id": `{"schema_version":1,"products":[{"id":"a","name":"A","category":"cms","rules":[{"id":"same","source":"passive","expression":"body=\"a\""}]},{"id":"b","name":"B","category":"cms","rules":[{"id":"same","source":"passive","expression":"body=\"b\""}]}]}`,
        "status only": `{"schema_version":1,"products":[{"id":"a","name":"A","category":"cms","rules":[{"id":"a-status","source":"passive","expression":"status=\"200\""}]}]}`,
        "traversal path": `{"schema_version":1,"products":[{"id":"a","name":"A","category":"cms","rules":[{"id":"a-path","source":"active","path":"/../config","expression":"body=\"a\""}]}]}`,
        "passive active path": `{"schema_version":1,"products":[{"id":"a","name":"A","category":"cms","rules":[{"id":"a-home","source":"passive","path":"/login","expression":"body=\"a\""}]}]}`,
    }
    for name, raw := range cases {
        t.Run(name, func(t *testing.T) {
            if _, err := CompileCatalog([]byte(raw)); err == nil {
                t.Fatal("expected catalog compile error")
            }
        })
    }
}

func TestCatalogReturnsProductsSortedByID(t *testing.T) {
    raw := `{"schema_version":1,"products":[{"id":"z","name":"Z","category":"cms","rules":[{"id":"z1","source":"passive","expression":"body=\"hit\""}]},{"id":"a","name":"A","category":"cms","rules":[{"id":"a1","source":"passive","expression":"body=\"hit\""}]}]}`
    catalog, err := CompileCatalog([]byte(raw))
    if err != nil {
        t.Fatal(err)
    }
    got := catalog.MatchPassive(Record{Body: "hit"})
    ids := []string{got[0].ID, got[1].ID}
    if !reflect.DeepEqual(ids, []string{"a", "z"}) {
        t.Fatalf("unexpected order: %v", ids)
    }
}
```

再增加 `TestCatalogTreatsRulesWithinProductAsOR` 和 `TestCatalogMatchesMultipleProducts`，分别锁定同产品规则 OR、不同产品同时命中和规则文件内首条证据优先。

- [ ] **Step 2: 运行 catalog 测试确认失败**

```bash
go test ./internal/appfingerprint -run 'TestCompileCatalog|TestCatalog' -count=1
```

Expected: FAIL，缺少 catalog 类型和方法。

- [ ] **Step 3: 实现 schema 和编译目录**

在 `catalog.go` 定义 JSON schema 与编译后类型：

```go
type ruleSetFile struct {
    SchemaVersion int           `json:"schema_version"`
    Products      []productFile `json:"products"`
}

type productFile struct {
    ID       string     `json:"id"`
    Name     string     `json:"name"`
    Category string     `json:"category"`
    Rules    []ruleFile `json:"rules"`
}

type ruleFile struct {
    ID         string `json:"id"`
    Source     Source `json:"source"`
    Path       string `json:"path,omitempty"`
    Expression string `json:"expression"`
}

type Catalog struct {
    products []compiledProduct
}

type RuleRef struct {
    ProductID    string
    ProductName  string
    Category     string
    RuleID       string
    Source       Source
    Path         string
    Expression   *Expression
    ProductOrder int
    RuleOrder    int
}

type Evidence struct {
    RuleID     string
    Source     Source
    URL        string
    StatusCode int
    Matches    []Match
}

type ProductResult struct {
    ID       string
    Name     string
    Category string
    Evidence Evidence
}
```

编译校验必须逐条返回带 product/rule ID 的错误，并执行：schema version=1、全局 ID 唯一、非空 name/category、source 枚举、passive 无 path、active 有安全 path、expression 完整编译、至少一个正向产品特征。

`validateActivePath` 必须拒绝：反斜杠、query、fragment、scheme/host、解码后的 `.`/`..` 段、`/.git`、`/.svn`、`/.env`、`/actuator/env`，以及 `.bak/.backup/.sql/.log/.db/.sqlite/.zip/.tar/.gz` 文件后缀。

- [ ] **Step 4: 添加最小内置规则与许可证**

先写入两个可用于后续集成测试的来源规则：WordPress passive 和 Spring Boot Actuator safe active。JSON 必须是 Task 2 测试中的 schema；不得加入 hash、status-only 或敏感路径。

`LICENSE.burp-finger` 原样保留固定基线仓库的 MIT 文本：

```text
MIT License

Copyright (c) 2026 zhangsan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 5: embed 并验证资产**

修改 `app/assets.go`：

```go
//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt assetprobe/fingerprints/gomap-web-fingerprints.json assetprobe/fingerprints/LICENSE.burp-finger secprobe/dicts/passwords/global.txt secprobe/protocols/*.yaml secprobe/templates/unauthorized/*.yaml
var files embed.FS

func WebFingerprints() ([]byte, error) {
    return files.ReadFile("assetprobe/fingerprints/gomap-web-fingerprints.json")
}

func WebFingerprintLicense() ([]byte, error) {
    return files.ReadFile("assetprobe/fingerprints/LICENSE.burp-finger")
}
```

在 `app/assets_test.go` 增加读取非空、`schema_version` 和 `MIT License` 断言。

`LoadBuiltin` 读取 `appassets.WebFingerprints()` 后调用 `CompileCatalog`。

- [ ] **Step 6: 运行规则与资产测试**

```bash
gofmt -w internal/appfingerprint/catalog.go internal/appfingerprint/catalog_test.go app/assets.go app/assets_test.go
go test ./internal/appfingerprint ./app -count=1
```

Expected: PASS。

- [ ] **Step 7: 提交**

```bash
git add internal/appfingerprint/catalog.go internal/appfingerprint/catalog_test.go app/assets.go app/assets_test.go app/assetprobe/fingerprints
git commit -m "feat(assetprobe): 新增 Web 指纹规则目录"
```

---

### Task 3: 为 crawlweb 增加 context-aware 受限抓取

**Files:**
- Create: `internal/crawlweb/crawlweb_test.go`
- Modify: `internal/crawlweb/crawlweb.go:22-193`

**Interfaces:**
- Consumes: 标准库 HTTP。
- Produces:
  - `crawlweb.FetchOptions`
  - `crawlweb.FetchResult`
  - `crawlweb.FetchWebInfoContext(ctx, rawURL, opts) (*FetchResult, error)`
  - `crawlweb.FormatHeaderMap(headers map[string][]string) string`
- Compatibility: `FetchWebInfo`、`AnalyzeWebsite` 保持现有签名和现有跨 origin、10 次 redirect、body 超限报错行为。

- [ ] **Step 1: 写 context、body 和 redirect 失败测试**

创建 `crawlweb_test.go`：

```go
package crawlweb

import (
    "context"
    "errors"
    "net/http"
    "net/http/httptest"
    "sync/atomic"
    "testing"
    "time"
)

func TestFetchWebInfoContextCancelsBlockedRequest(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        <-r.Context().Done()
    }))
    defer server.Close()

    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    _, err := FetchWebInfoContext(ctx, server.URL, FetchOptions{Timeout: time.Second, MaxBodyBytes: 1024})
    if !errors.Is(err, context.Canceled) {
        t.Fatalf("expected context canceled, got %v", err)
    }
}

func TestFetchWebInfoContextTruncatesBodyWithoutFailing(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _, _ = w.Write([]byte("0123456789abcdef"))
    }))
    defer server.Close()

    result, err := FetchWebInfoContext(context.Background(), server.URL, FetchOptions{
        Timeout:      time.Second,
        MaxBodyBytes: 10,
    })
    if err != nil {
        t.Fatal(err)
    }
    if result.Info.Http.Body != "0123456789" {
        t.Fatalf("unexpected body: %q", result.Info.Http.Body)
    }
    if result.FinalURL != server.URL {
        t.Fatalf("unexpected final URL: %s", result.FinalURL)
    }
}

func TestFetchWebInfoContextDoesNotFollowCrossOriginRedirect(t *testing.T) {
    var targetHits atomic.Int32
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        targetHits.Add(1)
        _, _ = w.Write([]byte("cross origin"))
    }))
    defer target.Close()

    source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, target.URL, http.StatusFound)
    }))
    defer source.Close()

    result, err := FetchWebInfoContext(context.Background(), source.URL, FetchOptions{
        Timeout:        time.Second,
        MaxBodyBytes:   1024,
        SameOriginOnly: true,
        MaxRedirects:   5,
    })
    if err != nil {
        t.Fatal(err)
    }
    if result.Info.Http.StatusCode != http.StatusFound || targetHits.Load() != 0 {
        t.Fatalf("unexpected redirect behavior: status=%d hits=%d", result.Info.Http.StatusCode, targetHits.Load())
    }
}
```

同时增加以下回归测试：

- `TestFetchWebInfoContextRejectsUserInfoRedirect`
- `TestFetchWebInfoContextSkipsUserInfoFavicon`
- `TestFetchWebInfoContextStopsAfterMaxRedirects`
- `TestFetchWebInfoKeepsLegacyCrossOriginRedirect`
- `TestFetchWebInfoKeepsLegacyBodyOverflowError`

userinfo 测试使用原子 counter 证明目标服务未收到请求；redirect 上限测试构造 6 跳链并设置 `MaxRedirects=5`；旧入口测试分别证明仍跟随跨 origin redirect、超过 2 MiB 仍返回 error。

- [ ] **Step 2: 运行测试确认失败**

```bash
go test ./internal/crawlweb -run 'TestFetchWebInfoContext|TestFetchWebInfoKeepsLegacy' -count=1
```

Expected: FAIL，缺少新入口。

- [ ] **Step 3: 实现 FetchOptions 和 context 传播**

在 `crawlweb.go` 增加：

```go
type FetchOptions struct {
    Timeout            time.Duration
    MaxBodyBytes       int64
    MaxRedirects       int
    SameOriginOnly     bool
    FetchFavicon       bool
    RejectBodyOverflow bool
}

type FetchResult struct {
    Info     *common.GlobalJson
    FinalURL string
}

func FetchWebInfoContext(ctx context.Context, fullURL string, opts FetchOptions) (*FetchResult, error)
```

实现要求：

- `http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)`。
- `opts.Timeout<=0` 使用 5 秒；`MaxBodyBytes<=0` 使用 2 MiB；`MaxRedirects<=0` 使用 5。
- body 读取 `MaxBodyBytes+1` 字节；`RejectBodyOverflow=false` 时截断成功，true 时保持旧入口的超限 error。
- `FinalURL` 必须取 `resp.Request.URL.String()`，主动 evidence 使用该真实响应 URL。
- redirect 比较规范化后的 scheme、hostname 和 effective port；跨 origin 返回 `http.ErrUseLastResponse`。
- 初始 URL、redirect target 和 favicon URL 出现 `URL.User != nil` 时拒绝或跳过，任何路径都不得发送 Authorization/userinfo。
- 同 origin 超过 `MaxRedirects` 返回明确错误。
- `FetchFavicon=false` 时不发 favicon 请求；为 true 时 favicon 请求继承同一个 ctx、timeout、same-origin 和 body 上限。
- `FormatHeaderMap` 按 header name 排序并输出与现有 `buildHomepageHeaderMap` 相同的 `Name: value` 文本，供 matcher 和公开结果复用。
- 保留现有 TLS compatible retry，但 retry 继续使用原 ctx。
- `FetchWebInfo` 传 `SameOriginOnly=false`、`MaxRedirects=10`、`RejectBodyOverflow=true` 保持旧语义；增加旧入口跨 origin 和 body 超限回归测试。`AnalyzeWebsite` 保持签名。

- [ ] **Step 4: 运行 crawlweb 测试和现有 assetprobe 首页测试**

```bash
gofmt -w internal/crawlweb/crawlweb.go internal/crawlweb/crawlweb_test.go
go test ./internal/crawlweb ./pkg/assetprobe -run 'TestFetchWebInfoContext|TestFetchWebInfoKeepsLegacy|TestDetectHomepageWithOptions' -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/crawlweb/crawlweb.go internal/crawlweb/crawlweb_test.go
git commit -m "refactor(crawlweb): 支持上下文感知的受限请求"
```

---

### Task 4: 实现基准目录和确定性主动探针规划

**Files:**
- Create: `internal/appfingerprint/path.go`
- Create: `internal/appfingerprint/path_test.go`

**Interfaces:**
- Consumes: Task 2 的 `Catalog`、`RuleRef`。
- Produces:
  - `normalizeTargetURL(raw string) (*url.URL, error)`
  - `buildBasePaths(target *url.URL, depth int) []string`
  - `buildProbePlan(target *url.URL, bases []string, rules []RuleRef, maxRequests int) []Probe`

- [ ] **Step 1: 写路径与去重失败测试**

```go
package appfingerprint

import (
    "net/url"
    "reflect"
    "testing"
)

func TestBuildBasePathsUsesRelativeParentDepth(t *testing.T) {
    target, _ := url.Parse("https://example.test/a/b/index.php?x=1")
    got := buildBasePaths(target, 2)
    want := []string{"/a/b", "/a", "/"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("want %v, got %v", want, got)
    }
}

func TestBuildBasePathsTreatsExtensionlessPathAsDirectory(t *testing.T) {
    target, _ := url.Parse("https://example.test/a/login")
    got := buildBasePaths(target, 1)
    want := []string{"/a/login", "/a"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("want %v, got %v", want, got)
    }
}

func TestBuildProbePlanDeduplicatesSharedURLAndDropsQuery(t *testing.T) {
    target, _ := url.Parse("https://example.test/a/?token=secret")
    rules := []RuleRef{
        {ProductID: "a", RuleID: "a-login", Path: "/login", ProductOrder: 0, RuleOrder: 0},
        {ProductID: "b", RuleID: "b-login", Path: "/login", ProductOrder: 1, RuleOrder: 0},
    }
    got := buildProbePlan(target, []string{"/a", "/"}, rules, 10)
    if len(got) != 2 {
        t.Fatalf("expected two unique base URLs, got %#v", got)
    }
    if got[0].URL != "https://example.test/a/login" || len(got[0].Rules) != 2 {
        t.Fatalf("unexpected first probe: %#v", got[0])
    }
    if got[1].URL != "https://example.test/login" {
        t.Fatalf("unexpected root probe: %#v", got[1])
    }
}

func TestNormalizeTargetURLRejectsUserInfoAndNonHTTP(t *testing.T) {
    for _, raw := range []string{"ftp://example.test/a", "https://user:pass@example.test/a", "https:///missing"} {
        if _, err := normalizeTargetURL(raw); err == nil {
            t.Fatalf("expected invalid URL: %s", raw)
        }
    }
}
```

- [ ] **Step 2: 运行路径测试确认失败**

```bash
go test ./internal/appfingerprint -run 'TestBuildBasePaths|TestBuildProbePlan|TestNormalizeTargetURL' -count=1
```

Expected: FAIL，缺少路径规划函数。

- [ ] **Step 3: 实现规范化和 planner**

定义：

```go
type Probe struct {
    URL   string
    Rules []RuleRef
    Order int
}
```

实现顺序固定为：catalog product order → rule order → base path order。用 `map[string]int` 只定位已存在 probe 的 slice index，禁止遍历 map 生成输出。

路径拼接规则：

```text
base=/a/b + rule=/login -> /a/b/login
base=/     + rule=/login -> /login
```

使用已校验 path 和 `path.Join`，再补回根 `/`；生成 URL 时清空 `RawQuery`、`ForceQuery` 和 `Fragment`，保留输入 scheme/host/port。达到 `maxRequests` 后截断新 URL，但已经存在的 URL仍可追加共享规则。

- [ ] **Step 4: 运行路径测试**

```bash
gofmt -w internal/appfingerprint/path.go internal/appfingerprint/path_test.go
go test ./internal/appfingerprint -run 'TestBuildBasePaths|TestBuildProbePlan|TestNormalizeTargetURL' -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/appfingerprint/path.go internal/appfingerprint/path_test.go
git commit -m "feat(assetprobe): 新增主动指纹路径规划"
```

---

### Task 5: 实现 bounded 主动指纹执行引擎

**Files:**
- Create: `internal/appfingerprint/http_fetcher.go`
- Create: `internal/appfingerprint/engine.go`
- Create: `internal/appfingerprint/engine_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Consumes: Task 2 catalog、Task 3 crawlweb、Task 4 planner。
- Produces:
  - `NewEngine(catalog *Catalog, fetcher Fetcher) *Engine`
  - `(*Engine).Detect(ctx context.Context, req Request) (Result, error)`
  - `NewHTTPFetcher() Fetcher`

- [ ] **Step 1: 写 fake fetcher 下的引擎失败测试**

测试文件定义内部 fake：

```go
type fakeFetcher struct {
    mu        sync.Mutex
    responses map[string]Page
    errors    map[string]error
    calls     []string
}

func (f *fakeFetcher) Fetch(_ context.Context, rawURL string, _ FetchOptions) (Page, error) {
    f.mu.Lock()
    defer f.mu.Unlock()
    f.calls = append(f.calls, rawURL)
    if err := f.errors[rawURL]; err != nil {
        return Page{}, err
    }
    return f.responses[rawURL], nil
}
```

至少增加：

- `TestEngineSkipsActiveRulesForPassiveProduct`
- `TestEngineSharesOneActiveResponseAcrossProducts`
- `TestEngineIgnoresSingleActiveProbeFailure`
- `TestEngineReturnsContextCancellation`
- `TestEngineResultDoesNotDependOnResponseCompletionOrder`
- `TestEngineHonorsMaxRequests`
- `TestEngineHonorsConcurrency`
- `TestEngineWaitsOnRateLimiterForEveryProbe`
- `TestEngineAppliesPerRequestTimeout`

`TestEngineSkipsActiveRulesForPassiveProduct` 的断言必须检查 fetch calls 只有输入 URL，没有该产品 active URL；共享响应测试必须检查同一 `/login` 只调用一次并返回两个产品。预算测试使用阻塞 fetcher 和 fake limiter，分别断言最大同时 Fetch 数不超过 `Concurrency`、active Fetch 次数不超过 `MaxRequests`、每个实际 probe 恰好调用一次 limiter、per-request timeout 取消阻塞 Fetch，caller cancel 后不再派发新 job。

- [ ] **Step 2: 运行引擎测试确认失败**

```bash
go test ./internal/appfingerprint -run 'TestEngine' -count=1
```

Expected: FAIL，缺少 Engine/Fetcher/Page。

- [ ] **Step 3: 定义抓取 seam 和内部结果**

在 `types.go` 追加：

```go
type FetchOptions struct {
    Timeout       time.Duration
    MaxBodyBytes  int64
    FetchFavicon  bool
}

type Page struct {
    URL           string
    Title         string
    HTMLHash      string
    FaviconMD5    string
    ICP           string
    Header        string
    Body          string
    StatusCode    int
    ContentLength int64
    ContentType   string
    Server        string
    RedirectChain []string
}

type Fetcher interface {
    Fetch(ctx context.Context, rawURL string, opts FetchOptions) (Page, error)
}

type Result struct {
    URL      string
    Homepage Page
    Products []ProductResult
}
```

`httpFetcher.Fetch` 调用 `crawlweb.FetchWebInfoContext`，设置 `SameOriginOnly=true`、`MaxRedirects=5`、`RejectBodyOverflow=false`，把 `FetchResult.Info` 转为 `Page`，并把 `FetchResult.FinalURL` 写入 `Page.URL`；Header 直接使用 Task 3 的 `crawlweb.FormatHeaderMap`，避免复制 header 规范化逻辑。

首页 fetch 传 `FetchFavicon=true`；主动 probe 传 false。

- [ ] **Step 4: 实现 Engine 默认值、passive 和 active worker pool**

`engine.go` 定义：

```go
type Engine struct {
    catalog    *Catalog
    fetcher    Fetcher
    newLimiter func(int) probeLimiter
}

type probeLimiter interface {
    Wait(context.Context) error
}

func NewEngine(catalog *Catalog, fetcher Fetcher) *Engine
func (e *Engine) Detect(ctx context.Context, req Request) (Result, error)
```

生产 limiter 使用：

```go
rate.NewLimiter(rate.Limit(req.RateLimit), 1).Wait(ctx)
```

执行算法必须严格按以下顺序：

1. 校验/填充 request 默认值；负数返回错误。
2. normalize URL，首页 Fetch；失败直接返回 error。
3. `Page -> Record`，执行 `MatchPassive`。
4. 用 passive ProductID 集合过滤 `ActiveRules`。
5. 生成确定 plan，并在网络前按 `MaxRequests` 截断。
6. 固定 worker pool 消费 probe；每个 worker 先 limiter.Wait，再用 `context.WithTimeout` 包裹 Fetch。
7. 单 probe error 只记录为该 job 无结果；`context.Canceled`/`DeadlineExceeded` 来自 caller 时整体返回 ctx error。
8. 每个 response 只匹配该 probe 附带的 rules。
9. 聚合时 passive 优先；active 同 product 选择 `(ProductOrder, RuleOrder, Probe.Order)` 最小证据。
10. 最终按 ProductID 排序。

不得返回请求计数或失败列表。

- [ ] **Step 5: 运行引擎测试并整理依赖**

```bash
gofmt -w internal/appfingerprint/types.go internal/appfingerprint/http_fetcher.go internal/appfingerprint/engine.go internal/appfingerprint/engine_test.go
go mod tidy
go test ./internal/appfingerprint ./internal/crawlweb -count=1
```

Expected: PASS；`golang.org/x/time` 出现在直接依赖区。

- [ ] **Step 6: 提交**

```bash
git add internal/appfingerprint go.mod go.sum
git commit -m "feat(assetprobe): 实现主动 Web 指纹执行引擎"
```

---

### Task 6: 暴露 `Scanner.DetectApplications` 公开 SDK

**Files:**
- Create: `pkg/assetprobe/application_types.go`
- Create: `pkg/assetprobe/application.go`
- Create: `pkg/assetprobe/application_test.go`
- Modify: `pkg/assetprobe/scanner.go:29-38,1088-1115`
- Modify: `pkg/assetprobe/json.go:20-31`

**Interfaces:**
- Consumes: Task 5 `appfingerprint.Engine`。
- Produces:
  - `Scanner.DetectApplications(ctx, ApplicationScanRequest) (*ApplicationScanResult, error)`
  - `ApplicationScanResult.ToJSON(pretty bool)`

- [ ] **Step 1: 写公开 SDK 失败测试**

`application_test.go` 使用内置 WordPress 和 Spring Boot 规则：

```go
package assetprobe

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestDetectApplicationsMatchesPassiveProduct(t *testing.T) {
    activeHits := 0
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/actuator/health" {
            activeHits++
        }
        _, _ = w.Write([]byte(`<html><body><a href="/wp-content/a.css">wp</a></body></html>`))
    }))
    defer server.Close()

    scanner, err := NewScanner(Options{})
    if err != nil {
        t.Fatal(err)
    }
    result, err := scanner.DetectApplications(context.Background(), ApplicationScanRequest{URL: server.URL})
    if err != nil {
        t.Fatal(err)
    }
    if len(result.Products) != 1 || result.Products[0].ID != "wordpress" {
        t.Fatalf("unexpected products: %#v", result.Products)
    }
    if result.Products[0].Evidence.Source != ApplicationEvidencePassive {
        t.Fatalf("unexpected evidence: %#v", result.Products[0].Evidence)
    }
    if activeHits != 1 {
        t.Fatalf("spring active rule should still run once, got %d", activeHits)
    }
}

func TestDetectApplicationsMatchesActiveProductAtParentDepth(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/a/b/index.php":
            _, _ = w.Write([]byte("home"))
        case "/a/actuator/health":
            _, _ = w.Write([]byte(`{"status":"UP","status":"ok"}`))
        default:
            http.NotFound(w, r)
        }
    }))
    defer server.Close()

    scanner, err := NewScanner(Options{})
    if err != nil {
        t.Fatal(err)
    }
    result, err := scanner.DetectApplications(context.Background(), ApplicationScanRequest{
        URL:     server.URL + "/a/b/index.php",
        Depth:   1,
        Timeout: time.Second,
    })
    if err != nil {
        t.Fatal(err)
    }
    if len(result.Products) != 1 || result.Products[0].ID != "spring-boot-actuator" {
        t.Fatalf("unexpected products: %#v", result.Products)
    }
    if result.Products[0].Evidence.URL != server.URL+"/a/actuator/health" {
        t.Fatalf("unexpected evidence URL: %#v", result.Products[0].Evidence)
    }
}

func TestApplicationScanResultToJSON(t *testing.T) {
    result := &ApplicationScanResult{URL: "https://example.test"}
    data, err := result.ToJSON(false)
    if err != nil {
        t.Fatal(err)
    }
    if string(data) != `{"URL":"https://example.test","Homepage":{"URL":"","Title":"","HTMLHash":"","FaviconHash":"","ICP":"","Response":{"HeaderMap":"","Header":{"StatusCode":0,"ContentLength":0,"ContentType":"","Server":"","RedirectChain":null},"Body":""}},"Products":null}` {
        t.Fatalf("unexpected JSON: %s", data)
    }
}
```

- [ ] **Step 2: 运行公开测试确认失败**

```bash
go test ./pkg/assetprobe -run 'TestDetectApplications|TestApplicationScanResultToJSON' -count=1
```

Expected: FAIL，缺少公开类型和方法。

- [ ] **Step 3: 定义公开类型**

`application_types.go` 必须与规格一致：

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

type ApplicationEvidenceSource string

const (
    ApplicationEvidencePassive ApplicationEvidenceSource = "passive"
    ApplicationEvidenceActive  ApplicationEvidenceSource = "active"
)

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

- [ ] **Step 4: 初始化不可变 Engine 并实现 public adapter**

在 `scanner.go` 包级状态增加：

```go
applicationFingerprintEngine *appfingerprint.Engine
```

`initAssets` 在 probes/services 成功后执行：

```go
catalog, err := appfingerprint.LoadBuiltin()
if err != nil {
    return fmt.Errorf("load web fingerprints failed: %w", err)
}
applicationFingerprintEngine = appfingerprint.NewEngine(catalog, appfingerprint.NewHTTPFetcher())
```

`application.go`：

```go
func (s *Scanner) DetectApplications(ctx context.Context, req ApplicationScanRequest) (*ApplicationScanResult, error)
```

只做 public/internal 类型映射；不得重新实现默认值、URL 校验、matcher 或 planner。内部 `Page` 映射为现有 `HomepageResult`，Header/Body/redirect chain 保持字段语义。

`json.go` 增加：

```go
func (r *ApplicationScanResult) ToJSON(pretty bool) ([]byte, error) {
    return marshalJSON(r, pretty)
}
```

- [ ] **Step 5: 运行公开 SDK 与全 assetprobe 测试**

```bash
gofmt -w pkg/assetprobe/application_types.go pkg/assetprobe/application.go pkg/assetprobe/application_test.go pkg/assetprobe/scanner.go pkg/assetprobe/json.go
go test ./pkg/assetprobe ./app ./internal/appfingerprint -count=1
```

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add pkg/assetprobe/application_types.go pkg/assetprobe/application.go pkg/assetprobe/application_test.go pkg/assetprobe/scanner.go pkg/assetprobe/json.go
git commit -m "feat(assetprobe): 暴露应用指纹 SDK"
```

---

### Task 7: 扩充并审查首批内置规则

**Files:**
- Modify: `app/assetprobe/fingerprints/gomap-web-fingerprints.json`
- Modify: `internal/appfingerprint/catalog_test.go`

**Interfaces:**
- Consumes: Task 2 schema、Task 1 expression。
- Produces: 固定、可审计的首批内置产品规则。

- [ ] **Step 1: 写规则清单和安全失败测试**

在 `catalog_test.go` 增加内置目录测试，要求至少包含以下固定 ProductID；不以总数量作为验收条件：

```go
func TestBuiltinCatalogContainsCuratedProducts(t *testing.T) {
    catalog, err := LoadBuiltin()
    if err != nil {
        t.Fatal(err)
    }
    want := []string{
        "apache-shiro",
        "asp-net",
        "druid-monitor",
        "go-language",
        "grafana",
        "graphql",
        "gitlab",
        "java-language",
        "jenkins",
        "nacos",
        "next-js",
        "node-js",
        "php-language",
        "python-language",
        "ruby-on-rails",
        "rust-language",
        "spring-boot-actuator",
        "swagger-openapi",
        "swagger-ui",
        "vue-js",
        "wordpress",
    }
    if got := catalog.ProductIDs(); !reflect.DeepEqual(got, want) {
        t.Fatalf("unexpected builtin products:\nwant: %v\ngot:  %v", want, got)
    }
}
```

另加测试遍历所有 active rules，断言 path 不命中 `validateActivePath` 的禁止项；遍历所有 rule，断言 `Expression.HasPositiveEvidence()`；并断言许可证完整包含 `Copyright (c) 2026 zhangsan`，代表性 WordPress、Spring Boot、Nacos、GraphQL 规则的 expression/path 与固定基线转换表一致。

- [ ] **Step 2: 运行规则清单测试确认失败**

```bash
go test ./internal/appfingerprint -run 'TestBuiltinCatalog' -count=1
```

Expected: FAIL，当前只有 Task 2 的两个 seed 产品。

- [ ] **Step 3: 从固定 burp-finger 基线人工转换明确规则**

来源固定为 `107d20dd42b179d1e76853415283db78e6f10ad0`。只转换以下规则类别：

- passive header/body：ASP.NET、PHP、Java、Python、Node.js、Ruby on Rails、Go、Rust、Vue.js、Next.js、Apache Shiro、WordPress、Swagger UI、Grafana、GitLab。
- active safe GET：Druid `/druid/index.html`、Spring Boot `/actuator/health`、Jenkins `/login`、Nacos `/nacos/index.html`、GraphQL `/graphql` `/graphiql` `/graphql/console`、Swagger/OpenAPI `/swagger-resources` `/v2/api-docs` `/v3/api-docs`。

转换规则：

- burp-finger 同一 rule 的 `match[]` 转成 expression 内 `&&`。
- 同 product 不同 rules 保持 OR，不把它们合并为 AND。
- header field 转为完整 header 文本，例如 `field=X-Powered-By, match=PHP` 转为 `header="X-Powered-By: PHP"`。
- 明显正则（如 `.+`、`Next\\.js`）显式使用 `~=`，不得依赖隐式 regex。
- burp-finger 固定基线的 hash 规则均为 Murmur 整数，不转换为 `favicon_md5`。
- 不导入 `Sensitive`、`Vulnerability`、敏感 description、status-only、query path、fragment path 或禁止 path。
- category 统一小写：`cms`、`framework`、`middleware`、`language`、`api`。
- ProductID 和 RuleID 使用稳定 kebab-case，并保持 JSON product/rule 顺序确定。
- 在 `SOURCES.md` 记录固定 commit、原始文件路径 `src/main/resources/rules/fingerprints.json`，并逐项列出 ProductID、原始 `name/type`、采用的 rule 序号及舍弃 hash/path 的原因；该文件只用于审计，不参与运行时加载。

- [ ] **Step 4: 运行规则与公开集成测试**

```bash
python3 -m json.tool app/assetprobe/fingerprints/gomap-web-fingerprints.json >/dev/null
go test ./internal/appfingerprint ./app ./pkg/assetprobe -count=1
```

Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add app/assetprobe/fingerprints/gomap-web-fingerprints.json app/assetprobe/fingerprints/SOURCES.md internal/appfingerprint/catalog_test.go
git commit -m "feat(assetprobe): 内置首批应用指纹规则"
```

---

### Task 8: 补充文档并执行完整验证

**Files:**
- Modify: `pkg/assetprobe/README.md:3-85`
- Modify: `README.md:8-16,150-240`

**Interfaces:**
- Consumes: Task 6 公开 SDK。
- Produces: 对用户可执行的 SDK 示例和明确流量约束。

- [ ] **Step 1: 更新能力列表和 SDK 示例**

在两个 README 中增加以下可运行示例，字段名必须与 Task 6 完全一致：

```go
apps, err := scanner.DetectApplications(context.Background(), assetprobe.ApplicationScanRequest{
    URL:          "https://example.com/app/index.php",
    Depth:        1,
    Concurrency:  10,
    RateLimit:    10,
    Timeout:      5 * time.Second,
    MaxRequests:  100,
    MaxBodyBytes: 2 * 1024 * 1024,
})
if err != nil {
    panic(err)
}
for _, product := range apps.Products {
    fmt.Println(product.Name, product.Category, product.Evidence.URL)
}
```

文档必须明确：

- 这是独立 SDK 方法，不由 `Scanner.Scan` 自动触发。
- 调用即会发送额外 safe GET。
- Depth 只向父目录回溯。
- 不执行敏感文件和漏洞探测。
- 当前不识别版本，不支持自定义规则。

不得增加 CLI 示例或 zvas 内容。

- [ ] **Step 2: 运行 focused tests**

```bash
go test ./internal/appfingerprint ./internal/crawlweb ./pkg/assetprobe ./app -count=1
```

Expected: PASS，0 failures。

- [ ] **Step 3: 运行 race tests**

```bash
go test -race ./internal/appfingerprint ./internal/crawlweb ./pkg/assetprobe -count=1
```

Expected: PASS，0 data races。

- [ ] **Step 4: 运行完整回归**

```bash
go test ./... -count=1
```

Expected: PASS，所有包通过；默认关闭的 Testcontainers 集成测试保持跳过。

- [ ] **Step 5: 检查格式、依赖与工作区**

```bash
gofmt -w internal/appfingerprint internal/crawlweb pkg/assetprobe app
go mod tidy
git diff --check
git status --short
```

Expected: 无 gofmt/go.mod 漂移、无 whitespace error；只显示本任务预期 README 修改。

- [ ] **Step 6: 提交文档**

```bash
git add README.md pkg/assetprobe/README.md
git commit -m "docs(assetprobe): 补充应用指纹使用说明"
```

- [ ] **Step 7: 提交后重新验证**

```bash
go test ./... -count=1
git diff --check
git status --short
```

Expected: tests PASS；worktree clean。

---

## Final Review Checklist

- [ ] `Scanner.Scan`、`ScanResult` 和端口扫描测试没有语义变化。
- [ ] `DetectApplications` 是唯一公开执行入口。
- [ ] public request/result 中不存在 Meta、version、confidence 或 zvas 字段。
- [ ] passive 与 active 使用相同 `Expression` evaluator。
- [ ] active request 固定 GET、same-origin、无 query/认证/body，并受全部预算限制。
- [ ] Depth 只沿输入目录向父级回溯。
- [ ] 单个主动请求失败不会使整体失败；caller context 取消会返回 context error。
- [ ] 产品和证据选择不依赖 goroutine 完成顺序。
- [ ] 内置规则没有 Murmur 冒充 MD5、status-only、纯否定或敏感路径。
- [ ] `../zvas` 没有任何改动。
- [ ] 所有提交符合 Conventional Commits 且提交说明为中文。
