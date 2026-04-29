# MongoDB Credential Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `mongodb credential` probing to secprobe while preserving existing `mongodb unauthorized` and enrichment behavior, and keep the current `unauthorized -> credential` execution order.

**Architecture:** Keep MongoDB on the existing dual-path secprobe model: `protocol_catalog` declares both `credential` and `unauthorized`, `default_registry` wires both probers, and MongoDB owns its own `credential_prober.go` beside the existing unauthorized/enrichment files. Use a real authenticated read-only confirmation action (`ListDatabaseNames`) so credential success semantics stay aligned with the current unauthorized confirmation contract.

**Tech Stack:** Go 1.24.6, `go.mongodb.org/mongo-driver`, existing `pkg/secprobe` registry/run contracts, embedded secprobe dictionaries in `app/assets.go`, testcontainers-go with `mongo:7.0.16`.

---

### Task 1: Close The MongoDB Credential Dictionary And Catalog Loop

**Files:**
- Create: `app/secprobe/dicts/mongodb.txt`
- Modify: `app/assets.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`

- [ ] **Step 1: Write the failing catalog and builtin-dictionary tests**

Add to `pkg/secprobe/protocol_catalog_test.go`:

```go
func TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized(t *testing.T) {
	spec, ok := LookupProtocolSpec("mongodb", 27017)
	if !ok {
		t.Fatal("expected mongodb protocol spec")
	}
	wantKinds := []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized}
	if !reflect.DeepEqual(spec.ProbeKinds, wantKinds) {
		t.Fatalf("expected mongodb probe kinds %v, got %v", wantKinds, spec.ProbeKinds)
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindCredential) {
		t.Fatal("expected mongodb credential probing to be declared")
	}
	if !ProtocolSupportsKind("mongodb", ProbeKindUnauthorized) {
		t.Fatal("expected mongodb unauthorized probing to stay declared")
	}
}
```

Update `pkg/secprobe/assets_test.go`:

```go
func TestBuiltinCredentialsLoadMongoDBByProtocolAndAlias(t *testing.T) {
	tests := []string{"mongodb", "mongo"}
	for _, protocol := range tests {
		t.Run(protocol, func(t *testing.T) {
			creds, err := BuiltinCredentials(protocol)
			if err != nil {
				t.Fatalf("load %s builtin credentials: %v", protocol, err)
			}
			if len(creds) == 0 {
				t.Fatalf("expected builtin credentials for %s", protocol)
			}
		})
	}
}
```

Update `pkg/secprobe/dictionaries_test.go`:

```go
func TestCredentialDictionaryCandidatesUsesCatalogDictNamesForMongoAlias(t *testing.T) {
	got := CredentialDictionaryCandidates("mongo", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "mongodb.txt"),
		filepath.Join("/tmp/dicts", "mongo.txt"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CredentialDictionaryCandidates(%q) = %v, want %v", "mongo", got, want)
	}
}
```

- [ ] **Step 2: Run the dictionary/catalog slice and verify it fails**

Run:

```bash
go test ./pkg/secprobe -run 'TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized|TestBuiltinCredentialsLoadMongoDBByProtocolAndAlias|TestCredentialDictionaryCandidatesUsesCatalogDictNamesForMongoAlias' -v
```

Expected: FAIL because MongoDB is not yet declared as `credential`, `mongodb.txt` is missing from `app/secprobe/dicts`, and `app/assets.go` does not embed or expose it.

- [ ] **Step 3: Add the builtin dictionary asset and catalog declaration**

Create `app/secprobe/dicts/mongodb.txt` with a small weak-credential baseline that the later authenticated test container can reuse:

```text
admin : admin
root : root
mongodb : mongodb
```

Update `app/assets.go`:

```go
//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/amqp.txt secprobe/dicts/ftp.txt secprobe/dicts/mongodb.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/oracle.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/smtp.txt secprobe/dicts/snmp.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt
```

and in `SecprobeDict`:

```go
case "mongodb":
	return files.ReadFile("secprobe/dicts/mongodb.txt")
```

Update `pkg/secprobe/protocol_catalog.go` so MongoDB becomes:

```go
{
	Name:               "mongodb",
	Aliases:            []string{"mongo"},
	Ports:              []int{27017},
	DictNames:          []string{"mongodb", "mongo"},
	ProbeKinds:         []ProbeKind{ProbeKindCredential, ProbeKindUnauthorized},
	SupportsEnrichment: true,
},
```

Update the existing MongoDB assertions in `pkg/secprobe/protocol_catalog_test.go`, `pkg/secprobe/assets_test.go`, and `pkg/secprobe/dictionaries_test.go` to reflect the new dual-kind declaration and builtin dictionary availability.

- [ ] **Step 4: Re-run the dictionary/catalog slice and verify it passes**

Run:

```bash
go test ./pkg/secprobe -run 'TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized|TestBuiltinCredentialsLoadMongoDBByProtocolAndAlias|TestCredentialDictionaryCandidatesUsesCatalogDictNamesForMongoAlias' -v
```

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add app/secprobe/dicts/mongodb.txt app/assets.go pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/assets_test.go pkg/secprobe/dictionaries_test.go
git commit -m "feat(secprobe): 补齐 mongodb credential 字典与 catalog 声明" \
  -m "新增 mongodb 内置弱口令字典，并在 app/assets.go 中完成 secprobe 字典 embed 与读取映射。" \
  -m "将 mongodb protocol catalog 调整为同时支持 credential 与 unauthorized，为后续 MongoDB 凭证探测接线提供声明闭环。" \
  -m "补充 builtin credentials、dictionary candidates 与 protocol catalog 回归测试，确认 mongo/mongodb 两个入口都能命中字典与能力声明。"
```

### Task 2: Implement The MongoDB Credential Prober

**Files:**
- Create: `internal/secprobe/mongodb/credential_prober.go`
- Create: `internal/secprobe/mongodb/credential_prober_test.go`
- Modify: `internal/secprobe/mongodb/prober_internal_test.go`

- [ ] **Step 1: Write the failing MongoDB credential unit tests**

Create `internal/secprobe/mongodb/credential_prober_test.go` in package `mongodb` so it can stub package-level helpers. Add at least:

```go
type fakeMongoCredentialClient struct {
	names          []string
	listErr        error
	disconnectErr  error
	disconnectCall int
}

func (f *fakeMongoCredentialClient) ListDatabaseNames(context.Context, any) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]string(nil), f.names...), nil
}

func (f *fakeMongoCredentialClient) Disconnect(context.Context) error {
	f.disconnectCall++
	return f.disconnectErr
}

func TestMongoDBCredentialProberSucceedsAfterAuthenticatedListDatabaseNames(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() { openMongoCredentialClient = originalOpen })

	client := &fakeMongoCredentialClient{names: []string{"admin", "app"}}
	openMongoCredentialClient = func(context.Context, core.SecurityCandidate, time.Duration, core.Credential) (mongoCredentialClient, error) {
		return client, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{{
		Username: "admin",
		Password: "admin",
	}})

	if !result.Success || result.ProbeKind != core.ProbeKindCredential || result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected mongodb credential success, got %+v", result)
	}
	if result.Username != "admin" || result.Password != "admin" {
		t.Fatalf("expected winning credential evidence, got %+v", result)
	}
	if result.Evidence != "listDatabaseNames succeeded after authentication" {
		t.Fatalf("unexpected evidence: %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() { openMongoCredentialClient = originalOpen })

	openMongoCredentialClient = func(context.Context, core.SecurityCandidate, time.Duration, core.Credential) (mongoCredentialClient, error) {
		return nil, errors.New("command listDatabases requires authentication")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{{
		Username: "admin",
		Password: "wrong",
	}})

	if result.Success || result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() { openMongoCredentialClient = originalOpen })

	openMongoCredentialClient = func(context.Context, core.SecurityCandidate, time.Duration, core.Credential) (mongoCredentialClient, error) {
		return nil, errors.New("server selection error: dial tcp 127.0.0.1:27017: connection refused")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{{
		Username: "admin",
		Password: "admin",
	}})

	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure, got %+v", result)
	}
}

func TestMongoDBCredentialProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{{
		Username: "admin",
		Password: "admin",
	}})

	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure, got %+v", result)
	}
}

func TestMongoDBCredentialProberRequiresVisibleDatabasesForConfirmation(t *testing.T) {
	originalOpen := openMongoCredentialClient
	t.Cleanup(func() { openMongoCredentialClient = originalOpen })

	client := &fakeMongoCredentialClient{names: nil}
	openMongoCredentialClient = func(context.Context, core.SecurityCandidate, time.Duration, core.Credential) (mongoCredentialClient, error) {
		return client, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       27017,
		Service:    "mongodb",
	}, core.CredentialProbeOptions{Timeout: time.Second}, []core.Credential{{
		Username: "admin",
		Password: "admin",
	}})

	if result.Success || result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation, got %+v", result)
	}
}
```

Add a URI-formatting assertion to `internal/secprobe/mongodb/prober_internal_test.go`:

```go
func TestMongoCredentialURIFormatsAuthAndIPv6(t *testing.T) {
	got := mongoCredentialURI(core.SecurityCandidate{
		ResolvedIP: "2001:db8::1",
		Port:       27017,
	}, core.Credential{
		Username: "user@example.com",
		Password: "p@ss:word",
	})
	want := "mongodb://user%40example.com:p%40ss%3Aword@[2001:db8::1]:27017/?directConnection=true"
	if got != want {
		t.Fatalf("mongoCredentialURI() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run the MongoDB credential unit slice and verify it fails**

Run:

```bash
go test ./internal/secprobe/mongodb -run 'TestMongoDBCredentialProber|TestMongoCredentialURIFormatsAuthAndIPv6' -v
```

Expected: FAIL because `New()` currently does not return a MongoDB credential prober, `openMongoCredentialClient` does not exist, and `mongoCredentialURI` is undefined.

- [ ] **Step 3: Implement the credential prober with a real authenticated read-only confirmation**

Create `internal/secprobe/mongodb/credential_prober.go` with this structure:

```go
package mongodb

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoCredentialClient interface {
	ListDatabaseNames(context.Context, any) ([]string, error)
	Disconnect(context.Context) error
}

var openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
	uri := mongoCredentialURI(candidate, cred)
	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(timeout).
		SetConnectTimeout(timeout).
		SetSocketTimeout(timeout)

	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return mongo.Connect(connectCtx, clientOptions)
}

func New() core.Prober { return credentialProber{} }
```

Implement:

- `Name() == "mongodb"`
- `Kind() == credential`
- `Match(candidate.Service == "mongodb")`
- Loop through credentials, and for each:
  - respect `ctx.Err()`
  - open a real MongoDB client with the credential
  - call `ListDatabaseNames(confirmCtx, bson.D{})`
  - treat empty names as `insufficient-confirmation`
  - on success, set `Success=true`, `Stage=confirmed`, `FindingType=credential-valid`, `Username`, `Password`, `Capabilities=[]core.Capability{core.CapabilityEnumerable}`, `Evidence="listDatabaseNames succeeded after authentication"`
  - if `opts.StopOnSuccess`, return immediately; otherwise keep the most recent success and continue to mirror existing credential probers
- Reuse a failure classifier aligned with the unauthorized classifier:
  - auth-like text -> `authentication`
  - dial/server-selection/connect/no-route/refused -> `connection`
  - context cancel/deadline -> `canceled` / `timeout`
  - default -> `insufficient-confirmation`

Add helper:

```go
func mongoCredentialURI(candidate core.SecurityCandidate, cred core.Credential) string {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}
	user := url.QueryEscape(cred.Username)
	pass := url.QueryEscape(cred.Password)
	return fmt.Sprintf("mongodb://%s:%s@%s/?directConnection=true", user, pass, net.JoinHostPort(host, strconv.Itoa(candidate.Port)))
}
```

- [ ] **Step 4: Re-run the MongoDB credential unit slice and verify it passes**

Run:

```bash
go test ./internal/secprobe/mongodb -run 'TestMongoDBCredentialProber|TestMongoCredentialURIFormatsAuthAndIPv6' -v
```

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add internal/secprobe/mongodb/credential_prober.go internal/secprobe/mongodb/credential_prober_test.go internal/secprobe/mongodb/prober_internal_test.go
git commit -m "feat(secprobe): 新增 mongodb 凭证探测器" \
  -m "在 mongodb 协议目录下新增 credential prober，使用真实用户名密码建连并通过 ListDatabaseNames 做只读确认，确保 credential-valid 只在真实认证成功后返回。" \
  -m "保持 mongodb unauthorized 与 enrichment 逻辑不变，并沿用现有 failure reason 语义，不引入新的公共结果状态。" \
  -m "补充 mongodb credential 单测与认证 URI 格式回归，覆盖成功、认证失败、连接失败、上下文取消与确认不足等路径。"
```

### Task 3: Wire The Default Registry And Add Authenticated MongoDB Regression

**Files:**
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing registry and Run regressions**

Update `pkg/secprobe/default_registry_test.go`:

```go
{
	name:      "mongodb credential",
	candidate: SecurityCandidate{Service: "mongodb", Port: 27017},
	kind:      ProbeKindCredential,
	want:      "mongodb",
}
```

and change the old contract assertions from:

```go
{name: "mongodb credential miss", candidate: SecurityCandidate{Service: "mongodb", Port: 27017}, kind: ProbeKindCredential, wantOK: false}
```

to:

```go
{name: "mongodb credential hit", candidate: SecurityCandidate{Service: "mongodb", Port: 27017}, kind: ProbeKindCredential, wantOK: true, wantName: "mongodb"}
```

Add to `pkg/secprobe/run_test.go`:

```go
func TestRunUsesDefaultRegistryForMongoDBCredentialAfterUnauthorizedFailure(t *testing.T) {
	container := testutil.StartMongoDBWithAuth(t, testutil.MongoDBConfig{
		Username: "admin",
		Password: "admin",
	})

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success || got.ProbeKind != ProbeKindCredential || got.FindingType != FindingTypeCredentialValid {
		t.Fatalf("expected mongodb credential fallback success via default registry, got %+v", got)
	}
	if got.Username == "" || got.Password == "" {
		t.Fatalf("expected winning mongodb credential evidence, got %+v", got)
	}
}
```

- [ ] **Step 2: Run the registry/Run slice and verify it fails**

Run:

```bash
go test ./pkg/secprobe -run 'TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForMongoDBCredentialAfterUnauthorizedFailure' -v
```

Expected: FAIL because the default registry does not yet register a MongoDB credential prober, and `StartMongoDBWithAuth` does not exist.

- [ ] **Step 3: Add the authenticated MongoDB container helper and default wiring**

Update `internal/secprobe/testutil/testcontainers.go`:

```go
type MongoDBConfig struct {
	Username string
	Password string
}

func StartMongoDBWithAuth(t *testing.T, cfg MongoDBConfig) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "mongo:7.0.16",
		ExposedPorts: []string{"27017/tcp"},
		Env: map[string]string{
			"MONGO_INITDB_ROOT_USERNAME": cfg.Username,
			"MONGO_INITDB_ROOT_PASSWORD": cfg.Password,
		},
		Cmd: []string{"mongod", "--auth", "--bind_ip_all", "--port", "27017"},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("27017/tcp"),
			wait.ForLog("Waiting for connections"),
		).WithStartupTimeout(120 * time.Second),
	}, "27017/tcp")
}
```

Update `pkg/secprobe/default_registry.go`:

```go
r.registerCoreProber(mongodbprobe.New())
r.registerCoreProber(mongodbprobe.NewUnauthorized())
```

Keep the existing MongoDB wiring grouped together.

- [ ] **Step 4: Re-run the registry/Run slice and verify it passes**

Run:

```bash
go test ./pkg/secprobe -run 'TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForMongoDBCredentialAfterUnauthorizedFailure' -v
```

Expected: PASS, including the authenticated MongoDB container regression.

- [ ] **Step 5: Run the final MongoDB integration slice**

Run:

```bash
go test ./internal/secprobe/mongodb ./pkg/secprobe -run 'TestMongoDBCredentialProber|TestMongoDBUnauthorizedProber|TestLookupProtocolSpecSupportsMongoDBCredentialAndUnauthorized|TestBuiltinCredentialsLoadMongoDBByProtocolAndAlias|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForMongoDBUnauthorized|TestRunUsesDefaultRegistryForMongoDBCredentialAfterUnauthorizedFailure' -v
```

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add internal/secprobe/testutil/testcontainers.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/run_test.go
git commit -m "feat(secprobe): 接入 mongodb 默认凭证探测链路" \
  -m "在默认 registry 中为 mongodb 同时注册 credential 与 unauthorized 两类 prober，使其复用现有未授权优先、失败后回退凭证爆破的执行顺序。" \
  -m "新增启用鉴权的 MongoDB testcontainer 夹具，并补充默认 Run 路径回归，验证 unauthorized 未命中后能够回退到 credential 成功。" \
  -m "完成 mongodb dual-path 的 registry 契约与真实容器验证，为后续 secprobe 默认链路提供稳定覆盖。"
```

## Self-Review

- Spec coverage: 本计划覆盖了 spec 中定义的四个核心点：`mongodb` 同时支持 `credential + unauthorized`、保留 enrichment、不改变单 finding 模型、并以真实认证 + 只读确认作为成功标准。
- Placeholder scan: 已移除占位语句，每个任务都给出了明确文件、测试代码、命令和提交要求。
- Type consistency: 计划统一使用 `mongodbprobe.New()` 作为 credential prober 构造器，`mongodbprobe.NewUnauthorized()` 继续保留 unauthorized 入口；认证帮助函数命名统一为 `openMongoCredentialClient` / `mongoCredentialURI` / `StartMongoDBWithAuth`。
