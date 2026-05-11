# secprobe P2 HTTP/API Credential Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在不修改 `secprobe` 顶层 capability 与 engine 主链路的前提下，完成 `P2` 的第一批兼容升级：新增 `activemq` 原子认证、引入 `httpauth` 复用子层，并接入 `zabbix` 与 `neo4j` 的 HTTP/API 登录型 `credential` provider，同时把 `rsync` 单列为边界评估项。

**Architecture:** 保持 `metadata -> planner -> engine -> provider` 不变，继续只使用 `credential / unauthorized / enrichment` 三种顶层语义。`activemq` 直接落成新的 `CredentialAuthenticator`；`zabbix` 与 `neo4j` 通过新增的 `internal/secprobe/httpauth` 复用层实现 HTTP/API 登录，但对 `engine` 来说仍然只是一次 `AuthenticateOnce`。`rsync` 本轮不并批实现，而是产出边界评估结论，避免混淆 `credential` 与 `unauthorized`。

**Tech Stack:** Go, `pkg/secprobe/registry`, `pkg/secprobe/engine`, `pkg/secprobe/metadata`, `pkg/secprobe/result`, `pkg/secprobe/strategy`, `net/http`, `httptest`, YAML metadata under `app/secprobe/protocols`, and Go `testing`.

---

## File Map

### Metadata and registry wiring

- Create: `app/secprobe/protocols/activemq.yaml`
- Create: `app/secprobe/protocols/zabbix.yaml`
- Create: `app/secprobe/protocols/neo4j.yaml`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

### HTTP/API credential helper

- Create: `internal/secprobe/httpauth/types.go`
- Create: `internal/secprobe/httpauth/client.go`
- Create: `internal/secprobe/httpauth/classify.go`
- Create: `internal/secprobe/httpauth/client_test.go`
- Create: `internal/secprobe/httpauth/classify_test.go`

### Protocol providers

- Create: `internal/secprobe/activemq/auth_once.go`
- Create: `internal/secprobe/activemq/auth_once_test.go`
- Create: `internal/secprobe/zabbix/auth_once.go`
- Create: `internal/secprobe/zabbix/auth_once_test.go`
- Create: `internal/secprobe/neo4j/auth_once.go`
- Create: `internal/secprobe/neo4j/auth_once_test.go`

### Documentation and boundary record

- Modify: `README.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`
- Modify: `docs/secprobe-third-party-migration-guide.md`
- Create: `docs/secprobe-rsync-boundary-note.md`

---

## Task 1: Lock P2 Metadata and Registry Expectations Before Implementation

**Files:**
- Create: `app/secprobe/protocols/activemq.yaml`
- Create: `app/secprobe/protocols/zabbix.yaml`
- Create: `app/secprobe/protocols/neo4j.yaml`
- Modify: `pkg/secprobe/metadata/loader_test.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write failing metadata loader tests for the three new protocols**

Add new table entries in `pkg/secprobe/metadata/loader_test.go` similar to the existing `imap/pop3/kafka/ldap` coverage:

```go
{
	name:            "activemq",
	ports:           []int{61613},
	users:           []string{"admin", "root", "activemq", "system", "user"},
	evidenceProfile: "activemq_basic",
},
{
	name:            "zabbix",
	ports:           []int{80, 443, 8080, 8443},
	users:           []string{"Admin", "admin", "guest", "user"},
	evidenceProfile: "zabbix_http_basic",
},
{
	name:            "neo4j",
	ports:           []int{7474, 7473},
	users:           []string{"neo4j", "admin", "root", "test"},
	evidenceProfile: "neo4j_http_basic",
},
```

- [ ] **Step 2: Write failing protocol catalog assertions**

Extend `pkg/secprobe/protocol_catalog_test.go` with cases like:

```go
{
	name: "activemq service",
	in:   SecurityCandidate{Service: "activemq"},
	want: ProtocolSpec{
		Name: "activemq",
		Ports: []int{61613},
		DefaultUsers: []string{"admin", "root", "activemq", "system", "user"},
		PasswordSource: sharedPasswordSource,
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
},
{
	name: "zabbix service",
	in:   SecurityCandidate{Service: "zabbix"},
	want: ProtocolSpec{
		Name: "zabbix",
		Ports: []int{80, 443, 8080, 8443},
		DefaultUsers: []string{"Admin", "admin", "guest", "user"},
		PasswordSource: sharedPasswordSource,
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
},
{
	name: "neo4j port fallback",
	in:   SecurityCandidate{Port: 7474},
	want: ProtocolSpec{
		Name: "neo4j",
		Ports: []int{7474, 7473},
		DefaultUsers: []string{"neo4j", "admin", "root", "test"},
		PasswordSource: sharedPasswordSource,
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
},
```

- [ ] **Step 3: Write failing default registry assertions for the new atomic credential slots**

Add candidates to `pkg/secprobe/default_registry_test.go`:

```go
{Service: "activemq", Port: 61613},
{Service: "zabbix", Port: 80},
{Service: "neo4j", Port: 7474},
```

and extend the atomic provider checks:

```go
if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "activemq", Port: 61613}); !ok {
	t.Fatal("expected activemq atomic credential plugin")
}
if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "zabbix", Port: 80}); !ok {
	t.Fatal("expected zabbix atomic credential plugin")
}
if _, ok := r.lookupAtomicCredential(SecurityCandidate{Service: "neo4j", Port: 7474}); !ok {
	t.Fatal("expected neo4j atomic credential plugin")
}
```

- [ ] **Step 4: Run the focused metadata and registry slice and confirm failure**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadBuiltin|TestLookupProtocolSpecIncludesMetadataProtocols|TestDefaultRegistry.*(activemq|zabbix|neo4j)' -count=1
```

Expected: FAIL because the YAML files and registry registrations do not exist yet.

- [ ] **Step 5: Add the minimal metadata files to satisfy the failing tests**

Create `app/secprobe/protocols/activemq.yaml`:

```yaml
name: activemq
ports:
  - 61613
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: medium
  auth_family: password
  transport: tcp
dictionary:
  default_users:
    - admin
    - root
    - activemq
    - system
    - user
  password_source: builtin:passwords/global
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
results:
  credential_success_type: credential_valid
  evidence_profile: activemq_basic
```

Create `app/secprobe/protocols/zabbix.yaml`:

```yaml
name: zabbix
ports:
  - 80
  - 443
  - 8080
  - 8443
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: medium
  auth_family: password
  transport: http
dictionary:
  default_users:
    - Admin
    - admin
    - guest
    - user
  password_source: builtin:passwords/global
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
results:
  credential_success_type: credential_valid
  evidence_profile: zabbix_http_basic
```

Create `app/secprobe/protocols/neo4j.yaml`:

```yaml
name: neo4j
ports:
  - 7474
  - 7473
capabilities:
  credential: true
  unauthorized: false
  enrichment: false
policy_tags:
  lockout_risk: medium
  auth_family: password
  transport: http
dictionary:
  default_users:
    - neo4j
    - admin
    - root
    - test
  password_source: builtin:passwords/global
  default_tiers:
    - top
    - common
  allow_empty_username: false
  allow_empty_password: false
  expansion_profile: static_basic
results:
  credential_success_type: credential_valid
  evidence_profile: neo4j_http_basic
```

- [ ] **Step 6: Re-run the focused metadata tests**

Run:

```bash
go test ./pkg/secprobe/metadata ./pkg/secprobe -run 'TestLoadBuiltin|TestLookupProtocolSpecIncludesMetadataProtocols|TestDefaultRegistry.*(activemq|zabbix|neo4j)' -count=1
```

Expected: still FAIL, but now only on missing default registry registrations.

- [ ] **Step 7: Commit the metadata baseline**

```bash
git add app/secprobe/protocols/activemq.yaml app/secprobe/protocols/zabbix.yaml app/secprobe/protocols/neo4j.yaml pkg/secprobe/metadata/loader_test.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/default_registry_test.go
git commit -m "test(secprobe): 锁定 P2 协议元数据与注册基线"
```

---

## Task 2: Implement the `activemq` Atomic Credential Provider

**Files:**
- Create: `internal/secprobe/activemq/auth_once.go`
- Create: `internal/secprobe/activemq/auth_once_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write failing unit tests for the `activemq` authenticator**

Create `internal/secprobe/activemq/auth_once_test.go` with:

```go
func TestActiveMQAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "admin" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "mq.local", IP: "127.0.0.1", Port: 61613, Protocol: "activemq",
	}, strategy.Credential{Username: "admin", Password: "secret"})

	if !out.Result.Success || out.Result.Evidence != "ActiveMQ STOMP authentication succeeded" {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestActiveMQAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errActiveMQAuthenticationFailed, want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:61613: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host: "mq.local", IP: "127.0.0.1", Port: 61613, Protocol: "activemq",
			}, strategy.Credential{Username: "admin", Password: "wrong"})

			if out.Result.Success {
				t.Fatalf("expected failure, got %+v", out)
			}
			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}
```

Add a real-path test using a fake STOMP server:

```go
func TestActiveMQAuthenticatorAuthenticateOnceUsesSTOMPConnect(t *testing.T) {
	server, cleanup := newTestSTOMPServer(t)
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host: "mq.local", IP: "127.0.0.1", Port: server.port(), Protocol: "activemq",
	}, strategy.Credential{Username: "admin", Password: "secret"})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	server.assertConnect(t, "admin", "secret")
}
```

- [ ] **Step 2: Run the protocol test and confirm failure**

Run:

```bash
go test ./internal/secprobe/activemq -run 'TestActiveMQAuthenticatorAuthenticateOnce' -count=1
```

Expected: FAIL because `NewAuthenticator` and the protocol package do not exist yet.

- [ ] **Step 3: Implement the minimal STOMP-based authenticator**

Create `internal/secprobe/activemq/auth_once.go` with the same structure as `internal/secprobe/kafka/auth_once.go`, but using a small STOMP `CONNECT`/`CONNECTED` exchange:

```go
type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error: err.Error(), ErrorCode: classifyActiveMQFailure(err), FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success: true, Username: cred.Username, Password: cred.Password,
		Evidence: "ActiveMQ STOMP authentication succeeded", FindingType: result.FindingTypeCredentialValid,
	}}
}
```

The real-path implementation should:

- dial TCP with context deadline
- read the banner if present
- send:

```text
STOMP
accept-version:1.2
host:localhost
login:<user>
passcode:<pass>

\x00
```

- accept `CONNECTED` as success
- treat `ERROR` as authentication failure

- [ ] **Step 4: Register the provider in the default registry**

Update `pkg/secprobe/default_registry.go`:

```go
import activemqprobe "github.com/yrighc/gomap/internal/secprobe/activemq"

// inside RegisterDefaultProbers
r.RegisterAtomicCredential("activemq", activemqprobe.NewAuthenticator(nil))
```

- [ ] **Step 5: Re-run the ActiveMQ slice and the related default-registry checks**

Run:

```bash
go test ./internal/secprobe/activemq ./pkg/secprobe -run 'TestActiveMQAuthenticatorAuthenticateOnce|TestDefaultRegistry.*activemq' -count=1
```

Expected: PASS

- [ ] **Step 6: Commit the `activemq` provider**

```bash
git add internal/secprobe/activemq/auth_once.go internal/secprobe/activemq/auth_once_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 新增 activemq 原子认证能力"
```

---

## Task 3: Add the `httpauth` Credential Helper Layer

**Files:**
- Create: `internal/secprobe/httpauth/types.go`
- Create: `internal/secprobe/httpauth/client.go`
- Create: `internal/secprobe/httpauth/classify.go`
- Create: `internal/secprobe/httpauth/client_test.go`
- Create: `internal/secprobe/httpauth/classify_test.go`

- [ ] **Step 1: Write failing tests for the helper layer**

Create `internal/secprobe/httpauth/client_test.go`:

```go
func TestClientDoFormLoginPreservesCookies(t *testing.T) {
	var sessionSeen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
			w.WriteHeader(http.StatusOK)
		case "/profile":
			_, err := r.Cookie("sid")
			sessionSeen = err == nil
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: time.Second})
	if _, err := client.Do(context.Background(), Request{Method: http.MethodPost, URL: srv.URL + "/login"}); err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if _, err := client.Do(context.Background(), Request{Method: http.MethodGet, URL: srv.URL + "/profile"}); err != nil {
		t.Fatalf("profile request failed: %v", err)
	}
	if !sessionSeen {
		t.Fatal("expected cookie jar to preserve session cookie")
	}
}
```

Create `internal/secprobe/httpauth/classify_test.go`:

```go
func TestClassifyMapsStandardHTTPFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:80: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "tls", err: errors.New("tls: handshake failure"), want: result.ErrorCodeConnection},
	}
	for _, tt := range tests {
		if got := ClassifyTransportError(tt.err); got != tt.want {
			t.Fatalf("%s: want %q got %q", tt.name, tt.want, got)
		}
	}
}
```

- [ ] **Step 2: Run the helper tests and verify failure**

Run:

```bash
go test ./internal/secprobe/httpauth -count=1
```

Expected: FAIL because the package and helper APIs do not exist yet.

- [ ] **Step 3: Implement the small helper layer**

Create `internal/secprobe/httpauth/types.go`:

```go
package httpauth

import "net/http"

type Config struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

type Request struct {
	Method  string
	URL     string
	Header  http.Header
	Body    []byte
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}
```

Create `internal/secprobe/httpauth/client.go`:

```go
func NewClient(cfg Config) *Client
func (c *Client) Do(ctx context.Context, req Request) (Response, error)
```

Implementation requirements:

- use `cookiejar.New(nil)`
- use `http.Transport` with optional insecure TLS
- carry context deadline
- fully read and close response body

Create `internal/secprobe/httpauth/classify.go`:

```go
func ClassifyTransportError(err error) result.ErrorCode {
	if err == nil {
		return ""
	}
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "refused"), strings.Contains(text, "tls"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}
```

- [ ] **Step 4: Re-run the helper test slice**

Run:

```bash
go test ./internal/secprobe/httpauth -count=1
```

Expected: PASS

- [ ] **Step 5: Commit the helper layer**

```bash
git add internal/secprobe/httpauth/types.go internal/secprobe/httpauth/client.go internal/secprobe/httpauth/classify.go internal/secprobe/httpauth/client_test.go internal/secprobe/httpauth/classify_test.go
git commit -m "feat(secprobe): 新增 http api 认证复用层"
```

---

## Task 4: Implement `zabbix` and `neo4j` HTTP/API Credential Providers

**Files:**
- Create: `internal/secprobe/zabbix/auth_once.go`
- Create: `internal/secprobe/zabbix/auth_once_test.go`
- Create: `internal/secprobe/neo4j/auth_once.go`
- Create: `internal/secprobe/neo4j/auth_once_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write failing `zabbix` provider tests**

Create `internal/secprobe/zabbix/auth_once_test.go`:

```go
func TestZabbixAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "Admin" || cred.Password != "zabbix" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "zbx.local", IP: "127.0.0.1", Port: 80, Protocol: "zabbix",
	}, strategy.Credential{Username: "Admin", Password: "zabbix"})

	if !out.Result.Success || out.Result.Evidence != "Zabbix HTTP login succeeded" {
		t.Fatalf("expected success, got %+v", out)
	}
}
```

Add a real-path test with an `httptest.Server` that accepts a JSON-RPC style login and returns a session token.

- [ ] **Step 2: Write failing `neo4j` provider tests**

Create `internal/secprobe/neo4j/auth_once_test.go`:

```go
func TestNeo4jAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "neo4j" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "neo.local", IP: "127.0.0.1", Port: 7474, Protocol: "neo4j",
	}, strategy.Credential{Username: "neo4j", Password: "secret"})

	if !out.Result.Success || out.Result.Evidence != "Neo4j HTTP login succeeded" {
		t.Fatalf("expected success, got %+v", out)
	}
}
```

Add a real-path `httptest.Server` test that requires HTTP basic auth on a fixed endpoint and returns `200` on valid credentials and `401` on invalid credentials.

- [ ] **Step 3: Run both protocol test slices and verify failure**

Run:

```bash
go test ./internal/secprobe/zabbix ./internal/secprobe/neo4j -count=1
```

Expected: FAIL because neither provider exists yet.

- [ ] **Step 4: Implement the `zabbix` provider on top of `httpauth`**

Create `internal/secprobe/zabbix/auth_once.go` with the same outer structure as other credential providers:

```go
func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	client := httpauth.NewClient(httpauth.Config{
		Timeout: timeoutFromContext(ctx),
		InsecureSkipVerify: target.Port == 443 || target.Port == 8443,
	})

	resp, err := client.Do(ctx, httpauth.Request{
		Method: http.MethodPost,
		URL:    buildZabbixLoginURL(target),
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   []byte(buildZabbixJSONRPCLogin(cred.Username, cred.Password)),
	})
	if err != nil {
		return err
	}
	return interpretZabbixLoginResponse(resp)
}
```

Keep the first version narrow:

- fixed login endpoint
- JSON login only
- no token refresh
- no multi-step form handling

- [ ] **Step 5: Implement the `neo4j` provider on top of `httpauth`**

Create `internal/secprobe/neo4j/auth_once.go` with:

```go
func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	client := httpauth.NewClient(httpauth.Config{
		Timeout: timeoutFromContext(ctx),
		InsecureSkipVerify: target.Port == 7473,
	})

	req, err := buildNeo4jRequest(target, cred)
	if err != nil {
		return err
	}
	resp, err := client.Do(ctx, req)
	if err != nil {
		return err
	}
	return interpretNeo4jLoginResponse(resp)
}
```

Keep the first version narrow:

- one fixed HTTP endpoint
- basic-auth style login
- no Bolt support in this slice

- [ ] **Step 6: Wire both providers into the default registry**

Update `pkg/secprobe/default_registry.go`:

```go
import neo4jprobe "github.com/yrighc/gomap/internal/secprobe/neo4j"
import zabbixprobe "github.com/yrighc/gomap/internal/secprobe/zabbix"

r.RegisterAtomicCredential("zabbix", zabbixprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("neo4j", neo4jprobe.NewAuthenticator(nil))
```

- [ ] **Step 7: Re-run the provider and default-registry slices**

Run:

```bash
go test ./internal/secprobe/httpauth ./internal/secprobe/zabbix ./internal/secprobe/neo4j ./pkg/secprobe -run 'Test(Zabbix|Neo4j)|TestDefaultRegistry.*(zabbix|neo4j)' -count=1
```

Expected: PASS

- [ ] **Step 8: Commit the HTTP/API providers**

```bash
git add internal/secprobe/zabbix/auth_once.go internal/secprobe/zabbix/auth_once_test.go internal/secprobe/neo4j/auth_once.go internal/secprobe/neo4j/auth_once_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 新增 zabbix 与 neo4j http 认证能力"
```

---

## Task 5: Document the Final P2 Boundary and Record the `rsync` Deferral

**Files:**
- Modify: `README.md`
- Modify: `docs/secprobe-protocol-extension-guide.md`
- Modify: `docs/secprobe-third-party-migration-guide.md`
- Create: `docs/secprobe-rsync-boundary-note.md`

- [ ] **Step 1: Write the rsync boundary note**

Create `docs/secprobe-rsync-boundary-note.md` with:

```md
# secprobe rsync Boundary Note

日期：2026-05-11

当前不将 `rsync` 并入本轮 P2 实现，原因如下：

- `rsync` 同时存在匿名模块访问与凭证认证边界
- 第一版若同时做模块枚举、匿名确认、凭证认证，容易把 provider 写成小引擎
- 当前 `secprobe` 的推荐模型是：
  - `credential` provider 只做一次认证尝试
  - `unauthorized` checker 只做一次匿名确认

因此本轮结论为：

- `rsync` 延后
- 后续先单独设计它的模块发现与匿名访问边界
```

- [ ] **Step 2: Update README and extension docs**

Append concise notes to `README.md` and `docs/secprobe-protocol-extension-guide.md`:

```md
- `activemq` 第一版按原子 `credential` 协议接入
- `zabbix`、`neo4j` 第一版按 HTTP/API 登录型 `credential` 接入
- `httpauth` 是 provider 层复用助手，不是新的 capability，也不是 YAML DSL
- `rsync` 本轮只完成边界评估，不并入实现批次
```

- [ ] **Step 3: Update the third-party migration guide**

Add one short section to `docs/secprobe-third-party-migration-guide.md`:

```md
### P2 HTTP/API Credential 子层

当前 `zabbix`、`neo4j` 通过 `internal/secprobe/httpauth` 复用 HTTP 登录辅助逻辑，
但对外仍然只是普通 `credential` provider。

这意味着三方扩展方如果需要接类似协议，应优先：

1. 保持 `RegisterAtomicCredential(...)`
2. 在 provider 内复用 HTTP helper
3. 不新增顶层 capability
```

- [ ] **Step 4: Run a final targeted regression slice**

Run:

```bash
go test ./internal/secprobe/activemq ./internal/secprobe/httpauth ./internal/secprobe/zabbix ./internal/secprobe/neo4j ./pkg/secprobe -count=1
```

Expected: PASS

- [ ] **Step 5: Commit the docs and boundary note**

```bash
git add README.md docs/secprobe-protocol-extension-guide.md docs/secprobe-third-party-migration-guide.md docs/secprobe-rsync-boundary-note.md
git commit -m "docs(secprobe): 回写 P2 http api 认证边界"
```

---

## Spec Coverage Check

- `activemq` 继续走现有 atomic credential 模型：由 Task 2 实现
- `httpauth` 子层：由 Task 3 实现
- `zabbix` / `neo4j` 作为 HTTP/API credential 样板：由 Task 4 实现
- `rsync` 单列边界评估：由 Task 5 记录
- 不修改 `engine / planner / credentials / metadata schema` 的顶层语义：通过 Task 3 与 Task 4 的文件范围约束体现

## Self-Review

- Placeholder scan: 本计划未使用 `TODO` / `TBD` / “后续补充” 之类占位语句
- Type consistency: 全程统一使用 `CredentialAuthenticator`、`AuthenticateOnce`、`httpauth`、`RegisterAtomicCredential(...)`
- Scope check: `rsync` 已明确降级为边界记录，避免本计划膨胀为多子系统混合实现

---

Plan complete and saved to `docs/superpowers/plans/2026-05-11-secprobe-p2-http-api-credential-compatibility.md`. Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
