# Secprobe Phase 3 Unauthorized (Memcached + Zookeeper) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add phase-3 `unauthorized` protocols `memcached` and `zookeeper` to GoMap secprobe without changing the public API, while preserving the confirmed-success contract already established by `redis` and `mongodb` unauthorized probing.

**Architecture:** Reuse the current `unauthorized` extension pattern: protocol metadata stays in `pkg/secprobe/protocol_catalog.go`, default wiring stays in `pkg/secprobe/default_registry.go`, and each protocol owns its own `internal/secprobe/<protocol>/unauthorized_prober.go`. `memcached` should use a minimal read-only `stats` confirmation path over TCP, while `zookeeper` should use a real session plus root-children listing to confirm anonymous access without introducing write-side verification.

**Tech Stack:** Go 1.24.6, existing `pkg/secprobe` and `internal/secprobe/core` contracts, current unauthorized patterns in `redis` / `mongodb`, `github.com/go-zookeeper/zk`, existing testcontainers helpers, Go testing package.

---

## Scope Decomposition

This plan intentionally covers only phase-3 of the approved Chujiu alignment design:

- `memcached unauthorized`
- `zookeeper unauthorized`

Out of scope for this plan:

- `ftp unauthorized`
- `telnet unauthorized`
- `mongodb credential`
- `http` / `https` / `http_proxy` / `https_proxy` / `socks5` / `adb` / `jdwp`
- protocol enrichment for `memcached` or `zookeeper`

## File Map

### Shared metadata

- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

### Memcached unauthorized

- Create: `internal/secprobe/memcached/unauthorized_prober.go`
- Create: `internal/secprobe/memcached/unauthorized_prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/run_test.go`

### Zookeeper unauthorized

- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/zookeeper/unauthorized_prober.go`
- Create: `internal/secprobe/zookeeper/unauthorized_prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/run_test.go`

### Docs and regression

- Modify: `README.md`

---

### Task 1: Wire Phase-3 Unauthorized Metadata In The Catalog

**Files:**
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Write the failing phase-3 catalog tests**

Add a new test to `pkg/secprobe/protocol_catalog_test.go`:

```go
func TestLookupProtocolSpecIncludesPhaseThreeUnauthorizedProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "memcached by port",
			port:    11211,
			want: ProtocolSpec{
				Name:       "memcached",
				Ports:      []int{11211},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
			},
		},
		{
			name:    "zookeeper by name",
			service: "zookeeper",
			want: ProtocolSpec{
				Name:       "zookeeper",
				Ports:      []int{2181},
				ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if !reflect.DeepEqual(spec, tt.want) {
				t.Fatalf("expected %#v, got %#v", tt.want, spec)
			}
			if ProtocolSupportsKind(tt.want.Name, ProbeKindCredential) {
				t.Fatalf("expected %s credential probing to stay unsupported", tt.want.Name)
			}
			if !ProtocolSupportsKind(tt.want.Name, ProbeKindUnauthorized) {
				t.Fatalf("expected %s unauthorized probing to be declared", tt.want.Name)
			}
		})
	}
}
```

Extend `TestProtocolSupportsKindUsesCatalogDeclaration`:

```go
	if !ProtocolSupportsKind("memcached", ProbeKindUnauthorized) {
		t.Fatal("expected memcached unauthorized probing to be declared")
	}
	if ProtocolSupportsKind("memcached", ProbeKindCredential) {
		t.Fatal("expected memcached credential probing to stay unsupported")
	}
	if !ProtocolSupportsKind("zookeeper", ProbeKindUnauthorized) {
		t.Fatal("expected zookeeper unauthorized probing to be declared")
	}
	if ProtocolSupportsKind("zookeeper", ProbeKindCredential) {
		t.Fatal("expected zookeeper credential probing to stay unsupported")
	}
```

- [ ] **Step 2: Run the targeted catalog tests to verify phase-3 metadata is missing**

Run:

```bash
go test ./pkg/secprobe -run 'TestLookupProtocolSpecIncludesPhaseThreeUnauthorizedProtocols|TestProtocolSupportsKindUsesCatalogDeclaration' -v
```

Expected: FAIL because `memcached` and `zookeeper` are not yet declared in `builtinProtocolSpecs`.

- [ ] **Step 3: Add the phase-3 unauthorized protocol declarations**

Update `pkg/secprobe/protocol_catalog.go` by inserting these two specs into `builtinProtocolSpecs`:

```go
	{
		Name:       "memcached",
		Ports:      []int{11211},
		ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
	},
	{
		Name:       "zookeeper",
		Ports:      []int{2181},
		ProbeKinds: []ProbeKind{ProbeKindUnauthorized},
	},
```

Notes for implementers:

- Do not add `DictNames`; unauthorized protocols must not enter the credential dictionary path.
- Do not set `SupportsEnrichment`; phase-3 only adds confirmation probing.
- Do not add strict-port filtering like `oracle` / `snmp`; normal known-port fallback is acceptable for these two TCP protocols.

- [ ] **Step 4: Re-run the catalog tests**

Run:

```bash
go test ./pkg/secprobe -run 'TestLookupProtocolSpecIncludesPhaseThreeUnauthorizedProtocols|TestProtocolSupportsKindUsesCatalogDeclaration' -v
```

Expected: PASS.

- [ ] **Step 5: Commit the phase-3 catalog wiring**

```bash
git add pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): 声明第三阶段未授权协议元数据" \
  -m "在 protocol catalog 中新增 memcached 与 zookeeper 两个 unauthorized 协议声明。" \
  -m "保持 unauthorized 协议不进入字典链路，只声明标准名、默认端口与 ProbeKindUnauthorized。" \
  -m "同步补充 phase-3 catalog 断言，锁定两协议不支持 credential、仅支持 unauthorized 的能力边界。"
```

---

### Task 2: Add Memcached Unauthorized Confirmation And Default Wiring

**Files:**
- Create: `internal/secprobe/memcached/unauthorized_prober.go`
- Create: `internal/secprobe/memcached/unauthorized_prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing memcached unit, registry, candidate, and default-run tests**

Create `internal/secprobe/memcached/unauthorized_prober_test.go`:

```go
package memcached

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeStatsClient struct {
	stats    map[string]string
	statsErr error
	closed   bool
}

func (c *fakeStatsClient) Stats() (map[string]string, error) {
	if c.statsErr != nil {
		return nil, c.statsErr
	}
	return c.stats, nil
}

func (c *fakeStatsClient) Close() error {
	c.closed = true
	return nil
}

func TestMemcachedUnauthorizedProberFindsExposedStats(t *testing.T) {
	originalOpen := openMemcached
	t.Cleanup(func() { openMemcached = originalOpen })

	openMemcached = func(context.Context, core.SecurityCandidate, time.Duration) (statsClient, error) {
		return &fakeStatsClient{stats: map[string]string{"version": "1.6.39", "uptime": "42"}}, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if !result.Success {
		t.Fatalf("expected memcached unauthorized success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized-access finding type, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openMemcached
	t.Cleanup(func() { openMemcached = originalOpen })

	openMemcached = func(context.Context, core.SecurityCandidate, time.Duration) (statsClient, error) {
		return nil, errors.New("dial tcp 127.0.0.1:11211: connection refused")
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Success {
		t.Fatalf("expected memcached unauthorized failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberClassifiesInsufficientConfirmation(t *testing.T) {
	originalOpen := openMemcached
	t.Cleanup(func() { openMemcached = originalOpen })

	openMemcached = func(context.Context, core.SecurityCandidate, time.Duration) (statsClient, error) {
		return &fakeStatsClient{stats: map[string]string{"uptime": "42"}}, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Success {
		t.Fatalf("expected insufficient confirmation, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonInsufficientConfirmation {
		t.Fatalf("expected insufficient-confirmation failure reason, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before probe, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestMemcachedUnauthorizedProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       11211,
		Service:    "memcached",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before probe, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "memcached unauthorized",
			candidate: SecurityCandidate{Service: "memcached", Port: 11211},
			kind:      ProbeKindUnauthorized,
			want:      "memcached-unauthorized",
		},
```

and:

```go
		{name: "memcached unauthorized hit", candidate: SecurityCandidate{Service: "memcached", Port: 11211}, kind: ProbeKindUnauthorized, wantOK: true, wantName: "memcached-unauthorized"},
```

Extend `pkg/secprobe/candidates_test.go` by adding memcached to `TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols`:

```go
			{Port: 11211, Open: true, Service: "memcached"},
```

and update the expectations:

```go
	if len(candidates) != 10 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "snmp" || candidates[2].Service != "smb" || candidates[3].Service != "smtp" || candidates[4].Service != "mssql" || candidates[5].Service != "oracle" || candidates[6].Service != "rdp" || candidates[7].Service != "amqp" || candidates[8].Service != "vnc" || candidates[9].Service != "memcached" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
```

Add to `pkg/secprobe/run_test.go`:

```go
func TestRunUsesDefaultRegistryForMemcachedUnauthorized(t *testing.T) {
	container := testutil.StartMemcachedNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "memcached",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected memcached unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected memcached unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected memcached unauthorized finding type via default registry, got %+v", got)
	}
}
```

- [ ] **Step 2: Run the memcached-targeted test slice and confirm it fails**

Run:

```bash
go test ./internal/secprobe/memcached ./pkg/secprobe -run 'TestMemcachedUnauthorizedProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForMemcachedUnauthorized' -v
```

Expected: FAIL because the `memcached` package does not exist yet, default registry does not register it, and no testcontainer helper exists.

- [ ] **Step 3: Implement the memcached unauthorized prober**

Create `internal/secprobe/memcached/unauthorized_prober.go`:

```go
package memcached

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type statsClient interface {
	Stats() (map[string]string, error)
	Close() error
}

type textStatsClient struct {
	conn net.Conn
}

func (c *textStatsClient) Close() error { return c.conn.Close() }

func (c *textStatsClient) Stats() (map[string]string, error) {
	if _, err := c.conn.Write([]byte("stats\r\n")); err != nil {
		return nil, err
	}

	stats := make(map[string]string)
	reader := bufio.NewReader(c.conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "END":
			return stats, nil
		case strings.HasPrefix(line, "STAT "):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) == 3 {
				stats[parts[1]] = parts[2]
			}
		case line == "":
			continue
		default:
			return nil, fmt.Errorf("unexpected memcached stats line %q", line)
		}
	}
}

var openMemcached = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration) (statsClient, error) {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(candidate.Port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return &textStatsClient{conn: conn}, nil
}

func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "memcached-unauthorized" }

func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "memcached"
}

func (unauthorizedProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, _ []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}

	result.Stage = core.StageAttempted

	client, err := openMemcached(ctx, candidate, opts.Timeout)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}
	defer func() { _ = client.Close() }()

	stats, err := client.Stats()
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMemcachedUnauthorizedFailure(err)
		return result
	}
	if stats["version"] == "" {
		result.Error = "stats response missing version"
		result.FailureReason = core.FailureReasonInsufficientConfirmation
		return result
	}

	result.Success = true
	result.Stage = core.StageConfirmed
	result.Capabilities = []core.Capability{core.CapabilityReadable}
	result.Evidence = "stats returned version without authentication"
	return result
}

func classifyMemcachedUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case err == context.Canceled, strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case err == context.DeadlineExceeded, strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
```

Implementation constraints:

- Keep the confirmation read-only: only `stats`, no `set` / `get` write-side verification.
- Treat missing `version` as `insufficient-confirmation`, not success.
- Do not add dictionary wiring or credential fallback for memcached.

- [ ] **Step 4: Register memcached in the default registry, add a container helper, and wire candidate tests**

Update `pkg/secprobe/default_registry.go`:

```go
import (
	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	memcachedprobe "github.com/yrighc/gomap/internal/secprobe/memcached"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	// existing imports...
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mssqlprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(rdpprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(snmpprobe.New())
	r.registerCoreProber(smbprobe.New())
	r.registerCoreProber(smtpprobe.New())
	r.registerCoreProber(oracledbprobe.New())
	r.registerCoreProber(amqpprobe.New())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(vncprobe.New())
	r.registerCoreProber(memcachedprobe.NewUnauthorized())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}
```

Add to `internal/secprobe/testutil/testcontainers.go`:

```go
func StartMemcachedNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "memcached:1.6.39-alpine",
		ExposedPorts: []string{"11211/tcp"},
		Cmd:          []string{"memcached", "-u", "root", "-p", "11211"},
		WaitingFor: wait.ForListeningPort("11211/tcp").WithStartupTimeout(60 * time.Second),
	}, "11211/tcp")
}
```

- [ ] **Step 5: Re-run the memcached slice**

Run:

```bash
go test ./internal/secprobe/memcached ./pkg/secprobe -run 'TestMemcachedUnauthorizedProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForMemcachedUnauthorized' -v
```

Expected: PASS.

- [ ] **Step 6: Commit the memcached unauthorized batch**

```bash
git add internal/secprobe/memcached/unauthorized_prober.go internal/secprobe/memcached/unauthorized_prober_test.go internal/secprobe/testutil/testcontainers.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go pkg/secprobe/run_test.go
git commit -m "feat(secprobe): 接入 memcached 未授权访问探测" \
  -m "新增 memcached unauthorized prober，使用只读 stats 交互确认匿名访问成立，不引入写操作验证。" \
  -m "默认 registry、候选构建与默认 Run 路径同步接入 memcached-unauthorized，并新增 testcontainers 夹具覆盖真实无认证容器。" \
  -m "保持 unauthorized-access 的 confirmed 契约，缺少 version 证据时回落为 insufficient-confirmation，避免 banner-only 误判。"
```

---

### Task 3: Add Zookeeper Unauthorized Confirmation And Default Wiring

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/zookeeper/unauthorized_prober.go`
- Create: `internal/secprobe/zookeeper/unauthorized_prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing zookeeper unit, registry, candidate, and default-run tests**

Create `internal/secprobe/zookeeper/unauthorized_prober_test.go`:

```go
package zookeeper

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-zookeeper/zk"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeZKClient struct {
	children    []string
	childrenErr error
	closed      bool
}

func (c *fakeZKClient) Children(path string) ([]string, *zk.Stat, error) {
	if path != "/" {
		return nil, nil, errors.New("unexpected path")
	}
	if c.childrenErr != nil {
		return nil, nil, c.childrenErr
	}
	return c.children, nil, nil
}

func (c *fakeZKClient) Close() { c.closed = true }

func TestZookeeperUnauthorizedProberFindsReadableRoot(t *testing.T) {
	originalOpen := openZookeeper
	t.Cleanup(func() { openZookeeper = originalOpen })

	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return &fakeZKClient{children: []string{"zookeeper", "app"}}, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if !result.Success {
		t.Fatalf("expected zookeeper unauthorized success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized-access finding type, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openZookeeper
	t.Cleanup(func() { openZookeeper = originalOpen })

	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return &fakeZKClient{childrenErr: zk.ErrNoAuth}, nil
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Success {
		t.Fatalf("expected zookeeper unauthorized failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesConnectionFailure(t *testing.T) {
	originalOpen := openZookeeper
	t.Cleanup(func() { openZookeeper = originalOpen })

	openZookeeper = func(context.Context, core.SecurityCandidate, time.Duration) (zkClient, error) {
		return nil, errors.New("dial tcp 127.0.0.1:2181: connection refused")
	}

	result := NewUnauthorized().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before probe, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestZookeeperUnauthorizedProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := NewUnauthorized().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       2181,
		Service:    "zookeeper",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, nil)

	if result.Stage != "" {
		t.Fatalf("expected empty stage before probe, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "zookeeper unauthorized",
			candidate: SecurityCandidate{Service: "zookeeper", Port: 2181},
			kind:      ProbeKindUnauthorized,
			want:      "zookeeper-unauthorized",
		},
```

and:

```go
		{name: "zookeeper unauthorized hit", candidate: SecurityCandidate{Service: "zookeeper", Port: 2181}, kind: ProbeKindUnauthorized, wantOK: true, wantName: "zookeeper-unauthorized"},
```

Extend `pkg/secprobe/candidates_test.go` again:

```go
			{Port: 2181, Open: true, Service: "zookeeper"},
```

and update the expectations:

```go
	if len(candidates) != 11 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "snmp" || candidates[2].Service != "smb" || candidates[3].Service != "smtp" || candidates[4].Service != "mssql" || candidates[5].Service != "oracle" || candidates[6].Service != "zookeeper" || candidates[7].Service != "rdp" || candidates[8].Service != "amqp" || candidates[9].Service != "vnc" || candidates[10].Service != "memcached" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
```

Add to `pkg/secprobe/run_test.go`:

```go
func TestRunUsesDefaultRegistryForZookeeperUnauthorized(t *testing.T) {
	container := testutil.StartZookeeperNoAuth(t)

	result := Run(context.Background(), []SecurityCandidate{{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "zookeeper",
	}}, CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	got := result.Results[0]
	if !got.Success {
		t.Fatalf("expected zookeeper unauthorized success via default registry, got %+v", got)
	}
	if got.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected zookeeper unauthorized probe kind via default registry, got %+v", got)
	}
	if got.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected zookeeper unauthorized finding type via default registry, got %+v", got)
	}
}
```

- [ ] **Step 2: Run the zookeeper-targeted test slice and confirm it fails**

Run:

```bash
go test ./internal/secprobe/zookeeper ./pkg/secprobe -run 'TestZookeeperUnauthorizedProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForZookeeperUnauthorized' -v
```

Expected: FAIL because the `zookeeper` package does not exist yet, `go-zookeeper/zk` is not in `go.mod`, and no default registry wiring or container helper exists.

- [ ] **Step 3: Add the zookeeper dependency and implement the unauthorized prober**

Add the dependency by running:

```bash
go get github.com/go-zookeeper/zk
```

Create `internal/secprobe/zookeeper/unauthorized_prober.go`:

```go
package zookeeper

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-zookeeper/zk"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type zkClient interface {
	Children(path string) ([]string, *zk.Stat, error)
	Close()
}

var openZookeeper = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration) (zkClient, error) {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	conn, events, err := zk.Connect([]string{net.JoinHostPort(host, strconv.Itoa(candidate.Port))}, timeout)
	if err != nil {
		return nil, err
	}
	if err := waitForZKSession(ctx, events); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func waitForZKSession(ctx context.Context, events <-chan zk.Event) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				return context.DeadlineExceeded
			}
			switch event.State {
			case zk.StateConnected, zk.StateHasSession:
				return nil
			case zk.StateExpired, zk.StateAuthFailed:
				if event.Err != nil {
					return event.Err
				}
				return context.DeadlineExceeded
			}
		}
	}
}

func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "zookeeper-unauthorized" }

func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "zookeeper"
}

func (unauthorizedProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, _ []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}

	result.Stage = core.StageAttempted

	client, err := openZookeeper(ctx, candidate, opts.Timeout)
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}
	defer client.Close()

	children, _, err := client.Children("/")
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyZookeeperUnauthorizedFailure(err)
		return result
	}

	result.Success = true
	result.Stage = core.StageConfirmed
	result.Capabilities = []core.Capability{core.CapabilityEnumerable}
	result.Evidence = "Children(/) succeeded without authentication"
	if len(children) > 0 {
		result.Evidence = "Children(/) listed nodes without authentication"
	}
	return result
}

func classifyZookeeperUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	if err == zk.ErrNoAuth || err == zk.ErrAuthFailed {
		return core.FailureReasonAuthentication
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "noauth"), strings.Contains(text, "permission"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "session expired"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case err == context.Canceled, strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case err == context.DeadlineExceeded, strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
```

Implementation constraints:

- Keep the confirmation read-only: use `Children("/")`, not `Create` / `Set`.
- Anonymous access is confirmed by a successful root-node list, not by TCP connect alone.
- `zk.ErrNoAuth` must classify as `authentication`, not `insufficient-confirmation`.

- [ ] **Step 4: Register zookeeper in the default registry and add a container helper**

Update `pkg/secprobe/default_registry.go`:

```go
import (
	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	memcachedprobe "github.com/yrighc/gomap/internal/secprobe/memcached"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	zookeeperprobe "github.com/yrighc/gomap/internal/secprobe/zookeeper"
	// existing imports...
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mssqlprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(rdpprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(snmpprobe.New())
	r.registerCoreProber(smbprobe.New())
	r.registerCoreProber(smtpprobe.New())
	r.registerCoreProber(oracledbprobe.New())
	r.registerCoreProber(amqpprobe.New())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(vncprobe.New())
	r.registerCoreProber(zookeeperprobe.NewUnauthorized())
	r.registerCoreProber(memcachedprobe.NewUnauthorized())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}
```

Add to `internal/secprobe/testutil/testcontainers.go`:

```go
func StartZookeeperNoAuth(t *testing.T) ServiceContainer {
	t.Helper()

	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "zookeeper:3.9.3",
		ExposedPorts: []string{"2181/tcp"},
		WaitingFor:   wait.ForListeningPort("2181/tcp").WithStartupTimeout(120 * time.Second),
	}, "2181/tcp")
}
```

- [ ] **Step 5: Re-run the zookeeper slice**

Run:

```bash
go test ./internal/secprobe/zookeeper ./pkg/secprobe -run 'TestZookeeperUnauthorizedProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract|TestRunUsesDefaultRegistryForZookeeperUnauthorized' -v
```

Expected: PASS.

- [ ] **Step 6: Commit the zookeeper unauthorized batch**

```bash
git add go.mod go.sum internal/secprobe/zookeeper/unauthorized_prober.go internal/secprobe/zookeeper/unauthorized_prober_test.go internal/secprobe/testutil/testcontainers.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go pkg/secprobe/run_test.go
git commit -m "feat(secprobe): 接入 zookeeper 未授权访问探测" \
  -m "新增 zookeeper unauthorized prober，通过真实会话建立与根节点 Children(/) 读取确认匿名访问成立。" \
  -m "默认 registry、候选构建与默认 Run 路径同步接入 zookeeper-unauthorized，并补充 testcontainers 夹具覆盖真实容器回归。" \
  -m "保持 unauthorized-access 的 confirmed 契约，连接成功但无法完成节点枚举时不误报成功，ErrNoAuth 归类为 authentication 失败。"
```

---

### Task 4: Sync README And Run The Phase-3 Regression Slice

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the phase-3 regression slice before changing documentation**

Run:

```bash
go test ./internal/secprobe/testutil ./internal/secprobe/memcached ./internal/secprobe/zookeeper ./pkg/secprobe -v
```

Expected: PASS after Tasks 1-3 are complete.

- [ ] **Step 2: Update README to advertise the new unauthorized coverage**

Update the `weak` example:

```md
gomap weak -target example.com -ports 6379,27017,11211,2181 -enable-unauth -enable-enrichment
```

Update the `-enable-unauth` description:

```md
- `-enable-unauth`: 启用 `redis` / `mongodb` / `memcached` / `zookeeper` 未授权访问探测
```

Add one minimal factual note near the secprobe explanation block:

```md
- `memcached` 与 `zookeeper` 第一版按 `unauthorized` 协议接入，使用只读确认动作，不依赖凭证字典
- `memcached` / `zookeeper` 默认端口不在 `weak` 的默认端口列表中，使用时需要显式通过 `-ports` 指定
```

Update the `port -weak` unauthorized example:

```md
gomap port -target example.com -ports 6379,27017,11211,2181 -weak -weak-enable-unauth -weak-enable-enrichment
```

- [ ] **Step 3: Re-run the phase-3 regression slice after the README change**

Run:

```bash
go test ./internal/secprobe/testutil ./internal/secprobe/memcached ./internal/secprobe/zookeeper ./pkg/secprobe -v
```

Expected: PASS, and the documentation update should not require any code changes.

- [ ] **Step 4: Commit the phase-3 documentation sync**

```bash
git add README.md
git commit -m "docs(secprobe): 更新第三阶段未授权协议说明" \
  -m "同步 README 中 weak 与 port -weak 的未授权示例端口，纳入 memcached 与 zookeeper 两个 phase-3 协议。" \
  -m "明确 memcached 与 zookeeper 第一版采用只读 unauthorized 确认动作，不依赖凭证字典，并提示其默认端口需显式指定。" \
  -m "在文档修改前后各执行一次 phase-3 回归切片，确认 README 同步不会引入额外行为变化。"
```
