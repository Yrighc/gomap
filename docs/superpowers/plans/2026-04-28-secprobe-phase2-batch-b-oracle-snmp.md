# Secprobe Phase 2 Batch B (Oracle + SNMP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add phase-2 batch-B `credential` protocols `oracle` and `snmp` to GoMap secprobe without changing the public API, while preserving the confirmed-success contract established in batch-A.

**Architecture:** Reuse the batch-A extension pattern: shared metadata and embedded dictionaries land first, then `oracle` and `snmp` each get isolated `internal/secprobe/<protocol>/prober.go` implementations with protocol-specific confirmation logic. `oracle` uses a pure-Go database driver and a small ordered `service name` attempt set, while `snmp` maps `community` onto the existing `Credential` model by interpreting `Credential.Password` as the protocol-private credential.

**Tech Stack:** Go 1.24.6, existing `pkg/secprobe` and `internal/secprobe/core` contracts, embedded dictionaries in `app/secprobe/dicts`, `github.com/sijms/go-ora/v2`, `github.com/gosnmp/gosnmp`, Go `database/sql`, Go testing package.

---

## Scope Decomposition

This plan intentionally covers only batch-B of the approved phase-2 design:

- `oracle`
- `snmp`

The already-completed batch-A (`smtp + amqp`) remains unchanged except for one dependency declaration cleanup in `go.mod`.

## File Map

### Task 0 dependency cleanup

- Modify: `go.mod`

### Shared wiring

- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Create: `app/secprobe/dicts/oracle.txt`
- Create: `app/secprobe/dicts/snmp.txt`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`

### Oracle implementation

- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/oracle/prober.go`
- Create: `internal/secprobe/oracle/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

### SNMP implementation

- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/snmp/prober.go`
- Create: `internal/secprobe/snmp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

### Docs and regression

- Modify: `README.md`

---

### Task 0: Clean Up the AMQP Direct Dependency Declaration

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Move `amqp091-go` from indirect-only to the direct require block**

Update `go.mod` so the direct dependency block contains:

```go
require (
	github.com/PuerkitoBio/goquery v1.8.1
	github.com/corpix/uarand v0.2.0
	github.com/dlclark/regexp2 v1.11.5
	github.com/docker/go-connections v0.5.0
	github.com/go-sql-driver/mysql v1.9.3
	github.com/hirochachacha/go-smb2 v1.1.0
	github.com/jlaffaye/ftp v0.2.0
	github.com/lib/pq v1.12.3
	github.com/microsoft/go-mssqldb v1.9.7
	github.com/natefinch/lumberjack v2.0.0+incompatible
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/redis/go-redis/v9 v9.18.0
	github.com/refraction-networking/utls v1.7.0
	github.com/sergei-bronnikov/grdp v0.3.0
	github.com/testcontainers/testcontainers-go v0.34.1
	go.mongodb.org/mongo-driver v1.17.4
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.48.0
	golang.org/x/text v0.34.0
)
```

And remove this exact indirect line from the second block:

```go
github.com/rabbitmq/amqp091-go v1.10.0 // indirect
```

- [ ] **Step 2: Run the existing AMQP regression slice to verify the cleanup is behavior-neutral**

Run:

```bash
go test ./internal/secprobe/amqp ./pkg/secprobe -run 'TestAMQPProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: PASS, because this task only cleans dependency metadata.

- [ ] **Step 3: Commit the dependency cleanup**

```bash
git add go.mod
git commit -m "chore(deps): 清理 amqp 直接依赖声明" \
  -m "将 github.com/rabbitmq/amqp091-go 从 indirect 列表移动到直接依赖区，保持 go.mod 与当前源码 import 关系一致。" \
  -m "本次不调整任何实现逻辑，只通过现有 AMQP 与 secprobe 回归切片验证依赖声明清理不会引入行为变化。"
```

---

### Task 1: Wire Batch-B Metadata and Embedded Dictionaries

**Files:**
- Create: `app/secprobe/dicts/oracle.txt`
- Create: `app/secprobe/dicts/snmp.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`
- Modify: `pkg/secprobe/dictionaries_test.go`

- [ ] **Step 1: Write the failing shared-wiring tests**

Extend `app/assets_test.go` by adding two new secprobe dict cases:

```go
		{protocol: "oracle", snippets: []string{"system : oracle", "scott : tiger"}},
		{protocol: "snmp", snippets: []string{": public", ": private"}},
```

Extend `pkg/secprobe/assets_test.go`:

```go
func TestBuiltinCredentialsLoadByProtocol(t *testing.T) {
	tests := []string{
		"ssh", "ftp", "mysql", "postgresql", "redis", "telnet",
		"mssql", "rdp", "smb", "vnc", "smtp", "amqp", "oracle", "snmp",
	}

	for _, protocol := range tests {
		creds, err := BuiltinCredentials(protocol)
		if err != nil {
			t.Fatalf("load %s builtin credentials: %v", protocol, err)
		}
		if len(creds) == 0 {
			t.Fatalf("expected builtin credentials for %s", protocol)
		}
	}
}

func TestBuiltinCredentialsLoadByProtocolAlias(t *testing.T) {
	tests := []struct {
		protocol string
		wantUser string
		wantPass string
	}{
		{protocol: "cifs", wantUser: "administrator", wantPass: "administrator"},
		{protocol: "smtps", wantUser: "admin", wantPass: "admin"},
		{protocol: "amqps", wantUser: "guest", wantPass: "guest"},
		{protocol: "oracle-tns", wantUser: "system", wantPass: "oracle"},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			creds, err := BuiltinCredentials(tt.protocol)
			if err != nil {
				t.Fatalf("load %s builtin credentials: %v", tt.protocol, err)
			}
			if len(creds) == 0 {
				t.Fatalf("expected builtin credentials for %s alias", tt.protocol)
			}
			if creds[0].Username != tt.wantUser || creds[0].Password != tt.wantPass {
				t.Fatalf("expected %s credentials via alias, got %+v", tt.protocol, creds[0])
			}
		})
	}
}

func TestBuiltinCredentialsLoadSNMPCommunityMapping(t *testing.T) {
	creds, err := BuiltinCredentials("snmp")
	if err != nil {
		t.Fatalf("load snmp builtin credentials: %v", err)
	}
	if len(creds) == 0 {
		t.Fatal("expected builtin credentials for snmp")
	}
	if creds[0].Username != "" || creds[0].Password != "public" {
		t.Fatalf("expected first snmp credential to map empty username + public community, got %+v", creds[0])
	}
}
```

Add a new batch-B catalog test to `pkg/secprobe/protocol_catalog_test.go`:

```go
func TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "oracle alias",
			service: "oracle-tns",
			want: ProtocolSpec{
				Name:       "oracle",
				Aliases:    []string{"oracle-tns"},
				Ports:      []int{1521},
				DictNames:  []string{"oracle"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name: "snmp port fallback",
			port: 161,
			want: ProtocolSpec{
				Name:       "snmp",
				Ports:      []int{161},
				DictNames:  []string{"snmp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
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
			if !ProtocolSupportsKind(tt.want.Name, ProbeKindCredential) {
				t.Fatalf("expected %s credential probing to be declared", tt.want.Name)
			}
		})
	}
}
```

Extend `pkg/secprobe/dictionaries_test.go`:

```go
func TestCredentialDictionaryCandidatesUsesCatalogDictNamesForBatchBAlias(t *testing.T) {
	tests := []struct {
		protocol string
		want     []string
	}{
		{
			protocol: "oracle-tns",
			want: []string{
				filepath.Join("/tmp/dicts", "oracle.txt"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			if got := CredentialDictionaryCandidates(tt.protocol, "/tmp/dicts"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CredentialDictionaryCandidates(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify batch-B shared wiring is not connected yet**

Run:

```bash
go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestBuiltinCredentialsLoadByProtocol|TestBuiltinCredentialsLoadByProtocolAlias|TestBuiltinCredentialsLoadSNMPCommunityMapping|TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols|TestCredentialDictionaryCandidatesUsesCatalogDictNamesForBatchBAlias' -v
```

Expected: FAIL because `oracle` / `snmp` dictionaries and catalog declarations do not exist yet.

- [ ] **Step 3: Add the dictionaries, embed wiring, and protocol catalog entries**

Create `app/secprobe/dicts/oracle.txt`:

```text
system : oracle
sys : oracle
scott : tiger
test : test
```

Create `app/secprobe/dicts/snmp.txt`:

```text
: public
: private
: manager
: cisco
```

Update `app/assets.go`:

```go
//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/amqp.txt secprobe/dicts/ftp.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/oracle.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/smtp.txt secprobe/dicts/snmp.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt
var files embed.FS

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "amqp":
		return files.ReadFile("secprobe/dicts/amqp.txt")
	case "ftp":
		return files.ReadFile("secprobe/dicts/ftp.txt")
	case "mssql":
		return files.ReadFile("secprobe/dicts/mssql.txt")
	case "mysql":
		return files.ReadFile("secprobe/dicts/mysql.txt")
	case "oracle":
		return files.ReadFile("secprobe/dicts/oracle.txt")
	case "postgresql":
		return files.ReadFile("secprobe/dicts/postgresql.txt")
	case "rdp":
		return files.ReadFile("secprobe/dicts/rdp.txt")
	case "redis":
		return files.ReadFile("secprobe/dicts/redis.txt")
	case "smb":
		return files.ReadFile("secprobe/dicts/smb.txt")
	case "smtp":
		return files.ReadFile("secprobe/dicts/smtp.txt")
	case "snmp":
		return files.ReadFile("secprobe/dicts/snmp.txt")
	case "ssh":
		return files.ReadFile("secprobe/dicts/ssh.txt")
	case "telnet":
		return files.ReadFile("secprobe/dicts/telnet.txt")
	case "vnc":
		return files.ReadFile("secprobe/dicts/vnc.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", protocol)
	}
}
```

Update `pkg/secprobe/protocol_catalog.go` by inserting:

```go
	{
		Name:       "oracle",
		Aliases:    []string{"oracle-tns"},
		Ports:      []int{1521},
		DictNames:  []string{"oracle"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
```

and:

```go
	{
		Name:       "snmp",
		Ports:      []int{161},
		DictNames:  []string{"snmp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
```

- [ ] **Step 4: Run the shared-wiring tests to verify batch-B dictionaries and catalog now resolve**

Run:

```bash
go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestBuiltinCredentialsLoadByProtocol|TestBuiltinCredentialsLoadByProtocolAlias|TestBuiltinCredentialsLoadSNMPCommunityMapping|TestLookupProtocolSpecIncludesPhaseTwoBatchBCredentialProtocols|TestCredentialDictionaryCandidatesUsesCatalogDictNamesForBatchBAlias' -v
```

Expected: PASS, and `oracle` / `snmp` now load builtin dictionaries and resolve through the catalog.

- [ ] **Step 5: Commit the batch-B shared wiring**

```bash
git add app/assets.go app/assets_test.go app/secprobe/dicts/oracle.txt app/secprobe/dicts/snmp.txt pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/assets_test.go pkg/secprobe/dictionaries_test.go
git commit -m "feat(secprobe): 增加第二阶段 batch-b 的协议元数据与内置字典接线" \
  -m "补充 oracle 与 snmp 两个 batch-b credential 协议的 catalog 声明、默认端口、oracle-tns alias 和 DictNames。" \
  -m "新增 oracle/snmp 内置字典资源，并固定 snmp community 通过空用户名加密码字段映射进现有 Credential 解析链。" \
  -m "通过 assets、catalog 与 canonical dict 测试先锁住 batch-b 后续协议实现依赖的共享接线闭环。"
```

---

### Task 2: Implement Oracle Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/oracle/prober.go`
- Create: `internal/secprobe/oracle/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: Write the failing Oracle prober, registry, and candidate tests**

Create `internal/secprobe/oracle/prober_test.go`:

```go
package oracle

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeOracleDB struct {
	pingErr error
	closed  bool
}

func (db *fakeOracleDB) PingContext(context.Context) error { return db.pingErr }
func (db *fakeOracleDB) Close() error {
	db.closed = true
	return nil
}

func TestOracleProberFindsValidCredential(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if !result.Success {
		t.Fatalf("expected oracle success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
}

func TestOracleProberTriesKnownServiceNamesInOrder(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	var attempts []string
	openOracle = func(_ context.Context, dsn string) (oracleDB, error) {
		attempts = append(attempts, dsn)
		if len(attempts) < 3 {
			return &fakeOracleDB{pingErr: errors.New("ORA-12514: service not known")}, nil
		}
		return &fakeOracleDB{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if !result.Success {
		t.Fatalf("expected oracle success after service-name fallback, got %+v", result)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected three service-name attempts, got %d (%v)", len(attempts), attempts)
	}
	assertOracleServiceNames(t, attempts, []string{"XEPDB1", "ORCLPDB1", "XE"})
}

func TestOracleProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openOracle
	t.Cleanup(func() { openOracle = originalOpen })

	openOracle = func(context.Context, string) (oracleDB, error) {
		return &fakeOracleDB{pingErr: errors.New("ORA-01017: invalid username/password; logon denied")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected oracle failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestOracleProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestOracleProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       1521,
		Service:    "oracle",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "system", Password: "oracle"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}

func assertOracleServiceNames(t *testing.T, attempts []string, want []string) {
	t.Helper()
	got := make([]string, 0, len(attempts))
	for _, dsn := range attempts {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse dsn %q: %v", dsn, err)
		}
		got = append(got, parsed.Path[1:])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("service-name attempts = %v, want %v", got, want)
	}
}
```

Update `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "oracle credential",
			candidate: SecurityCandidate{Service: "oracle", Port: 1521},
			kind:      ProbeKindCredential,
			want:      "oracle",
		},
```

and:

```go
		{name: "oracle credential", candidate: SecurityCandidate{Service: "oracle", Port: 1521}, kind: ProbeKindCredential, wantOK: true, wantName: "oracle"},
```

Extend `pkg/secprobe/candidates_test.go`:

```go
func TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 445, Open: true, Service: "cifs"},
			{Port: 587, Open: true, Service: "smtp"},
			{Port: 1433, Open: true, Service: "mssql"},
			{Port: 1521, Open: true, Service: "oracle-tns"},
			{Port: 3389, Open: true, Service: "rdp"},
			{Port: 5672, Open: true, Service: "amqp"},
			{Port: 5900, Open: true, Service: "vnc"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 8 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "smb" || candidates[2].Service != "smtp" || candidates[3].Service != "mssql" || candidates[4].Service != "oracle" || candidates[5].Service != "rdp" || candidates[6].Service != "amqp" || candidates[7].Service != "vnc" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
}
```

- [ ] **Step 2: Run the tests to verify Oracle is not implemented yet**

Run:

```bash
go test ./internal/secprobe/oracle ./pkg/secprobe -run 'TestOracleProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: FAIL because the `oracle` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Add the Oracle dependency, prober implementation, and registry wiring**

Update `go.mod` by adding:

```go
require github.com/sijms/go-ora/v2 v2.7.19
```

Create `internal/secprobe/oracle/prober.go`:

```go
package oracle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type oracleDB interface {
	PingContext(ctx context.Context) error
	Close() error
}

type sqlOracleDB struct {
	db *sql.DB
}

func (db sqlOracleDB) PingContext(ctx context.Context) error { return db.db.PingContext(ctx) }
func (db sqlOracleDB) Close() error                          { return db.db.Close() }

var openOracle = func(_ context.Context, dsn string) (oracleDB, error) {
	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return nil, err
	}
	return sqlOracleDB{db: db}, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string               { return "oracle" }
func (prober) Kind() core.ProbeKind       { return core.ProbeKindCredential }
func (prober) Match(c core.SecurityCandidate) bool { return c.Service == "oracle" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyOracleFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		for _, dsn := range buildOracleDSNAttempts(candidate, cred, opts) {
			db, err := openOracle(ctx, dsn)
			if err != nil {
				result.Error = err.Error()
				result.FailureReason = classifyOracleFailure(err)
				if isTerminalOracleFailure(result.FailureReason) {
					if successFound {
						return successResult
					}
					return result
				}
				continue
			}

			pingCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
			err = db.PingContext(pingCtx)
			cancel()
			_ = db.Close()
			if err == nil {
				successResult.Success = true
				successResult.Username = cred.Username
				successResult.Password = cred.Password
				successResult.Evidence = "Oracle authentication succeeded"
				successResult.Error = ""
				successResult.Stage = core.StageConfirmed
				successResult.FailureReason = ""
				successFound = true
				if opts.StopOnSuccess {
					return successResult
				}
				break
			}

			result.Error = err.Error()
			result.FailureReason = classifyOracleFailure(err)
			if isTerminalOracleFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func buildOracleDSNAttempts(candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions) []string {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	timeoutSeconds := int(opts.Timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}

	serviceNames := []string{"XEPDB1", "ORCLPDB1", "XE", "ORCL"}
	out := make([]string, 0, len(serviceNames))
	for _, serviceName := range serviceNames {
		query := url.Values{}
		query.Set("timeout", fmt.Sprintf("%d", timeoutSeconds))
		out = append(out, (&url.URL{
			Scheme:   "oracle",
			User:     url.UserPassword(cred.Username, cred.Password),
			Host:     fmt.Sprintf("%s:%d", host, candidate.Port),
			Path:     serviceName,
			RawQuery: query.Encode(),
		}).String())
	}
	return out
}

func classifyOracleFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "ora-01017"), strings.Contains(text, "invalid username/password"), strings.Contains(text, "logon denied"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "ora-12514"), strings.Contains(text, "ora-12541"), strings.Contains(text, "listener"), strings.Contains(text, "refused"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalOracleFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}
```

Update `pkg/secprobe/default_registry.go`:

```go
import (
	oracledbprobe "github.com/yrighc/gomap/internal/secprobe/oracle"
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
	r.registerCoreProber(smbprobe.New())
	r.registerCoreProber(smtpprobe.New())
	r.registerCoreProber(oracledbprobe.New())
	r.registerCoreProber(amqpprobe.New())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(vncprobe.New())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}
```

- [ ] **Step 4: Run the Oracle tests and registry lookup tests**

Run:

```bash
go test ./internal/secprobe/oracle ./pkg/secprobe -run 'TestOracleProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: PASS, and the default registry resolves `oracle` credential probing.

- [ ] **Step 5: Commit the Oracle protocol batch**

```bash
git add go.mod go.sum internal/secprobe/oracle/prober.go internal/secprobe/oracle/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go
git commit -m "feat(secprobe): 接入 oracle 凭证探测与默认注册" \
  -m "新增 oracle credential prober，采用 1521 + service name 的最小稳定登录面，并通过 go-ora 纯 Go 驱动完成真实数据库登录确认。" \
  -m "保持 confirmed 与 credential-valid 成功契约，不因 listener、端口开放或握手弱信号误报成功。" \
  -m "同步补充默认 registry、candidate 归一和 service-name 回退测试，为 batch-b 的 oracle 半批次建立稳定基线。"
```

---

### Task 3: Implement SNMP v2c Community Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/snmp/prober.go`
- Create: `internal/secprobe/snmp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: Write the failing SNMP prober, registry, and candidate tests**

Create `internal/secprobe/snmp/prober_test.go`:

```go
package snmp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSNMPClient struct {
	connectErr error
	getErr     error
	closed     bool
}

func (c *fakeSNMPClient) Connect() error { return c.connectErr }
func (c *fakeSNMPClient) Get([]string) (string, error) {
	if c.getErr != nil {
		return "", c.getErr
	}
	return "Linux test-agent", nil
}
func (c *fakeSNMPClient) Close() error {
	c.closed = true
	return nil
}

func TestSNMPProberFindsValidCommunity(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if !result.Success {
		t.Fatalf("expected snmp success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
}

func TestSNMPProberUsesCredentialPasswordAsCommunity(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	var gotCommunity string
	openSNMP = func(_ context.Context, _ core.SecurityCandidate, community string, _ time.Duration) (snmpClient, error) {
		gotCommunity = community
		return &fakeSNMPClient{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "", Password: "private"},
	})

	if !result.Success {
		t.Fatalf("expected snmp success, got %+v", result)
	}
	if gotCommunity != "private" {
		t.Fatalf("expected password field to map to community, got %q", gotCommunity)
	}
}

func TestSNMPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalOpen := openSNMP
	t.Cleanup(func() { openSNMP = originalOpen })

	openSNMP = func(context.Context, core.SecurityCandidate, string, time.Duration) (snmpClient, error) {
		return &fakeSNMPClient{getErr: errors.New("authorizationError: community invalid")}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected snmp failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesCanceledContextBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonCanceled {
		t.Fatalf("expected canceled failure reason, got %+v", result)
	}
}

func TestSNMPProberClassifiesDeadlineExceededBeforeProbe(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result := New().Probe(ctx, core.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       161,
		Service:    "snmp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "", Password: "public"},
	})

	if result.Stage != "" {
		t.Fatalf("expected empty stage before any credential attempt, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonTimeout {
		t.Fatalf("expected timeout failure reason, got %+v", result)
	}
}
```

Update `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "snmp credential",
			candidate: SecurityCandidate{Service: "snmp", Port: 161},
			kind:      ProbeKindCredential,
			want:      "snmp",
		},
```

and:

```go
		{name: "snmp credential", candidate: SecurityCandidate{Service: "snmp", Port: 161}, kind: ProbeKindCredential, wantOK: true, wantName: "snmp"},
```

Extend `pkg/secprobe/candidates_test.go` once more:

```go
func TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 161, Open: true, Service: "snmp"},
			{Port: 445, Open: true, Service: "cifs"},
			{Port: 587, Open: true, Service: "smtp"},
			{Port: 1433, Open: true, Service: "mssql"},
			{Port: 1521, Open: true, Service: "oracle-tns"},
			{Port: 3389, Open: true, Service: "rdp"},
			{Port: 5672, Open: true, Service: "amqp"},
			{Port: 5900, Open: true, Service: "vnc"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 9 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "snmp" || candidates[2].Service != "smb" || candidates[3].Service != "smtp" || candidates[4].Service != "mssql" || candidates[5].Service != "oracle" || candidates[6].Service != "rdp" || candidates[7].Service != "amqp" || candidates[8].Service != "vnc" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
}
```

- [ ] **Step 2: Run the tests to verify SNMP is not implemented yet**

Run:

```bash
go test ./internal/secprobe/snmp ./pkg/secprobe -run 'TestSNMPProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: FAIL because the `snmp` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Add the SNMP dependency, prober implementation, and registry wiring**

Update `go.mod` by adding:

```go
require github.com/gosnmp/gosnmp v1.40.0
```

Create `internal/secprobe/snmp/prober.go`:

```go
package snmp

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

const sysDescrOID = ".1.3.6.1.2.1.1.1.0"

type snmpClient interface {
	Connect() error
	Get(oids []string) (string, error)
	Close() error
}

type goSNMPClient struct {
	client *gosnmp.GoSNMP
}

func (c *goSNMPClient) Connect() error { return c.client.Connect() }
func (c *goSNMPClient) Close() error {
	if c.client.Conn != nil {
		return c.client.Conn.Close()
	}
	return nil
}
func (c *goSNMPClient) Get(oids []string) (string, error) {
	packet, err := c.client.Get(oids)
	if err != nil {
		return "", err
	}
	if len(packet.Variables) == 0 {
		return "", errors.New("snmp returned no variables")
	}
	return packet.Variables[0].Name, nil
}

var openSNMP = func(_ context.Context, candidate core.SecurityCandidate, community string, timeout time.Duration) (snmpClient, error) {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}
	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(candidate.Port),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
	}
	return &goSNMPClient{client: client}, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string               { return "snmp" }
func (prober) Kind() core.ProbeKind       { return core.ProbeKindCredential }
func (prober) Match(c core.SecurityCandidate) bool { return c.Service == "snmp" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		client, err := openSNMP(ctx, candidate, cred.Password, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			if isTerminalSNMPFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		if err := client.Connect(); err != nil {
			_ = client.Close()
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			if isTerminalSNMPFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		_, err = client.Get([]string{sysDescrOID})
		_ = client.Close()
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "SNMP v2c community succeeded"
			successResult.Error = ""
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifySNMPFailure(err)
		if isTerminalSNMPFailure(result.FailureReason) {
			if successFound {
				return successResult
			}
			return result
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func classifySNMPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "authorization"), strings.Contains(text, "community"), strings.Contains(text, "unknowncommunityname"), strings.Contains(text, "noaccess"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "udp"), strings.Contains(text, "refused"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func isTerminalSNMPFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}
```

Update `pkg/secprobe/default_registry.go`:

```go
import (
	snmpprobe "github.com/yrighc/gomap/internal/secprobe/snmp"
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
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}
```

- [ ] **Step 4: Run the SNMP tests and registry lookup tests**

Run:

```bash
go test ./internal/secprobe/snmp ./pkg/secprobe -run 'TestSNMPProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: PASS, and the default registry resolves `snmp` credential probing.

- [ ] **Step 5: Commit the SNMP protocol batch**

```bash
git add go.mod go.sum internal/secprobe/snmp/prober.go internal/secprobe/snmp/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go
git commit -m "feat(secprobe): 接入 snmp v2c community 探测与默认注册" \
  -m "新增 snmp credential prober，第一版只支持 v2c community，并通过最小只读 OID 请求确认 community 是否真实成立。" \
  -m "保持公共 Credential 结构不变，通过空用户名加密码字段映射 community，不反向污染已稳定的用户名密码协议路径。" \
  -m "同步补充默认 registry、candidate 构建和 community 映射测试，完成 batch-b 的第二个协议闭环。"
```

---

### Task 4: Sync README and Run the Batch-B Regression Slice

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the batch-B regression slice before the README change**

Run:

```bash
go test ./app ./pkg/secprobe ./internal/secprobe/oracle ./internal/secprobe/snmp -v
```

Expected: PASS after Tasks 0-3 are complete.

- [ ] **Step 2: Update README to advertise the new batch-B built-ins**

Update `README.md` so the secprobe protocol example becomes:

```md
- `-protocols`: 限定协议，逗号分隔，例如 `ssh,redis,mssql,rdp,vnc,smb,smtp,amqp,oracle,snmp`
```

And update the builtin credential list to:

```md
- 当前内置 `credential` 协议列表：`ftp, ssh, telnet, smtp, mysql, postgresql, redis, mssql, oracle, amqp, snmp, rdp, vnc, smb`
```

If the README includes a short batch-B note, keep it minimal and factual:

```md
- `snmp` 第一版按 `v2c community` 接入，内置字典使用兼容现有解析器的 `: community` 行格式
```

- [ ] **Step 3: Re-run the batch-B regression slice after the README change**

Run:

```bash
go test ./app ./pkg/secprobe ./internal/secprobe/oracle ./internal/secprobe/snmp -v
```

Expected: PASS, and no documentation-induced code changes are required.

- [ ] **Step 4: Commit the batch-B documentation sync**

```bash
git add README.md
git commit -m "docs(secprobe): 更新第二阶段 batch-b 的 oracle-snmp 协议说明" \
  -m "同步 README 中 secprobe 的协议示例和内置 credential 协议列表，纳入 oracle 与 snmp 两个 batch-b 协议。" \
  -m "明确 snmp 第一版采用 v2c community，并使用兼容现有解析器的 : community 字典格式，保持文档与实现语义一致。" \
  -m "在文档提交前后各执行一次 batch-b 回归切片，确认 README 同步不会引入额外行为变化。"
```
