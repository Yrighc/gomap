# Secprobe Phase 1 Protocol Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the phase-1 high-value `credential` protocols, `mssql`, `rdp`, `vnc`, and `smb`, to `GoMap secprobe` without changing the existing public API or result contract.

**Architecture:** The approved design spans several independent protocol families, so this implementation plan intentionally covers only the first working batch. We keep `pkg/secprobe/protocol_catalog.go`, `pkg/secprobe/default_registry.go`, `app/assets.go`, and `internal/secprobe/<protocol>/` as the only integration points, while each new prober owns its own protocol-specific confirmation logic and tests.

**Tech Stack:** Go 1.24, existing `pkg/secprobe` and `internal/secprobe/core` contracts, embedded dictionaries in `app/secprobe/dicts`, `github.com/microsoft/go-mssqldb`, `github.com/XTeam-Wing/x-crack/pkg/protocols/grdp`, `github.com/mitchellh/go-vnc`, `github.com/hirochachacha/go-smb2`, Go testing package.

---

## Scope Decomposition

The approved spec covers:

- Phase 1 `credential`: `mssql`, `rdp`, `vnc`, `smb`
- Phase 2 `credential`: `smtp`, `amqp`, `oracle`, `snmp`
- Phase 3 `unauthorized`: `memcached`, `zookeeper`
- Phase 4 candidate extension-layer protocols

These are independent protocol subsystems with different dependencies and confirmation rules. This plan covers only Phase 1 so we can finish one stable batch end-to-end, validate the extension pattern, and then write separate plans for later batches.

## File Map

### Shared wiring

- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Create: `app/secprobe/dicts/mssql.txt`
- Create: `app/secprobe/dicts/rdp.txt`
- Create: `app/secprobe/dicts/vnc.txt`
- Create: `app/secprobe/dicts/smb.txt`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

### Protocol implementations

- Create: `internal/secprobe/mssql/prober.go`
- Create: `internal/secprobe/mssql/prober_test.go`
- Create: `internal/secprobe/rdp/prober.go`
- Create: `internal/secprobe/rdp/prober_test.go`
- Create: `internal/secprobe/vnc/prober.go`
- Create: `internal/secprobe/vnc/prober_test.go`
- Create: `internal/secprobe/smb/prober.go`
- Create: `internal/secprobe/smb/prober_test.go`

### Dependency and documentation sync

- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `README.md`

---

### Task 1: Wire Phase-1 Protocol Metadata and Embedded Dictionaries

**Files:**
- Create: `app/secprobe/dicts/mssql.txt`
- Create: `app/secprobe/dicts/rdp.txt`
- Create: `app/secprobe/dicts/vnc.txt`
- Create: `app/secprobe/dicts/smb.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`

- [ ] **Step 1: Write the failing asset and catalog tests**

Update `app/assets_test.go` by extending the `TestEmbeddedSecprobeDictResourcesLoad` table:

```go
		{protocol: "mssql", prefix: "sa : sa\nsa : 123456\nadmin : admin\n"},
		{protocol: "rdp", prefix: "administrator : administrator\nadministrator : 123456\nadmin : admin\n"},
		{protocol: "vnc", prefix: " : 123456\n : vnc\n : admin\n"},
		{protocol: "smb", prefix: "administrator : administrator\nadministrator : 123456\nguest : guest\n"},
```

Add to `pkg/secprobe/protocol_catalog_test.go`:

```go
func TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    string
		dicts   []string
	}{
		{service: "mssql", port: 1433, want: "mssql", dicts: []string{"mssql"}},
		{service: "rdp", port: 3389, want: "rdp", dicts: []string{"rdp"}},
		{service: "vnc", port: 5900, want: "vnc", dicts: []string{"vnc"}},
		{service: "smb", port: 445, want: "smb", dicts: []string{"smb"}},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			spec, ok := LookupProtocolSpec(tt.service, tt.port)
			if !ok {
				t.Fatalf("expected protocol spec for %q/%d", tt.service, tt.port)
			}
			if spec.Name != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, spec.Name)
			}
			if !reflect.DeepEqual(spec.DictNames, tt.dicts) {
				t.Fatalf("expected dict names %v, got %v", tt.dicts, spec.DictNames)
			}
			if !ProtocolSupportsKind(tt.want, ProbeKindCredential) {
				t.Fatalf("expected %s credential probing to be declared", tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify the new protocols are not wired yet**

Run: `go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols' -v`

Expected: FAIL because `SecprobeDict` does not serve `mssql` / `rdp` / `vnc` / `smb`, and `builtinProtocolSpecs` does not declare them.

- [ ] **Step 3: Add the new dictionaries and protocol catalog entries**

Create `app/secprobe/dicts/mssql.txt`:

```text
sa : sa
sa : 123456
admin : admin
sa : P@ssw0rd
```

Create `app/secprobe/dicts/rdp.txt`:

```text
administrator : administrator
administrator : 123456
admin : admin
test : test
```

Create `app/secprobe/dicts/vnc.txt`:

```text
 : 123456
 : vnc
 : admin
 : password
```

Create `app/secprobe/dicts/smb.txt`:

```text
administrator : administrator
administrator : 123456
guest : guest
admin : admin
```

Update the `//go:embed` line in `app/assets.go` and extend `SecprobeDict`:

```go
//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/ftp.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt
var files embed.FS

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "ftp":
		return files.ReadFile("secprobe/dicts/ftp.txt")
	case "mssql":
		return files.ReadFile("secprobe/dicts/mssql.txt")
	case "mysql":
		return files.ReadFile("secprobe/dicts/mysql.txt")
	case "postgresql":
		return files.ReadFile("secprobe/dicts/postgresql.txt")
	case "rdp":
		return files.ReadFile("secprobe/dicts/rdp.txt")
	case "redis":
		return files.ReadFile("secprobe/dicts/redis.txt")
	case "smb":
		return files.ReadFile("secprobe/dicts/smb.txt")
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

Append to `builtinProtocolSpecs` in `pkg/secprobe/protocol_catalog.go`:

```go
	{
		Name:       "mssql",
		Ports:      []int{1433},
		DictNames:  []string{"mssql"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "rdp",
		Ports:      []int{3389},
		DictNames:  []string{"rdp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "vnc",
		Ports:      []int{5900},
		DictNames:  []string{"vnc"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "smb",
		Aliases:    []string{"cifs"},
		Ports:      []int{445, 139},
		DictNames:  []string{"smb"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
```

- [ ] **Step 4: Run the targeted tests to verify the wiring passes**

Run: `go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestLookupProtocolSpecIncludesPhaseOneCredentialProtocols' -v`

Expected: PASS, and the new phase-1 protocols load embedded dicts and resolve from the catalog.

- [ ] **Step 5: Commit the shared phase-1 wiring**

```bash
git add app/assets.go app/assets_test.go app/secprobe/dicts/mssql.txt app/secprobe/dicts/rdp.txt app/secprobe/dicts/vnc.txt app/secprobe/dicts/smb.txt pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go
git commit -m "feat(secprobe): 增加第一阶段协议元数据与内置字典接线" \
  -m "补充 mssql、rdp、vnc、smb 四个第一阶段协议的 protocol catalog 声明。" \
  -m "同步新增内置字典资源与 app 侧 embed 接线，保证默认 secprobe 路径可加载这些协议的凭证字典。" \
  -m "增加资产加载与 catalog 断言测试，先锁住后续协议实现所依赖的共享接入面。"
```

---

### Task 2: Implement MSSQL Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/mssql/prober.go`
- Create: `internal/secprobe/mssql/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write the failing MSSQL prober and registry tests**

Create `internal/secprobe/mssql/prober_test.go`:

```go
package mssql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe"
)

type fakeRow struct {
	value string
	err   error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	ptr := dest[0].(*string)
	*ptr = r.value
	return nil
}

type fakeDB struct {
	pingErr  error
	queryRow fakeRow
}

func (db *fakeDB) PingContext(context.Context) error { return db.pingErr }
func (db *fakeDB) QueryRowContext(context.Context, string, ...any) rowScanner { return db.queryRow }
func (db *fakeDB) Close() error { return nil }

func TestMSSQLProberFindsValidCredential(t *testing.T) {
	oldOpen := openMSSQL
	t.Cleanup(func() { openMSSQL = oldOpen })
	openMSSQL = func(string, int, string, string, time.Duration) (dbHandle, error) {
		return &fakeDB{queryRow: fakeRow{value: "Microsoft SQL Server 2022"}}, nil
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "db.local",
		ResolvedIP: "127.0.0.1",
		Port:       1433,
		Service:    "mssql",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "sa", Password: "P@ssw0rd"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed success, got %+v", result)
	}
}

func TestMSSQLProberClassifiesAuthenticationFailure(t *testing.T) {
	oldOpen := openMSSQL
	t.Cleanup(func() { openMSSQL = oldOpen })
	openMSSQL = func(string, int, string, string, time.Duration) (dbHandle, error) {
		return &fakeDB{pingErr: errors.New("login error: Login failed for user")}, nil
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "db.local",
		ResolvedIP: "127.0.0.1",
		Port:       1433,
		Service:    "mssql",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, []secprobe.Credential{
		{Username: "sa", Password: "bad"},
	})

	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "mssql credential",
			candidate: SecurityCandidate{Service: "mssql", Port: 1433},
			kind:      ProbeKindCredential,
			want:      "mssql",
		},
```

- [ ] **Step 2: Run the tests to verify MSSQL is still missing**

Run: `go test ./internal/secprobe/mssql ./pkg/secprobe -run 'TestMSSQLProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: FAIL because the `mssql` package does not exist yet and the default registry does not register an MSSQL prober.

- [ ] **Step 3: Add the MSSQL dependency and minimal prober implementation**

Run: `go get github.com/microsoft/go-mssqldb`

Create `internal/secprobe/mssql/prober.go`:

```go
package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/microsoft/go-mssqldb"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type dbHandle interface {
	PingContext(ctx context.Context) error
	QueryRowContext(ctx context.Context, query string, args ...any) rowScanner
	Close() error
}

type sqlDB struct{ *sql.DB }

func (db sqlDB) QueryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	return db.DB.QueryRowContext(ctx, query, args...)
}

var openMSSQL = func(host string, port int, username, password string, timeout time.Duration) (dbHandle, error) {
	timeoutSeconds := int(timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 1
	}
	connStr := fmt.Sprintf(
		"server=%s;user id=%s;password=%s;port=%d;encrypt=disable;connection timeout=%d",
		host, username, password, port, timeoutSeconds,
	)
	db, err := sql.Open("sqlserver", connStr)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	return sqlDB{DB: db}, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "mssql" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "mssql" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			result.FailureReason = ctxFailureReason(err)
			return result
		}

		result.Stage = core.StageAttempted
		db, err := openMSSQL(candidate.ResolvedIP, candidate.Port, cred.Username, cred.Password, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		pingCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		err = db.PingContext(pingCtx)
		cancel()
		if err != nil {
			_ = db.Close()
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		version := "Microsoft SQL Server"
		queryCtx, queryCancel := context.WithTimeout(ctx, opts.Timeout)
		if err := db.QueryRowContext(queryCtx, "SELECT @@VERSION").Scan(&version); err != nil {
			version = "Microsoft SQL Server"
		}
		queryCancel()
		_ = db.Close()

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = fmt.Sprintf("MSSQL authentication succeeded: %s", strings.TrimSpace(version))
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	mssqlprobe "github.com/yrighc/gomap/internal/secprobe/mssql"
```

and:

```go
	r.registerCoreProber(mssqlprobe.New())
```

- [ ] **Step 4: Run the MSSQL tests and registry lookup tests**

Run: `go test ./internal/secprobe/mssql ./pkg/secprobe -run 'TestMSSQLProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: PASS, and the default registry resolves `mssql` credential probing.

- [ ] **Step 5: Commit the MSSQL protocol batch**

```bash
git add go.mod go.sum internal/secprobe/mssql/prober.go internal/secprobe/mssql/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 接入 mssql 凭证探测协议" \
  -m "新增 mssql credential prober，并接入默认 secprobe registry。" \
  -m "实现基于连接与 PingContext 的认证确认逻辑，补充成功与认证失败分类测试。" \
  -m "保持现有 secprobe 结果模型不变，只在协议目录中增加新的内置实现。"
```

---

### Task 3: Implement RDP Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/rdp/prober.go`
- Create: `internal/secprobe/rdp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write the failing RDP tests and registry lookup assertion**

Create `internal/secprobe/rdp/prober_test.go`:

```go
package rdp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestRDPProberFindsValidCredential(t *testing.T) {
	oldVerify := verifyProtocol
	oldLoginSSL := loginForSSL
	oldLoginRDP := loginForRDP
	t.Cleanup(func() {
		verifyProtocol = oldVerify
		loginForSSL = oldLoginSSL
		loginForRDP = oldLoginRDP
	})

	verifyProtocol = func(string) (string, error) { return protocolSSL, nil }
	loginForSSL = func(string, string, string, string) error { return nil }

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "win.local",
		ResolvedIP: "127.0.0.1",
		Port:       3389,
		Service:    "rdp",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "administrator", Password: "P@ssw0rd"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed success, got %+v", result)
	}
}

func TestRDPProberClassifiesAuthenticationFailure(t *testing.T) {
	oldVerify := verifyProtocol
	oldLoginSSL := loginForSSL
	oldLoginRDP := loginForRDP
	t.Cleanup(func() {
		verifyProtocol = oldVerify
		loginForSSL = oldLoginSSL
		loginForRDP = oldLoginRDP
	})

	verifyProtocol = func(string) (string, error) { return protocolRDP, nil }
	loginForRDP = func(string, string, string, string) error {
		return errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "win.local",
		ResolvedIP: "127.0.0.1",
		Port:       3389,
		Service:    "rdp",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, []secprobe.Credential{
		{Username: "administrator", Password: "bad"},
	})

	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "rdp credential",
			candidate: SecurityCandidate{Service: "rdp", Port: 3389},
			kind:      ProbeKindCredential,
			want:      "rdp",
		},
```

- [ ] **Step 2: Run the tests to verify the RDP package is still absent**

Run: `go test ./internal/secprobe/rdp ./pkg/secprobe -run 'TestRDPProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: FAIL because the `rdp` package does not exist yet and `RegisterDefaultProbers` does not include it.

- [ ] **Step 3: Add the RDP dependency and implement the prober with injectable protocol hooks**

Run: `go get github.com/XTeam-Wing/x-crack`

Create `internal/secprobe/rdp/prober.go`:

```go
package rdp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	grdp "github.com/XTeam-Wing/x-crack/pkg/protocols/grdp"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

const (
	protocolSSL = "ssl"
	protocolRDP = "rdp"
)

var verifyProtocol = func(target string) (string, error) {
	return grdp.VerifyProtocol(target), nil
}

var loginForSSL = func(target, host, username, password string) error {
	return grdp.LoginForSSL(target, host, username, password)
}

var loginForRDP = func(target, host, username, password string) error {
	return grdp.LoginForRDP(target, host, username, password)
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "rdp" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "rdp" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}

	target := fmt.Sprintf("%s:%d", candidate.ResolvedIP, candidate.Port)
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			result.FailureReason = ctxFailureReason(err)
			return result
		}

		result.Stage = core.StageAttempted
		protocol, err := verifyProtocol(target)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		if protocol == protocolSSL {
			err = loginForSSL(target, candidate.ResolvedIP, cred.Username, cred.Password)
		} else {
			err = loginForRDP(target, candidate.ResolvedIP, cred.Username, cred.Password)
		}
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = "RDP authentication succeeded"
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}

func classifyFailure(err error) core.FailureReason {
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "login"), strings.Contains(text, "credential"), strings.Contains(text, "denied"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "refused"), strings.Contains(text, "reset"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	switch {
	case errors.Is(err, context.Canceled):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	rdpprobe "github.com/yrighc/gomap/internal/secprobe/rdp"
```

and:

```go
	r.registerCoreProber(rdpprobe.New())
```

- [ ] **Step 4: Run the RDP tests and registry lookup tests**

Run: `go test ./internal/secprobe/rdp ./pkg/secprobe -run 'TestRDPProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: PASS, and the default registry resolves `rdp` credential probing.

- [ ] **Step 5: Commit the RDP protocol batch**

```bash
git add go.mod go.sum internal/secprobe/rdp/prober.go internal/secprobe/rdp/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 接入 rdp 凭证探测协议" \
  -m "新增 rdp credential prober，并通过默认 registry 暴露给 secprobe 执行链。" \
  -m "RDP 认证确认逻辑复用 Chujiu_reload 所采用的 grdp 依赖，测试侧使用可注入协议探测钩子避免重型集成环境。" \
  -m "补充成功、认证失败与注册查找断言，保持 secprobe 统一结果语义。"
```

---

### Task 4: Implement VNC Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/vnc/prober.go`
- Create: `internal/secprobe/vnc/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write the failing VNC tests and registry lookup assertion**

Create `internal/secprobe/vnc/prober_test.go`:

```go
package vnc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe"
)

type fakeClient struct{}

func (fakeClient) Close() error { return nil }

func TestVNCProberAcceptsPasswordOnlyCredential(t *testing.T) {
	oldDial := dialContext
	oldClient := newClient
	t.Cleanup(func() {
		dialContext = oldDial
		newClient = oldClient
	})

	dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}
	newClient = func(net.Conn, string) (clientConn, error) { return fakeClient{}, nil }

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "", Password: "123456"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed success, got %+v", result)
	}
}

func TestVNCProberClassifiesAuthenticationFailure(t *testing.T) {
	oldDial := dialContext
	oldClient := newClient
	t.Cleanup(func() {
		dialContext = oldDial
		newClient = oldClient
	})

	dialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}
	newClient = func(net.Conn, string) (clientConn, error) {
		return nil, errors.New("authentication failed")
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "vnc.local",
		ResolvedIP: "127.0.0.1",
		Port:       5900,
		Service:    "vnc",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, []secprobe.Credential{
		{Username: "", Password: "bad"},
	})

	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "vnc credential",
			candidate: SecurityCandidate{Service: "vnc", Port: 5900},
			kind:      ProbeKindCredential,
			want:      "vnc",
		},
```

- [ ] **Step 2: Run the tests to verify the VNC package is still absent**

Run: `go test ./internal/secprobe/vnc ./pkg/secprobe -run 'TestVNCProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: FAIL because the `vnc` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Add the VNC dependency and implement the password-only prober**

Run: `go get github.com/mitchellh/go-vnc`

Create `internal/secprobe/vnc/prober.go`:

```go
package vnc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	gvnc "github.com/mitchellh/go-vnc"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type clientConn interface {
	Close() error
}

var dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

var newClient = func(conn net.Conn, password string) (clientConn, error) {
	return gvnc.Client(conn, &gvnc.ClientConfig{
		Auth: []gvnc.ClientAuth{
			&gvnc.PasswordAuth{Password: password},
		},
	})
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "vnc" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "vnc" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}

	address := fmt.Sprintf("%s:%d", candidate.ResolvedIP, candidate.Port)
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			result.FailureReason = ctxFailureReason(err)
			return result
		}
		result.Stage = core.StageAttempted

		conn, err := dialContext(ctx, "tcp", address)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		client, err := newClient(conn, cred.Password)
		if err != nil {
			_ = conn.Close()
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		_ = client.Close()
		_ = conn.Close()

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = "VNC authentication succeeded"
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}

func classifyFailure(err error) core.FailureReason {
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "password"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "refused"), strings.Contains(text, "reset"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	switch {
	case errors.Is(err, context.Canceled):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	vncprobe "github.com/yrighc/gomap/internal/secprobe/vnc"
```

and:

```go
	r.registerCoreProber(vncprobe.New())
```

- [ ] **Step 4: Run the VNC tests and registry lookup tests**

Run: `go test ./internal/secprobe/vnc ./pkg/secprobe -run 'TestVNCProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: PASS, and password-only VNC credentials work through the standard credential result contract.

- [ ] **Step 5: Commit the VNC protocol batch**

```bash
git add go.mod go.sum internal/secprobe/vnc/prober.go internal/secprobe/vnc/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 接入 vnc 凭证探测协议" \
  -m "新增 vnc credential prober，并支持基于空用户名加密码的默认字典尝试方式。" \
  -m "实现可注入的 VNC 连接与客户端握手钩子，使用单元测试覆盖成功和认证失败场景。" \
  -m "同步将 vnc 注册到默认 secprobe registry，保持结果阶段和 finding 语义一致。"
```

---

### Task 5: Implement SMB Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/smb/prober.go`
- Create: `internal/secprobe/smb/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write the failing SMB tests and registry lookup assertion**

Create `internal/secprobe/smb/prober_test.go`:

```go
package smb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe"
)

type fakeMount struct{}

func (fakeMount) Umount() error { return nil }

type fakeSession struct {
	mountErr error
}

func (s fakeSession) Mount(string) (shareMount, error) { return fakeMount{}, s.mountErr }
func (s fakeSession) Logoff() error { return nil }

func TestSMBProberFindsValidCredential(t *testing.T) {
	oldDial := dialSession
	t.Cleanup(func() { dialSession = oldDial })
	dialSession = func(context.Context, string, string, string, time.Duration) (session, error) {
		return fakeSession{}, nil
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "smb.local",
		ResolvedIP: "127.0.0.1",
		Port:       445,
		Service:    "smb",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "administrator", Password: "123456"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed success, got %+v", result)
	}
}

func TestSMBProberClassifiesAuthenticationFailure(t *testing.T) {
	oldDial := dialSession
	t.Cleanup(func() { dialSession = oldDial })
	dialSession = func(context.Context, string, string, string, time.Duration) (session, error) {
		return nil, errors.New("nt status logon failure")
	}

	result := New().Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "smb.local",
		ResolvedIP: "127.0.0.1",
		Port:       445,
		Service:    "smb",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second}, []secprobe.Credential{
		{Username: "administrator", Password: "bad"},
	})

	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "smb credential",
			candidate: SecurityCandidate{Service: "smb", Port: 445},
			kind:      ProbeKindCredential,
			want:      "smb",
		},
```

- [ ] **Step 2: Run the tests to verify the SMB package is still absent**

Run: `go test ./internal/secprobe/smb ./pkg/secprobe -run 'TestSMBProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: FAIL because the `smb` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Add the SMB dependency and implement the IPC$ confirmation prober**

Run: `go get github.com/hirochachacha/go-smb2`

Create `internal/secprobe/smb/prober.go`:

```go
package smb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	gsmb2 "github.com/hirochachacha/go-smb2"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type shareMount interface {
	Umount() error
}

type session interface {
	Mount(name string) (shareMount, error)
	Logoff() error
}

var dialSession = func(ctx context.Context, address, username, password string, timeout time.Duration) (session, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	dialer := &gsmb2.Dialer{
		Initiator: &gsmb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}
	s, err := dialer.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return s, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "smb" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "smb" }

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}

	address := fmt.Sprintf("%s:%d", candidate.ResolvedIP, candidate.Port)
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			result.FailureReason = ctxFailureReason(err)
			return result
		}
		result.Stage = core.StageAttempted

		s, err := dialSession(ctx, address, cred.Username, cred.Password, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		mount, err := s.Mount("IPC$")
		if err != nil {
			_ = s.Logoff()
			result.Error = err.Error()
			result.FailureReason = classifyFailure(err)
			continue
		}

		_ = mount.Umount()
		_ = s.Logoff()

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = "SMB authentication succeeded via IPC$ mount"
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}

func classifyFailure(err error) core.FailureReason {
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "logon failure"), strings.Contains(text, "access denied"), strings.Contains(text, "nt status"), strings.Contains(text, "authentication"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "refused"), strings.Contains(text, "reset"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	switch {
	case errors.Is(err, context.Canceled):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	smbprobe "github.com/yrighc/gomap/internal/secprobe/smb"
```

and:

```go
	r.registerCoreProber(smbprobe.New())
```

- [ ] **Step 4: Run the SMB tests and registry lookup tests**

Run: `go test ./internal/secprobe/smb ./pkg/secprobe -run 'TestSMBProber|TestRegisterDefaultProbersRegistersBuiltinLookupTargets' -v`

Expected: PASS, and `smb` resolves through the default registry with IPC$-based confirmation semantics.

- [ ] **Step 5: Commit the SMB protocol batch**

```bash
git add go.mod go.sum internal/secprobe/smb/prober.go internal/secprobe/smb/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go
git commit -m "feat(secprobe): 接入 smb 凭证探测协议" \
  -m "新增 smb credential prober，并使用 IPC$ 共享挂载作为认证成功的确认依据。" \
  -m "测试通过可注入 session 钩子覆盖成功与认证失败路径，避免引入额外重型集成环境。" \
  -m "同步注册 smb 默认 prober，保持 secprobe 主执行链和输出契约不变。"
```

---

### Task 6: Sync README and Run the Phase-1 Regression Slice

**Files:**
- Modify: `README.md`
- Modify: `pkg/secprobe/default_registry_test.go`

- [ ] **Step 1: Write the failing README-oriented assertion by locking the full default registry set**

Extend `pkg/secprobe/default_registry_test.go` with:

```go
func TestDefaultRegistryContainsPhaseOneCredentialProtocols(t *testing.T) {
	r := DefaultRegistry()

	for _, candidate := range []SecurityCandidate{
		{Service: "mssql", Port: 1433},
		{Service: "rdp", Port: 3389},
		{Service: "vnc", Port: 5900},
		{Service: "smb", Port: 445},
	} {
		if _, ok := r.Lookup(candidate, ProbeKindCredential); !ok {
			t.Fatalf("expected default registry to contain %+v", candidate)
		}
	}
}
```

- [ ] **Step 2: Run the final phase-1 regression slice before documentation sync**

Run: `go test ./app ./pkg/secprobe ./internal/secprobe/mssql ./internal/secprobe/rdp ./internal/secprobe/vnc ./internal/secprobe/smb -v`

Expected: PASS after Tasks 1-5 are complete.

- [ ] **Step 3: Update README to advertise the new phase-1 built-ins**

In `README.md`, update the secprobe examples and capability notes so the supported credential protocols explicitly include:

```md
- `-protocols`: 限定协议，逗号分隔，例如 `ssh,redis,mssql,rdp,vnc,smb`
```

and add a short built-in support note under the secprobe section:

```md
当前内置 `credential` 协议包括：

- `ftp`
- `ssh`
- `telnet`
- `mysql`
- `postgresql`
- `redis`
- `mssql`
- `rdp`
- `vnc`
- `smb`
```

- [ ] **Step 4: Re-run the regression slice after the README change**

Run: `go test ./app ./pkg/secprobe ./internal/secprobe/mssql ./internal/secprobe/rdp ./internal/secprobe/vnc ./internal/secprobe/smb -v`

Expected: PASS, with no documentation-induced code changes required.

- [ ] **Step 5: Commit the phase-1 documentation and regression lock**

```bash
git add README.md pkg/secprobe/default_registry_test.go
git commit -m "docs(secprobe): 更新第一阶段新增协议说明" \
  -m "更新 README 中 secprobe 的内置协议说明和示例命令，纳入 mssql、rdp、vnc、smb 四个第一阶段协议。" \
  -m "补充默认 registry 的最终断言测试，锁住第一阶段协议集合，便于后续第二阶段继续扩展。" \
  -m "完成 phase-1 回归切片验证，为后续独立编写第二阶段计划提供稳定基线。"
```

---

## Self-Review Checklist

Before executing this plan, verify:

1. Every phase-1 protocol is covered by at least one dedicated task:
   - `mssql`: Task 2
   - `rdp`: Task 3
   - `vnc`: Task 4
   - `smb`: Task 5
2. Shared dictionary and catalog wiring is isolated in Task 1.
3. Documentation sync is isolated in Task 6.
4. No task introduces Phase-2 or Phase-3 protocols.
5. Every protocol task preserves the existing `credential-valid` / `confirmed` result contract.
