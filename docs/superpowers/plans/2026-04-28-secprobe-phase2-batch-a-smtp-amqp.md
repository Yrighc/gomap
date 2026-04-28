# Secprobe Phase 2 Batch A (SMTP + AMQP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the phase-2 batch-A `credential` protocols, `smtp` and `amqp`, to `GoMap secprobe` without changing the existing public API or weakening the confirmed-success contract.

**Architecture:** Reuse the phase-1 extension pattern: shared metadata and embedded dictionaries land first, then each protocol gets an isolated `internal/secprobe/<protocol>/prober.go` implementation with protocol-specific confirmation logic. `smtp` stays dependency-light by using the Go standard library plus a tiny local `AUTH LOGIN` helper, while `amqp` uses the maintained RabbitMQ AMQP 0-9-1 client and confirms success only after authenticated connection/channel setup.

**Tech Stack:** Go 1.24.6, existing `pkg/secprobe` and `internal/secprobe/core` contracts, embedded dictionaries in `app/secprobe/dicts`, Go standard library `net/smtp` / `net/textproto` / `crypto/tls`, `github.com/rabbitmq/amqp091-go`, Go testing package.

---

## Scope Decomposition

The approved phase-2 spec covers:

- Batch A `credential`: `smtp`, `amqp`
- Batch B `credential`: `oracle`, `snmp`

This plan intentionally covers only Batch A so we can establish a second stable protocol batch before handling the heavier `oracle` / `snmp` semantics.

## File Map

### Shared wiring

- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Create: `app/secprobe/dicts/smtp.txt`
- Create: `app/secprobe/dicts/amqp.txt`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`

### Protocol implementations

- Create: `internal/secprobe/smtp/prober.go`
- Create: `internal/secprobe/smtp/prober_test.go`
- Create: `internal/secprobe/amqp/prober.go`
- Create: `internal/secprobe/amqp/prober_test.go`

### Registry, candidates, docs, dependencies

- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`
- Modify: `README.md`
- Modify: `go.mod`
- Modify: `go.sum`

---

### Task 1: Wire Batch-A Metadata and Embedded Dictionaries

**Files:**
- Create: `app/secprobe/dicts/smtp.txt`
- Create: `app/secprobe/dicts/amqp.txt`
- Modify: `app/assets.go`
- Modify: `app/assets_test.go`
- Modify: `pkg/secprobe/protocol_catalog.go`
- Modify: `pkg/secprobe/protocol_catalog_test.go`
- Modify: `pkg/secprobe/assets_test.go`

- [ ] **Step 1: Write the failing asset, builtin-credentials, and catalog tests**

Update `app/assets_test.go` by extending `TestEmbeddedSecprobeDictResourcesLoad`:

```go
		{protocol: "smtp", snippets: []string{"admin : 123456", "postmaster : postmaster"}},
		{protocol: "amqp", snippets: []string{"guest : guest", "rabbitmq : rabbitmq"}},
```

Extend `pkg/secprobe/assets_test.go`:

```go
func TestBuiltinCredentialsLoadByProtocol(t *testing.T) {
	tests := []string{
		"ssh", "ftp", "mysql", "postgresql", "redis", "telnet",
		"mssql", "rdp", "smb", "vnc", "smtp", "amqp",
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
```

Add to `pkg/secprobe/protocol_catalog_test.go`:

```go
func TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols(t *testing.T) {
	tests := []struct {
		name    string
		service string
		port    int
		want    ProtocolSpec
	}{
		{
			name:    "smtp alias",
			service: "smtps",
			want: ProtocolSpec{
				Name:       "smtp",
				Aliases:    []string{"smtps"},
				Ports:      []int{25, 465, 587},
				DictNames:  []string{"smtp"},
				ProbeKinds: []ProbeKind{ProbeKindCredential},
			},
		},
		{
			name: "amqp port fallback",
			port: 5672,
			want: ProtocolSpec{
				Name:       "amqp",
				Aliases:    []string{"amqps"},
				Ports:      []int{5672, 5671},
				DictNames:  []string{"amqp"},
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

- [ ] **Step 2: Run the tests to verify the new batch-A protocols are not wired yet**

Run:

```bash
go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestBuiltinCredentialsLoadByProtocol|TestBuiltinCredentialsLoadByProtocolAlias|TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols' -v
```

Expected: FAIL because `smtp` / `amqp` dict resources do not exist yet and `builtinProtocolSpecs` does not declare them.

- [ ] **Step 3: Add the new dictionaries and protocol catalog entries**

Create `app/secprobe/dicts/smtp.txt`:

```text
admin : admin
admin : 123456
postmaster : postmaster
test : test
```

Create `app/secprobe/dicts/amqp.txt`:

```text
guest : guest
admin : admin
rabbitmq : rabbitmq
test : test
```

Update `app/assets.go`:

```go
//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/amqp.txt secprobe/dicts/ftp.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/smtp.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt
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
		Name:       "smtp",
		Aliases:    []string{"smtps"},
		Ports:      []int{25, 465, 587},
		DictNames:  []string{"smtp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
	{
		Name:       "amqp",
		Aliases:    []string{"amqps"},
		Ports:      []int{5672, 5671},
		DictNames:  []string{"amqp"},
		ProbeKinds: []ProbeKind{ProbeKindCredential},
	},
```

- [ ] **Step 4: Run the targeted tests to verify the shared wiring passes**

Run:

```bash
go test ./app ./pkg/secprobe -run 'TestEmbeddedSecprobeDictResourcesLoad|TestBuiltinCredentialsLoadByProtocol|TestBuiltinCredentialsLoadByProtocolAlias|TestLookupProtocolSpecIncludesPhaseTwoBatchACredentialProtocols' -v
```

Expected: PASS, and `smtp` / `amqp` now load builtin dictionaries and resolve from the catalog.

- [ ] **Step 5: Commit the batch-A shared wiring**

```bash
git add app/assets.go app/assets_test.go app/secprobe/dicts/smtp.txt app/secprobe/dicts/amqp.txt pkg/secprobe/protocol_catalog.go pkg/secprobe/protocol_catalog_test.go pkg/secprobe/assets_test.go
git commit -m "feat(secprobe): 增加第二阶段第一批协议元数据与内置字典接线" \
  -m "补充 smtp 与 amqp 两个 batch-a credential 协议的 protocol catalog 声明、默认端口、别名和 DictNames。" \
  -m "同步新增内置字典资源与 app embed 接线，并覆盖 builtin credentials 的 canonical 与 alias 加载路径。" \
  -m "通过共享接线测试先锁住后续 smtp/amqp prober 实现依赖的 catalog 与字典闭环。"
```

---

### Task 2: Implement SMTP Credential Probing

**Files:**
- Create: `internal/secprobe/smtp/prober.go`
- Create: `internal/secprobe/smtp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: Write the failing SMTP prober, registry, and candidate tests**

Create `internal/secprobe/smtp/prober_test.go`:

```go
package smtp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeSession struct {
	mechs       map[string]bool
	authErrByMech map[string]error
	closed      bool
}

func (s *fakeSession) SupportsAuth(mech string) bool { return s.mechs[mech] }

func (s *fakeSession) Authenticate(mech, username, password string) error {
	if err := s.authErrByMech[mech]; err != nil {
		return err
	}
	if username == "mailer" && password == "correct" {
		return nil
	}
	return errors.New("535 authentication failed")
}

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

func TestSMTPProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalOpen := openSMTPSession
	t.Cleanup(func() { openSMTPSession = originalOpen })

	openSMTPSession = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) (smtpSession, error) {
		return &fakeSession{mechs: map[string]bool{"PLAIN": true}}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mail.local",
		ResolvedIP: "127.0.0.1",
		Port:       25,
		Service:    "smtp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []core.Credential{
		{Username: "mailer", Password: "wrong"},
		{Username: "mailer", Password: "correct"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed smtp success, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding, got %+v", result)
	}
}

func TestSMTPProberFallsBackFromPlainToLogin(t *testing.T) {
	originalOpen := openSMTPSession
	t.Cleanup(func() { openSMTPSession = originalOpen })

	openSMTPSession = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) (smtpSession, error) {
		return &fakeSession{
			mechs:         map[string]bool{"PLAIN": false, "LOGIN": true},
			authErrByMech: map[string]error{},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mail.local",
		ResolvedIP: "127.0.0.1",
		Port:       587,
		Service:    "smtp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []core.Credential{
		{Username: "mailer", Password: "correct"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected login fallback to confirm success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected SMTP success evidence, got %+v", result)
	}
}

func TestSMTPProberDoesNotTreatAuthCapabilityWithoutSuccessAsConfirmed(t *testing.T) {
	originalOpen := openSMTPSession
	t.Cleanup(func() { openSMTPSession = originalOpen })

	openSMTPSession = func(context.Context, core.SecurityCandidate, core.CredentialProbeOptions) (smtpSession, error) {
		return &fakeSession{
			mechs:         map[string]bool{"PLAIN": true, "LOGIN": true},
			authErrByMech: map[string]error{"PLAIN": errors.New("535 authentication failed"), "LOGIN": errors.New("535 authentication failed")},
		}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mail.local",
		ResolvedIP: "127.0.0.1",
		Port:       25,
		Service:    "smtp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "mailer", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected smtp auth failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}

func TestSMTPDialPlanUsesImplicitTLSForSMTPSPort(t *testing.T) {
	plan := smtpDialPlan(core.SecurityCandidate{ResolvedIP: "127.0.0.1", Port: 465})
	if !plan.implicitTLS {
		t.Fatalf("expected implicit TLS on port 465, got %+v", plan)
	}
	if plan.address != "127.0.0.1:465" {
		t.Fatalf("expected 127.0.0.1:465, got %+v", plan)
	}
}
```

Extend `pkg/secprobe/default_registry_test.go` inside `TestRegisterDefaultProbersRegistersBuiltinLookupTargets`:

```go
		{
			name:      "smtp credential",
			candidate: SecurityCandidate{Service: "smtp", Port: 25},
			kind:      ProbeKindCredential,
			want:      "smtp",
		},
```

Extend `pkg/secprobe/candidates_test.go`:

```go
func TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 25, Open: true, Service: "smtp"},
			{Port: 445, Open: true, Service: "cifs"},
			{Port: 1433, Open: true, Service: "mssql"},
			{Port: 3389, Open: true, Service: "rdp"},
			{Port: 5900, Open: true, Service: "vnc"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 6 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" ||
		candidates[1].Service != "smtp" ||
		candidates[2].Service != "smb" ||
		candidates[3].Service != "mssql" ||
		candidates[4].Service != "rdp" ||
		candidates[5].Service != "vnc" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
}
```

- [ ] **Step 2: Run the tests to verify SMTP is not implemented yet**

Run:

```bash
go test ./internal/secprobe/smtp ./pkg/secprobe -run 'TestSMTPProber|TestSMTPDialPlan|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols' -v
```

Expected: FAIL because the `smtp` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Implement the SMTP prober and default registry wiring**

Create `internal/secprobe/smtp/prober.go`:

```go
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	stdsmtp "net/smtp"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

type smtpSession interface {
	SupportsAuth(mech string) bool
	Authenticate(mech, username, password string) error
	Close() error
}

type smtpDialDecision struct {
	address     string
	implicitTLS bool
}

type smtpClientSession struct {
	client    *stdsmtp.Client
	host      string
	authParam string
}

var openSMTPSession = defaultOpenSMTPSession

func (prober) Name() string { return "smtp" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "smtp" }

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
			result.FailureReason = classifySMTPFailure(err)
			return result
		}
		result.Stage = core.StageAttempted

		session, err := openSMTPSession(ctx, candidate, opts)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifySMTPFailure(err)
			if isTerminalContextError(err) {
				return result
			}
			continue
		}

		mech := preferredSMTPMechanism(session)
		if mech == "" {
			_ = session.Close()
			result.Error = "smtp server does not advertise AUTH PLAIN or AUTH LOGIN"
			result.FailureReason = core.FailureReasonInsufficientConfirmation
			continue
		}

		err = session.Authenticate(mech, cred.Username, cred.Password)
		_ = session.Close()
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifySMTPFailure(err)
			if isTerminalContextError(err) {
				return result
			}
			continue
		}

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = fmt.Sprintf("SMTP authentication succeeded (%s)", mech)
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}

func preferredSMTPMechanism(session smtpSession) string {
	if session.SupportsAuth("PLAIN") {
		return "PLAIN"
	}
	if session.SupportsAuth("LOGIN") {
		return "LOGIN"
	}
	return ""
}

func smtpDialPlan(candidate core.SecurityCandidate) smtpDialDecision {
	return smtpDialDecision{
		address:     net.JoinHostPort(candidate.ResolvedIP, fmt.Sprintf("%d", candidate.Port)),
		implicitTLS: candidate.Port == 465,
	}
}

func (s *smtpClientSession) SupportsAuth(mech string) bool {
	for _, token := range strings.Fields(strings.ToUpper(s.authParam)) {
		if token == mech {
			return true
		}
	}
	return false
}

func (s *smtpClientSession) Authenticate(mech, username, password string) error {
	switch mech {
	case "PLAIN":
		return s.client.Auth(stdsmtp.PlainAuth("", username, password, s.host))
	case "LOGIN":
		return s.client.Auth(&loginAuth{username: username, password: password})
	default:
		return fmt.Errorf("unsupported smtp auth mechanism: %s", mech)
	}
}

func (s *smtpClientSession) Close() error {
	if err := s.client.Quit(); err != nil {
		return s.client.Close()
	}
	return nil
}

func defaultOpenSMTPSession(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions) (smtpSession, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	plan := smtpDialPlan(candidate)
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{ServerName: candidate.ResolvedIP, InsecureSkipVerify: true}

	var conn net.Conn
	var err error
	if plan.implicitTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", plan.address, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", plan.address)
	}
	if err != nil {
		return nil, err
	}

	client, err := stdsmtp.NewClient(conn, candidate.ResolvedIP)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if !plan.implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				_ = client.Close()
				return nil, err
			}
		}
	}

	_, authParam := client.Extension("AUTH")
	return &smtpClientSession{
		client:    client,
		host:      candidate.ResolvedIP,
		authParam: authParam,
	}, nil
}

func classifySMTPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "535"),
		strings.Contains(text, "534"),
		strings.Contains(text, "authentication"),
		strings.Contains(text, "password"),
		strings.Contains(text, "login"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset"),
		strings.Contains(text, "tls"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}
```

Implementation notes for the same file:

```go
// Keep AUTH LOGIN local instead of adding a new dependency.
type loginAuth struct {
	username string
	password string
	step     int
}

func (a *loginAuth) Start(server *stdsmtp.ServerInfo) (string, []byte, error) {
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	default:
		return nil, errors.New("smtp LOGIN requested too many steps")
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

func isTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	smtpprobe "github.com/yrighc/gomap/internal/secprobe/smtp"
```

and register it:

```go
	r.registerCoreProber(smtpprobe.New())
```

- [ ] **Step 4: Run the SMTP tests and registry lookup tests**

Run:

```bash
go test ./internal/secprobe/smtp ./pkg/secprobe -run 'TestSMTPProber|TestSMTPDialPlan|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: PASS, and the default registry resolves `smtp` credential probing.

- [ ] **Step 5: Commit the SMTP protocol batch**

```bash
git add internal/secprobe/smtp/prober.go internal/secprobe/smtp/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go
git commit -m "feat(secprobe): 接入 smtp 凭证探测与默认注册" \
  -m "新增 smtp credential prober，第一版只支持 AUTH PLAIN 与 AUTH LOGIN 两条最常见认证路径。" \
  -m "成功判定必须建立在真实 SMTP 认证被服务端接受的基础上，不因 EHLO capability、AUTH 广告或端口开放误报 credential-valid。" \
  -m "同步接入默认 registry 与候选测试，锁住 smtp 在 batch-a 中的默认接线行为。"
```

---

### Task 3: Implement AMQP Credential Probing

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/secprobe/amqp/prober.go`
- Create: `internal/secprobe/amqp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: Write the failing AMQP prober, dependency, registry, and candidate tests**

Create `internal/secprobe/amqp/prober_test.go`:

```go
package amqp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type fakeChannel struct{ closed bool }

func (c *fakeChannel) Close() error {
	c.closed = true
	return nil
}

type fakeConnection struct {
	channelErr error
	closed     bool
}

func (c *fakeConnection) Channel() (amqpChannel, error) {
	if c.channelErr != nil {
		return nil, c.channelErr
	}
	return &fakeChannel{}, nil
}

func (c *fakeConnection) Close() error {
	c.closed = true
	return nil
}

func TestAMQPProberFindsValidCredentialAndConfirmsStage(t *testing.T) {
	originalDial := dialAMQP
	t.Cleanup(func() { dialAMQP = originalDial })

	dialAMQP = func(context.Context, core.SecurityCandidate, core.Credential, core.CredentialProbeOptions) (amqpConnection, error) {
		return &fakeConnection{}, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mq.local",
		ResolvedIP: "127.0.0.1",
		Port:       5672,
		Service:    "amqp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []core.Credential{
		{Username: "guest", Password: "wrong"},
		{Username: "guest", Password: "guest"},
	})

	if !result.Success || result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed amqp success, got %+v", result)
	}
}

func TestAMQPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalDial := dialAMQP
	t.Cleanup(func() { dialAMQP = originalDial })

	dialAMQP = func(context.Context, core.SecurityCandidate, core.Credential, core.CredentialProbeOptions) (amqpConnection, error) {
		return nil, errors.New("Exception (403) Reason: \"ACCESS_REFUSED - Login was refused\"")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mq.local",
		ResolvedIP: "127.0.0.1",
		Port:       5672,
		Service:    "amqp",
	}, core.CredentialProbeOptions{Timeout: 5 * time.Second}, []core.Credential{
		{Username: "guest", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected amqp auth failure, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure, got %+v", result)
	}
}

func TestBuildAMQPURLUsesTLSForSecurePort(t *testing.T) {
	got := buildAMQPURL(core.SecurityCandidate{ResolvedIP: "127.0.0.1", Port: 5671}, core.Credential{
		Username: "guest",
		Password: "guest",
	})
	if got != "amqps://guest:guest@127.0.0.1:5671/" {
		t.Fatalf("expected secure amqps url, got %q", got)
	}
}
```

Update `pkg/secprobe/default_registry_test.go`:

```go
		{
			name:      "amqp credential",
			candidate: SecurityCandidate{Service: "amqp", Port: 5672},
			kind:      ProbeKindCredential,
			want:      "amqp",
		},
```

Extend `pkg/secprobe/candidates_test.go`:

```go
func TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh"},
			{Port: 25, Open: true, Service: "smtp"},
			{Port: 445, Open: true, Service: "cifs"},
			{Port: 1433, Open: true, Service: "mssql"},
			{Port: 3389, Open: true, Service: "rdp"},
			{Port: 5672, Open: true, Service: "amqp"},
			{Port: 5900, Open: true, Service: "vnc"},
		},
	}

	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 7 {
		t.Fatalf("expected registered default candidates, got %#v", candidates)
	}
	if candidates[0].Service != "ssh" ||
		candidates[1].Service != "smtp" ||
		candidates[2].Service != "smb" ||
		candidates[3].Service != "mssql" ||
		candidates[4].Service != "rdp" ||
		candidates[5].Service != "amqp" ||
		candidates[6].Service != "vnc" {
		t.Fatalf("unexpected candidate order: %#v", candidates)
	}
}
```

- [ ] **Step 2: Run the tests to verify AMQP is not implemented yet**

Run:

```bash
go test ./internal/secprobe/amqp ./pkg/secprobe -run 'TestAMQPProber|TestBuildAMQPURL|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols' -v
```

Expected: FAIL because the `amqp` package does not exist yet and the default registry does not include it.

- [ ] **Step 3: Add the AMQP dependency, prober implementation, and registry wiring**

Update `go.mod` by adding:

```go
require github.com/rabbitmq/amqp091-go v1.11.0
```

Create `internal/secprobe/amqp/prober.go`:

```go
package amqp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

type amqpChannel interface {
	Close() error
}

type amqpConnection interface {
	Channel() (amqpChannel, error)
	Close() error
}

type amqpChannelWrapper struct {
	ch *amqp091.Channel
}

func (c *amqpChannelWrapper) Close() error { return c.ch.Close() }

type amqpConnectionWrapper struct {
	conn *amqp091.Connection
}

func (c *amqpConnectionWrapper) Channel() (amqpChannel, error) {
	ch, err := c.conn.Channel()
	if err != nil {
		return nil, err
	}
	return &amqpChannelWrapper{ch: ch}, nil
}

func (c *amqpConnectionWrapper) Close() error { return c.conn.Close() }

var dialAMQP = defaultDialAMQP

func (prober) Name() string { return "amqp" }
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
func (prober) Match(candidate core.SecurityCandidate) bool { return candidate.Service == "amqp" }

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
			result.FailureReason = classifyAMQPFailure(err)
			return result
		}
		result.Stage = core.StageAttempted

		conn, err := dialAMQP(ctx, candidate, cred, opts)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyAMQPFailure(err)
			if isTerminalContextError(err) {
				return result
			}
			continue
		}

		ch, err := conn.Channel()
		if err != nil {
			_ = conn.Close()
			result.Error = err.Error()
			result.FailureReason = classifyAMQPFailure(err)
			if isTerminalContextError(err) {
				return result
			}
			continue
		}
		_ = ch.Close()
		_ = conn.Close()

		result.Success = true
		result.Stage = core.StageConfirmed
		result.Username = cred.Username
		result.Password = cred.Password
		result.Evidence = "AMQP authentication succeeded"
		result.Error = ""
		result.FailureReason = ""
		return result
	}

	return result
}

func buildAMQPURL(candidate core.SecurityCandidate, cred core.Credential) string {
	scheme := "amqp"
	if candidate.Port == 5671 {
		scheme = "amqps"
	}
	return (&url.URL{
		Scheme: scheme,
		User:   url.UserPassword(cred.Username, cred.Password),
		Host:   net.JoinHostPort(candidate.ResolvedIP, fmt.Sprintf("%d", candidate.Port)),
		Path:   "/",
	}).String()
}

func defaultDialAMQP(ctx context.Context, candidate core.SecurityCandidate, cred core.Credential, opts core.CredentialProbeOptions) (amqpConnection, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	config := amqp091.Config{
		SASL: []amqp091.Authentication{
			&amqp091.PlainAuth{Username: cred.Username, Password: cred.Password},
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: func(network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	conn, err := amqp091.DialConfig(buildAMQPURL(candidate, cred), config)
	if err != nil {
		return nil, err
	}
	return &amqpConnectionWrapper{conn: conn}, nil
}

func classifyAMQPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "access_refused"),
		strings.Contains(text, "login was refused"),
		strings.Contains(text, "authentication"),
		strings.Contains(text, "sasl"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "tls"):
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

func isTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
```

Update `pkg/secprobe/default_registry.go`:

```go
	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
```

and register it:

```go
	r.registerCoreProber(amqpprobe.New())
```

- [ ] **Step 4: Run the AMQP tests and registry lookup tests**

Run:

```bash
go test ./internal/secprobe/amqp ./pkg/secprobe -run 'TestAMQPProber|TestBuildAMQPURL|TestRegisterDefaultProbersRegistersBuiltinLookupTargets|TestBuildCandidatesIncludesDefaultRegisteredCatalogProtocols|TestDefaultRegistryContainsBuiltinCredentialContract' -v
```

Expected: PASS, and the default registry resolves `amqp` credential probing.

- [ ] **Step 5: Commit the AMQP protocol batch**

```bash
git add go.mod go.sum internal/secprobe/amqp/prober.go internal/secprobe/amqp/prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go pkg/secprobe/candidates_test.go
git commit -m "feat(secprobe): 接入 amqp 凭证探测与默认注册" \
  -m "新增 amqp credential prober，并接入第二阶段第一批默认 registry。" \
  -m "实现建立在真实 AMQP 认证连接与可用 channel 确认之上，不因协议头握手或 capability 返回误报 credential-valid。" \
  -m "同步补充依赖、候选过滤与默认注册断言测试，为 batch-a 收尾回归建立完整接线面。"
```

---

### Task 4: Sync README and Run the Batch-A Regression Slice

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the batch-A regression slice before the README change**

Run:

```bash
go test ./app ./pkg/secprobe ./internal/secprobe/smtp ./internal/secprobe/amqp -v
```

Expected: PASS after Tasks 1-3 are complete.

- [ ] **Step 2: Update README to advertise the new batch-A built-ins**

Update `README.md`:

```md
- `-protocols`: 限定协议，逗号分隔，例如 `ssh,redis,mssql,rdp,vnc,smb,smtp,amqp`
```

and update the built-in credential list:

```md
- 当前内置 `credential` 协议列表：`ftp, ssh, telnet, smtp, mysql, postgresql, redis, mssql, amqp, rdp, vnc, smb`
```

- [ ] **Step 3: Re-run the batch-A regression slice after the README change**

Run:

```bash
go test ./app ./pkg/secprobe ./internal/secprobe/smtp ./internal/secprobe/amqp -v
```

Expected: PASS, and no documentation-induced code changes are required.

- [ ] **Step 4: Commit the batch-A documentation sync**

```bash
git add README.md
git commit -m "docs(secprobe): 更新第二阶段第一批协议说明" \
  -m "同步 README 中 secprobe 的协议示例和内置 credential 协议列表，纳入 smtp 与 amqp 两个 batch-a 协议。" \
  -m "保持文档与默认 registry、catalog、字典接线后的真实行为一致，避免后续第二阶段联调时出现说明漂移。" \
  -m "在文档提交前后各执行一次 batch-a 回归切片，确认 README 同步不会引入额外行为变更。"
```
