# secprobe Engine Phase 3 Atomic Credential Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the remaining built-in credential protocols from legacy looped `core.Prober` implementations to atomic `AuthenticateOnce` plugins, so the centralized engine owns credential iteration for every built-in credential protocol.

**Architecture:** Keep YAML metadata declarative and unchanged as the protocol fact source. Each protocol gains a thin atomic authenticator that performs exactly one authentication attempt, returns standardized `result.Attempt` fields, and leaves loop control, stop-on-success, and terminal error handling to `pkg/secprobe/engine`. Built-in registration moves protocol-by-protocol from `registerCoreProber(...)` to `RegisterAtomicCredential(...)`, while legacy public-prober compatibility remains temporarily available for non-migrated or externally registered probers.

**Tech Stack:** Go, `pkg/secprobe/engine`, `pkg/secprobe/result`, `pkg/secprobe/registry`, existing metadata/planner pipeline, protocol packages under `internal/secprobe/*`, and Go `testing`.

---

## Scope Decomposition

Protocols already on the atomic credential path:

- `ssh`
- `redis`

Built-in credential protocols still using legacy prober-owned loops and in scope for this phase:

- `ftp`
- `mssql`
- `mysql`
- `postgresql`
- `oracle`
- `smtp`
- `telnet`
- `rdp`
- `vnc`
- `smb`
- `snmp`
- `amqp`
- `mongodb`

This phase explicitly does **not**:

- introduce unauthorized templates
- remove the public-prober compatibility path
- remove `Registry.Register(...)`
- redesign metadata schema beyond what phase 2 already shipped
- change the public `Run`, `RunWithRegistry`, `BuildCandidates`, or result JSON surface

---

## File Map

### Registration and engine-path regression coverage

- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/engine/runner_test.go`

### SQL and simple TCP credential atomic plugins

- Create: `internal/secprobe/ftp/auth_once.go`
- Create: `internal/secprobe/mssql/auth_once.go`
- Create: `internal/secprobe/mysql/auth_once.go`
- Create: `internal/secprobe/postgresql/auth_once.go`
- Create: `internal/secprobe/smtp/auth_once.go`
- Create: `internal/secprobe/telnet/auth_once.go`
- Create: `internal/secprobe/amqp/auth_once.go`
- Modify: `internal/secprobe/ftp/prober_test.go`
- Modify: `internal/secprobe/mssql/prober_test.go`
- Modify: `internal/secprobe/mysql/prober_test.go`
- Modify: `internal/secprobe/postgresql/prober_test.go`
- Modify: `internal/secprobe/smtp/prober_test.go`
- Modify: `internal/secprobe/telnet/prober_test.go`
- Modify: `internal/secprobe/amqp/prober_test.go`

### Session-heavy and protocol-specialized credential atomic plugins

- Create: `internal/secprobe/oracle/auth_once.go`
- Create: `internal/secprobe/rdp/auth_once.go`
- Create: `internal/secprobe/vnc/auth_once.go`
- Create: `internal/secprobe/smb/auth_once.go`
- Create: `internal/secprobe/snmp/auth_once.go`
- Create: `internal/secprobe/mongodb/auth_once.go`
- Modify: `internal/secprobe/oracle/prober_test.go`
- Modify: `internal/secprobe/rdp/prober_test.go`
- Modify: `internal/secprobe/vnc/prober_test.go`
- Modify: `internal/secprobe/smb/prober_test.go`
- Modify: `internal/secprobe/snmp/prober_test.go`
- Modify: `internal/secprobe/mongodb/credential_prober_test.go`

### Documentation

- Modify: `README.md`

---

## Task 1: Lock the Phase-3 Atomic Coverage Contract Before Code Changes

**Files:**
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/engine/runner_test.go`

- [ ] **Step 1: Add failing default-registry assertions for the remaining built-in credential protocols**

Extend `pkg/secprobe/default_registry_test.go` with a focused test that encodes the new expectation:

```go
func TestDefaultRegistryRegistersAtomicCredentialPluginsForAllBuiltinCredentialProtocols(t *testing.T) {
	r := DefaultRegistry()

	tests := []SecurityCandidate{
		{Service: "ftp", Port: 21},
		{Service: "mssql", Port: 1433},
		{Service: "mysql", Port: 3306},
		{Service: "postgresql", Port: 5432},
		{Service: "smtp", Port: 25},
		{Service: "telnet", Port: 23},
		{Service: "amqp", Port: 5672},
		{Service: "oracle", Port: 1521},
		{Service: "rdp", Port: 3389},
		{Service: "vnc", Port: 5900},
		{Service: "smb", Port: 445},
		{Service: "snmp", Port: 161},
		{Service: "mongodb", Port: 27017},
	}

	for _, candidate := range tests {
		if _, ok := r.lookupAtomicCredential(candidate); !ok {
			t.Fatalf("expected atomic credential plugin for %+v", candidate)
		}
	}
}
```

- [ ] **Step 2: Add a run-path regression test proving built-in credential protocols stay on the engine path**

Extend `pkg/secprobe/run_test.go` with a spy-based regression:

```go
func TestRunWithRegistryUsesAtomicCredentialPathForBuiltinFTP(t *testing.T) {
	registry := NewRegistry()

	var calls int32
	registry.RegisterAtomicCredential("ftp", stubAtomicAuthenticator(func(context.Context, strategy.Target, strategy.Credential) registrybridge.Attempt {
		atomic.AddInt32(&calls, 1)
		return registrybridge.Attempt{Result: result.Attempt{
			Success:     true,
			Username:    "admin",
			Password:    "admin",
			FindingType: result.FindingTypeCredentialValid,
			Evidence:    "FTP authentication succeeded",
		}}
	}))

	out := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target: "demo", ResolvedIP: "127.0.0.1", Port: 21, Service: "ftp",
	}}, CredentialProbeOptions{
		Credentials:   []Credential{{Username: "admin", Password: "admin"}},
		StopOnSuccess: true,
	})

	if len(out.Results) != 1 || !out.Results[0].Success {
		t.Fatalf("expected atomic success, got %+v", out)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly one atomic attempt, got %d", calls)
	}
}
```

- [ ] **Step 3: Add a runner regression that the engine keeps terminal-error semantics consistent across all new atomic authenticators**

Extend `pkg/secprobe/engine/runner_test.go`:

```go
func TestRunnerStopsCredentialLoopOnCanceledAcrossAtomicPlugins(t *testing.T) {
	var attempts atomic.Int32
	auth := stubAuthenticator(func(context.Context, strategy.Target, strategy.Credential) atomregistry.Attempt {
		attempts.Add(1)
		return atomregistry.Attempt{Result: result.Attempt{
			Error:       "context canceled",
			ErrorCode:   result.ErrorCodeCanceled,
			FindingType: result.FindingTypeCredentialValid,
		}}
	})

	out := Run(context.Background(), strategy.Plan{
		Capabilities: []strategy.Capability{strategy.CapabilityCredential},
		Execution:    strategy.ExecutionPolicy{StopOnFirstSuccess: false},
	}, Input{
		Credentials: []strategy.Credential{
			{Username: "a", Password: "1"},
			{Username: "a", Password: "2"},
		},
		Authenticator: auth,
	})

	if out.Success {
		t.Fatalf("expected canceled failure, got %+v", out)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected terminal cancellation after one attempt, got %d", got)
	}
}
```

- [ ] **Step 4: Run the focused baseline tests to capture the missing-plugin failure**

Run:

```bash
go test ./pkg/secprobe ./pkg/secprobe/engine -run 'TestDefaultRegistryRegistersAtomicCredentialPluginsForAllBuiltinCredentialProtocols|TestRunWithRegistryUsesAtomicCredentialPathForBuiltinFTP|TestRunnerStopsCredentialLoopOnCanceledAcrossAtomicPlugins' -v
```

Expected: FAIL because most built-in credential protocols are not yet registered via `RegisterAtomicCredential(...)`.

- [ ] **Step 5: Commit the test-first baseline**

```bash
git add pkg/secprobe/default_registry_test.go pkg/secprobe/run_test.go pkg/secprobe/engine/runner_test.go
git commit -m "test(secprobe): 锁定 phase3 原子认证迁移基线"
```

---

## Task 2: Migrate the SQL and Simple TCP Credential Protocols

**Files:**
- Create: `internal/secprobe/ftp/auth_once.go`
- Create: `internal/secprobe/mssql/auth_once.go`
- Create: `internal/secprobe/mysql/auth_once.go`
- Create: `internal/secprobe/postgresql/auth_once.go`
- Create: `internal/secprobe/smtp/auth_once.go`
- Create: `internal/secprobe/telnet/auth_once.go`
- Create: `internal/secprobe/amqp/auth_once.go`
- Modify: `internal/secprobe/ftp/prober_test.go`
- Modify: `internal/secprobe/mssql/prober_test.go`
- Modify: `internal/secprobe/mysql/prober_test.go`
- Modify: `internal/secprobe/postgresql/prober_test.go`
- Modify: `internal/secprobe/smtp/prober_test.go`
- Modify: `internal/secprobe/telnet/prober_test.go`
- Modify: `internal/secprobe/amqp/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`

- [ ] **Step 1: Add failing atomic-unit tests for the first protocol batch**

For each protocol package, add a focused `AuthenticateOnce` test following the existing SSH/Redis style. Example for `internal/secprobe/ftp/prober_test.go`:

```go
func TestFTPAuthenticatorAuthenticateOnce(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username == "admin" && cred.Password == "admin" {
			return nil
		}
		return errors.New("530 Login incorrect")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 21, Protocol: "ftp",
	}, strategy.Credential{Username: "admin", Password: "admin"})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected finding type: %+v", out.Result)
	}
}
```

Use the same pattern for:

- `mssql`: map login rejection to `result.ErrorCodeAuthentication`
- `mysql`: map dial / timeout / auth failures to standardized codes
- `postgresql`: same standardized code contract
- `smtp`: successful `AUTH` confirmation yields `credential_valid`
- `telnet`: login prompt success yields `credential_valid`
- `amqp`: successful connection open yields `credential_valid`

- [ ] **Step 2: Implement the first batch of atomic authenticators**

Create the files with the same constructor shape and standardized return contract used by `ssh` and `redis`. Example skeleton for `internal/secprobe/mysql/auth_once.go`:

```go
package mysql

type Authenticator struct {
	ping func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(ping func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if ping == nil {
		ping = pingWithAuth
	}
	return Authenticator{ping: ping}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.ping(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyMySQLFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "MySQL authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}
```

Apply the same file-level pattern to the other protocols, keeping each implementation to:

- one `Authenticator` type
- one `NewAuthenticator(...)` constructor
- one `AuthenticateOnce(...)` method
- small private helpers for protocol-specific dial / login / classification

- [ ] **Step 3: Register the first batch in the default registry**

Update `pkg/secprobe/default_registry.go` by adding:

```go
r.RegisterAtomicCredential("ftp", ftpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mssql", mssqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mysql", mysqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("postgresql", postgresqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("smtp", smtpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("telnet", telnetprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("amqp", amqpprobe.NewAuthenticator(nil))
```

Keep the existing `registerCoreProber(...)` lines for this first migration commit so the public compatibility surface remains intact while the engine path switches to atomic-first resolution.

- [ ] **Step 4: Run the focused protocol and secprobe tests**

Run:

```bash
go test ./internal/secprobe/ftp ./internal/secprobe/mssql ./internal/secprobe/mysql ./internal/secprobe/postgresql ./internal/secprobe/smtp ./internal/secprobe/telnet ./internal/secprobe/amqp ./pkg/secprobe -v
```

Expected: PASS with the new `AuthenticateOnce` tests and the phase-3 registry baseline for these protocols green.

- [ ] **Step 5: Commit the first migration batch**

```bash
git add internal/secprobe/ftp/auth_once.go internal/secprobe/mssql/auth_once.go internal/secprobe/mysql/auth_once.go internal/secprobe/postgresql/auth_once.go internal/secprobe/smtp/auth_once.go internal/secprobe/telnet/auth_once.go internal/secprobe/amqp/auth_once.go internal/secprobe/ftp/prober_test.go internal/secprobe/mssql/prober_test.go internal/secprobe/mysql/prober_test.go internal/secprobe/postgresql/prober_test.go internal/secprobe/smtp/prober_test.go internal/secprobe/telnet/prober_test.go internal/secprobe/amqp/prober_test.go pkg/secprobe/default_registry.go
git commit -m "feat(secprobe): 完成 phase3 第一批原子认证迁移"
```

---

## Task 3: Migrate the Session-Heavy Credential Protocols

**Files:**
- Create: `internal/secprobe/oracle/auth_once.go`
- Create: `internal/secprobe/rdp/auth_once.go`
- Create: `internal/secprobe/vnc/auth_once.go`
- Create: `internal/secprobe/smb/auth_once.go`
- Modify: `internal/secprobe/oracle/prober_test.go`
- Modify: `internal/secprobe/rdp/prober_test.go`
- Modify: `internal/secprobe/vnc/prober_test.go`
- Modify: `internal/secprobe/smb/prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`

- [ ] **Step 1: Add failing atomic tests for the session-heavy batch**

Follow the same unit-test shape, but explicitly lock protocol-specific error-code mapping. Example for `internal/secprobe/smb/prober_test.go`:

```go
func TestSMBAuthenticatorMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("STATUS_LOGON_FAILURE")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 445, Protocol: "smb",
	}, strategy.Credential{Username: "guest", Password: "guest"})

	if out.Result.Success {
		t.Fatalf("expected auth failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication code, got %+v", out.Result)
	}
}
```

- [ ] **Step 2: Implement the Oracle, RDP, VNC, and SMB atomic authenticators**

For each new file, reuse the protocol package's existing dial/login logic but collapse it to one attempt. Example skeleton for `internal/secprobe/vnc/auth_once.go`:

```go
type Authenticator struct {
	login func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(login func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if login == nil {
		login = loginOnce
	}
	return Authenticator{login: login}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.login(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyVNCFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "VNC authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}
```

- [ ] **Step 3: Register the second batch in the default registry**

Update `pkg/secprobe/default_registry.go`:

```go
r.RegisterAtomicCredential("oracle", oracledbprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("rdp", rdpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("vnc", vncprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("smb", smbprobe.NewAuthenticator(nil))
```

- [ ] **Step 4: Run the focused session-heavy regression suite**

Run:

```bash
go test ./internal/secprobe/oracle ./internal/secprobe/rdp ./internal/secprobe/vnc ./internal/secprobe/smb ./pkg/secprobe -v
```

Expected: PASS with standardized result-code assertions and default-registry atomic coverage updated for this batch.

- [ ] **Step 5: Commit the second migration batch**

```bash
git add internal/secprobe/oracle/auth_once.go internal/secprobe/rdp/auth_once.go internal/secprobe/vnc/auth_once.go internal/secprobe/smb/auth_once.go internal/secprobe/oracle/prober_test.go internal/secprobe/rdp/prober_test.go internal/secprobe/vnc/prober_test.go internal/secprobe/smb/prober_test.go pkg/secprobe/default_registry.go
git commit -m "feat(secprobe): 完成 phase3 第二批原子认证迁移"
```

---

## Task 4: Migrate the Protocol-Specialized Credential Paths (`snmp`, `mongodb`)

**Files:**
- Create: `internal/secprobe/snmp/auth_once.go`
- Create: `internal/secprobe/mongodb/auth_once.go`
- Modify: `internal/secprobe/snmp/prober_test.go`
- Modify: `internal/secprobe/mongodb/credential_prober_test.go`
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Add failing tests that preserve the special semantics of `snmp` and `mongodb`**

Add assertions that explicitly pin the current behavior:

```go
func TestSNMPAuthenticatorTreatsTimeoutAsTerminal(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return context.DeadlineExceeded
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 161, Protocol: "snmp",
	}, strategy.Credential{Password: "public"})

	if out.Result.ErrorCode != result.ErrorCodeTimeout {
		t.Fatalf("expected timeout code, got %+v", out.Result)
	}
}
```

And for MongoDB:

```go
func TestMongoDBAuthenticatorReturnsEnumerableEvidenceOnSuccess(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host: "demo", IP: "127.0.0.1", Port: 27017, Protocol: "mongodb",
	}, strategy.Credential{Username: "root", Password: "root"})

	if !out.Result.Success || out.Result.Evidence == "" {
		t.Fatalf("expected success evidence, got %+v", out.Result)
	}
}
```

- [ ] **Step 2: Implement atomic authenticators for `snmp` and `mongodb`**

Create `internal/secprobe/snmp/auth_once.go` and `internal/secprobe/mongodb/auth_once.go` by extracting the single-attempt logic from the existing probers. The important contract is:

- `snmp` uses one community string per call
- `mongodb` confirms access with one `ListDatabaseNames` round-trip per call
- both return standardized `result.ErrorCode` values
- neither performs credential loops internally

Use the following constructor shape in both files:

```go
type Authenticator struct {
	check func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(check func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if check == nil {
		check = authenticateOnce
	}
	return Authenticator{check: check}
}
```

- [ ] **Step 3: Register the final credential batch and add a run-path regression for MongoDB**

Update `pkg/secprobe/default_registry.go`:

```go
r.RegisterAtomicCredential("snmp", snmpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mongodb", mongodbprobe.NewAuthenticator(nil))
```

Then add a focused `RunWithRegistry` regression showing that MongoDB now reaches success through the engine-owned credential loop instead of the legacy prober loop.

- [ ] **Step 4: Run the targeted special-protocol regression suite**

Run:

```bash
go test ./internal/secprobe/snmp ./internal/secprobe/mongodb ./pkg/secprobe -run 'TestSNMPAuthenticator|TestMongoDBAuthenticator|TestRunWithRegistry' -v
```

Expected: PASS with `snmp` and `mongodb` now covered by `lookupAtomicCredential(...)`.

- [ ] **Step 5: Commit the final credential migration batch**

```bash
git add internal/secprobe/snmp/auth_once.go internal/secprobe/mongodb/auth_once.go internal/secprobe/snmp/prober_test.go internal/secprobe/mongodb/credential_prober_test.go pkg/secprobe/default_registry.go pkg/secprobe/run_test.go
git commit -m "feat(secprobe): 完成 phase3 第三批原子认证迁移"
```

---

## Task 5: Shrink Built-in Dependence on Legacy Credential Probers and Document the New Boundary

**Files:**
- Modify: `pkg/secprobe/default_registry.go`
- Modify: `pkg/secprobe/default_registry_test.go`
- Modify: `README.md`

- [ ] **Step 1: Remove redundant built-in credential `registerCoreProber(...)` lines for migrated protocols**

After all built-in credential protocols have atomic implementations and passing tests, update `pkg/secprobe/default_registry.go` so the built-in credential set is registered atomic-first and no longer depends on legacy core probers for the credential path. Keep unauthorized legacy probers that are still needed for phase 4.

The resulting credential section should look like:

```go
r.RegisterAtomicCredential("ssh", sshprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("redis", redisprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("ftp", ftpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mssql", mssqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mysql", mysqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("postgresql", postgresqlprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("smtp", smtpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("telnet", telnetprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("amqp", amqpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("oracle", oracledbprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("rdp", rdpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("vnc", vncprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("smb", smbprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("snmp", snmpprobe.NewAuthenticator(nil))
r.RegisterAtomicCredential("mongodb", mongodbprobe.NewAuthenticator(nil))
```

- [ ] **Step 2: Tighten the registry contract tests**

Update `pkg/secprobe/default_registry_test.go` so the built-in credential protocols are asserted via `lookupAtomicCredential(...)` rather than inferred only through `Lookup(...)`.

- [ ] **Step 3: Document the phase-3 architecture boundary**

Add a short section to `README.md`:

```md
### secprobe engine phase 3

- All built-in credential protocols now execute through atomic `AuthenticateOnce` plugins
- Credential loops, stop-on-success, and terminal-error handling are centralized in `pkg/secprobe/engine`
- Legacy public-prober compatibility remains temporarily available for non-migrated unauthorized checks and external extensions
```

- [ ] **Step 4: Run the full secprobe regression suite**

Run:

```bash
go test ./pkg/secprobe ./internal/secprobe/... -v
```

Expected: PASS across registry, planner, engine, run, and all credential protocol packages.

- [ ] **Step 5: Commit the boundary cleanup**

```bash
git add pkg/secprobe/default_registry.go pkg/secprobe/default_registry_test.go README.md
git commit -m "refactor(secprobe): 收口内置协议的原子认证执行路径"
```

---

## Self-Review Checklist

### Spec coverage

- Built-in credential protocols no longer own credential loops internally.
- Engine remains the only place that decides stop-on-success and terminal loop termination.
- Atomic plugins return standardized `result.ErrorCode` and `result.FindingType`.
- Metadata remains declarative and does not absorb protocol execution logic.

### Placeholder scan

- Every task names the exact files to create or modify.
- Every code-writing task includes a concrete constructor and method shape.
- Every verification step has an exact `go test` command and an expected pass/fail outcome.

### Type consistency

- Atomic credential interface remains `AuthenticateOnce(ctx, target, cred)`.
- Standardized result types remain `result.Attempt`, `result.ErrorCode`, and `result.FindingTypeCredentialValid`.
- Public secprobe surfaces remain `Run`, `RunWithRegistry`, `DefaultRegistry`, and `CredentialProbeOptions`.

