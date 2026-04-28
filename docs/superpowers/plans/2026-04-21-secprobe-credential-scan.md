# Secprobe Credential Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a new `pkg/secprobe` capability that performs credential-based protocol probing for `ssh`, `ftp`, `mysql`, `postgresql`, `redis`, and `telnet`, expose it through a new `gomap weak` command, and allow `gomap port --weak` to append security findings without changing existing `assetprobe` result models.

**Architecture:** Keep `pkg/assetprobe` focused on discovery and add a separate `pkg/secprobe` package for protocol security checks. `cmd/main.go` remains the CLI entrypoint, but `weak` orchestration and `port --weak` serialization are routed through small helper functions so the existing command code stays readable. Each protocol implementation lives behind a simple registry so new unsupported protocols can be added later without changing the dispatch path.

**Tech Stack:** Go standard library, existing embedded assets pattern in `app/assets.go`, protocol clients (`golang.org/x/crypto/ssh`, `github.com/jlaffaye/ftp`, `github.com/go-sql-driver/mysql`, `github.com/lib/pq`, `github.com/redis/go-redis/v9` or raw Redis TCP), and `testcontainers-go` for protocol integration tests.

---

## File Structure

**Create**

- `app/secprobe-ftp.txt`
- `app/secprobe-mysql.txt`
- `app/secprobe-postgresql.txt`
- `app/secprobe-redis.txt`
- `app/secprobe-ssh.txt`
- `app/secprobe-telnet.txt`
- `pkg/secprobe/types.go`
- `pkg/secprobe/json.go`
- `pkg/secprobe/assets.go`
- `pkg/secprobe/registry.go`
- `pkg/secprobe/candidates.go`
- `pkg/secprobe/run.go`
- `pkg/secprobe/assets_test.go`
- `pkg/secprobe/candidates_test.go`
- `pkg/secprobe/run_test.go`
- `internal/secprobe/ftp/prober.go`
- `internal/secprobe/mysql/prober.go`
- `internal/secprobe/postgresql/prober.go`
- `internal/secprobe/redis/prober.go`
- `internal/secprobe/ssh/prober.go`
- `internal/secprobe/telnet/prober.go`
- `internal/secprobe/testutil/testcontainers.go`
- `internal/secprobe/ftp/prober_test.go`
- `internal/secprobe/mysql/prober_test.go`
- `internal/secprobe/postgresql/prober_test.go`
- `internal/secprobe/redis/prober_test.go`
- `internal/secprobe/ssh/prober_test.go`
- `internal/secprobe/telnet/prober_test.go`

**Modify**

- `app/assets.go`
- `cmd/main.go`
- `pkg/assetprobe/json.go`
- `README.md`
- `examples/library/main.go`
- `go.mod`
- `go.sum`

**Why**

- `pkg/secprobe/*.go` holds public API, orchestration, JSON helpers, and candidate-building logic.
- `internal/secprobe/<protocol>/prober.go` keeps each protocol isolated and small.
- `internal/secprobe/testutil/testcontainers.go` centralizes container bootstrapping so individual protocol tests do not duplicate setup code.
- `app/assets.go` remains the single embedded-assets entrypoint, following the repository’s existing pattern.
- `cmd/main.go` stays the CLI boundary, but only grows orchestration helpers rather than protocol logic.

### Task 1: Scaffold Embedded Assets And Public Secprobe Types

**Files:**
- Create: `app/secprobe-ftp.txt`
- Create: `app/secprobe-mysql.txt`
- Create: `app/secprobe-postgresql.txt`
- Create: `app/secprobe-redis.txt`
- Create: `app/secprobe-ssh.txt`
- Create: `app/secprobe-telnet.txt`
- Create: `pkg/secprobe/types.go`
- Create: `pkg/secprobe/json.go`
- Create: `pkg/secprobe/assets.go`
- Create: `pkg/secprobe/assets_test.go`
- Modify: `app/assets.go`
- Test: `pkg/secprobe/assets_test.go`

- [ ] **Step 1: Write the failing asset and JSON tests**

```go
package secprobe

import "testing"

func TestBuiltinCredentialsLoadByProtocol(t *testing.T) {
	tests := []string{"ssh", "ftp", "mysql", "postgresql", "redis", "telnet"}
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

func TestSecurityResultToJSON(t *testing.T) {
	res := SecurityResult{
		Target:      "example.com",
		ResolvedIP:  "127.0.0.1",
		Port:        22,
		Service:     "ssh",
		FindingType: FindingTypeCredentialValid,
		Success:     true,
		Username:    "root",
		Password:    "root",
		Evidence:    "SSH authentication succeeded",
	}
	data, err := res.ToJSON(true)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if len(data) == 0 || data[0] != '{' {
		t.Fatalf("expected json object, got %q", string(data))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe -run 'TestBuiltinCredentialsLoadByProtocol|TestSecurityResultToJSON' -v`

Expected: FAIL with `stat .../pkg/secprobe: no such file or directory`

- [ ] **Step 3: Add the embedded dictionaries**

```text
# app/secprobe-ssh.txt
root : root
root : 123456
admin : admin
test : test
```

```text
# app/secprobe-ftp.txt
ftp : ftp
ftp : 123456
admin : admin
anonymous : anonymous
```

```text
# app/secprobe-mysql.txt
root : root
root : 123456
mysql : mysql
admin : admin
```

```text
# app/secprobe-postgresql.txt
postgres : postgres
postgres : 123456
admin : admin
test : test
```

```text
# app/secprobe-redis.txt
default : 123456
default : redis
redis : redis
redis : {{key}}
```

```text
# app/secprobe-telnet.txt
admin : admin
root : root
root : 123456
user : user
```

- [ ] **Step 4: Extend the embedded assets entrypoint**

```go
// app/assets.go
package appassets

import (
	"embed"
	"fmt"
)

//go:embed gomap-service-probes gomap-services dict-simple.txt dict-normal.txt dict-diff.txt secprobe-ftp.txt secprobe-mysql.txt secprobe-postgresql.txt secprobe-redis.txt secprobe-ssh.txt secprobe-telnet.txt
var files embed.FS

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "ftp":
		return files.ReadFile("secprobe-ftp.txt")
	case "mysql":
		return files.ReadFile("secprobe-mysql.txt")
	case "postgresql":
		return files.ReadFile("secprobe-postgresql.txt")
	case "redis":
		return files.ReadFile("secprobe-redis.txt")
	case "ssh":
		return files.ReadFile("secprobe-ssh.txt")
	case "telnet":
		return files.ReadFile("secprobe-telnet.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", protocol)
	}
}
```

- [ ] **Step 5: Add the minimal public secprobe types and JSON helpers**

```go
// pkg/secprobe/types.go
package secprobe

import "time"

const FindingTypeCredentialValid = "credential-valid"

type SecurityCandidate struct {
	Target     string
	ResolvedIP string
	Port       int
	Service    string
	Version    string
	Banner     string
}

type Credential struct {
	Username string
	Password string
}

type CredentialProbeOptions struct {
	Protocols     []string
	Concurrency   int
	Timeout       time.Duration
	StopOnSuccess bool
	DictDir       string
	Credentials   []Credential
}

type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Error       string
}

type SecurityMeta struct {
	Candidates int
	Attempted  int
	Succeeded  int
	Failed     int
	Skipped    int
}

type RunResult struct {
	Meta    SecurityMeta
	Results []SecurityResult
}
```

```go
// pkg/secprobe/json.go
package secprobe

import "encoding/json"

func marshalJSON(v any, pretty bool) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

func (r *SecurityResult) ToJSON(pretty bool) ([]byte, error) { return marshalJSON(r, pretty) }
func (r *RunResult) ToJSON(pretty bool) ([]byte, error)      { return marshalJSON(r, pretty) }
```

```go
// pkg/secprobe/assets.go
package secprobe

import (
	"strings"

	appassets "github.com/yrighc/gomap/app"
)

func BuiltinCredentials(protocol string) ([]Credential, error) {
	data, err := appassets.SecprobeDict(strings.ToLower(strings.TrimSpace(protocol)))
	if err != nil {
		return nil, err
	}
	return parseCredentialLines(string(data))
}
```

- [ ] **Step 6: Add minimal line parsing implementation**

```go
func parseCredentialLines(raw string) ([]Credential, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]Credential, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, Credential{
			Username: strings.TrimSpace(parts[0]),
			Password: strings.TrimSpace(parts[1]),
		})
	}
	return out, nil
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./pkg/secprobe -run 'TestBuiltinCredentialsLoadByProtocol|TestSecurityResultToJSON' -v`

Expected:

```text
=== RUN   TestBuiltinCredentialsLoadByProtocol
--- PASS: TestBuiltinCredentialsLoadByProtocol
=== RUN   TestSecurityResultToJSON
--- PASS: TestSecurityResultToJSON
PASS
```

- [ ] **Step 8: Commit**

```bash
git add app/assets.go app/secprobe-*.txt pkg/secprobe/types.go pkg/secprobe/json.go pkg/secprobe/assets.go pkg/secprobe/assets_test.go
git commit -m "feat(secprobe): add core types and embedded dictionaries"
```

### Task 2: Build Candidate Filtering, Service Normalization, And Registry Plumbing

**Files:**
- Create: `pkg/secprobe/candidates.go`
- Create: `pkg/secprobe/registry.go`
- Create: `pkg/secprobe/candidates_test.go`
- Create: `pkg/secprobe/run_test.go`
- Modify: `pkg/secprobe/assets.go`
- Test: `pkg/secprobe/candidates_test.go`
- Test: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing candidate and registry tests**

```go
package secprobe

import (
	"testing"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

func TestBuildCandidatesFiltersSupportedOpenPorts(t *testing.T) {
	res := &assetprobe.ScanResult{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Ports: []assetprobe.PortResult{
			{Port: 22, Open: true, Service: "ssh?"},
			{Port: 80, Open: true, Service: "http"},
			{Port: 6379, Open: true, Service: "redis/ssl"},
		},
	}
	candidates := BuildCandidates(res, CredentialProbeOptions{})
	if len(candidates) != 2 {
		t.Fatalf("expected 2 secprobe candidates, got %d", len(candidates))
	}
	if candidates[0].Service != "ssh" || candidates[1].Service != "redis" {
		t.Fatalf("unexpected services: %#v", candidates)
	}
}

func TestNormalizeServiceNameUsesKnownPortFallback(t *testing.T) {
	got := NormalizeServiceName("", 5432)
	if got != "postgresql" {
		t.Fatalf("expected postgresql, got %q", got)
	}
}

func TestRegisterAndLookupProber(t *testing.T) {
	r := NewRegistry()
	r.Register(stubProber{name: "ssh"})
	if _, ok := r.Lookup(SecurityCandidate{Service: "ssh", Port: 22}); !ok {
		t.Fatal("expected ssh prober")
	}
}

type stubProber struct{ name string }

func (s stubProber) Name() string { return s.name }
func (s stubProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.name
}
func (s stubProber) Probe(_ context.Context, _ SecurityCandidate, _ CredentialProbeOptions, _ []Credential) SecurityResult {
	return SecurityResult{Service: s.name}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe -run 'TestBuildCandidatesFiltersSupportedOpenPorts|TestNormalizeServiceNameUsesKnownPortFallback|TestRegisterAndLookupProber' -v`

Expected: FAIL with `undefined: BuildCandidates`, `undefined: NormalizeServiceName`, and `undefined: NewRegistry`

- [ ] **Step 3: Add service normalization and candidate builders**

```go
// pkg/secprobe/candidates.go
package secprobe

import (
	"sort"
	"strings"

	"github.com/yrighc/gomap/pkg/assetprobe"
)

var supportedByPort = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	3306: "mysql",
	5432: "postgresql",
	6379: "redis",
}

func NormalizeServiceName(service string, port int) string {
	service = strings.ToLower(strings.TrimSpace(service))
	service = strings.TrimSuffix(service, "?")
	service = strings.TrimSuffix(service, "/ssl")
	switch service {
	case "ftp", "ssh", "mysql", "postgresql", "redis", "telnet":
		return service
	case "":
		return supportedByPort[port]
	default:
		if v, ok := supportedByPort[port]; ok && strings.Contains(service, v) {
			return v
		}
		return supportedByPort[port]
	}
}

func BuildCandidates(res *assetprobe.ScanResult, opts CredentialProbeOptions) []SecurityCandidate {
	if res == nil {
		return nil
	}
	allowed := make(map[string]struct{}, len(opts.Protocols))
	for _, protocol := range opts.Protocols {
		p := NormalizeServiceName(protocol, 0)
		if p != "" {
			allowed[p] = struct{}{}
		}
	}

	out := make([]SecurityCandidate, 0, len(res.Ports))
	for _, p := range res.Ports {
		if !p.Open {
			continue
		}
		service := NormalizeServiceName(p.Service, p.Port)
		if service == "" {
			continue
		}
		if len(allowed) > 0 {
			if _, ok := allowed[service]; !ok {
				continue
			}
		}
		out = append(out, SecurityCandidate{
			Target:     res.Target,
			ResolvedIP: res.ResolvedIP,
			Port:       p.Port,
			Service:    service,
			Version:    p.Version,
			Banner:     p.Banner,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Target == out[j].Target {
			return out[i].Port < out[j].Port
		}
		return out[i].Target < out[j].Target
	})
	return out
}
```

- [ ] **Step 4: Add the registry and the smallest runnable `Run` skeleton**

```go
// pkg/secprobe/registry.go
package secprobe

import "context"

type Prober interface {
	Name() string
	Match(candidate SecurityCandidate) bool
	Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}

type Registry struct {
	probers []Prober
}

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) Register(prober Prober) {
	r.probers = append(r.probers, prober)
}

func (r *Registry) Lookup(candidate SecurityCandidate) (Prober, bool) {
	for _, prober := range r.probers {
		if prober.Match(candidate) {
			return prober, true
		}
	}
	return nil, false
}
```

```go
// pkg/secprobe/run_test.go
package secprobe

import (
	"context"
	"testing"
)

func TestRunSkipsUnsupportedCandidates(t *testing.T) {
	r := NewRegistry()
	result := RunWithRegistry(context.Background(), r, []SecurityCandidate{{Service: "http", Port: 80}}, CredentialProbeOptions{})
	if result.Meta.Candidates != 1 {
		t.Fatalf("expected one candidate, got %+v", result.Meta)
	}
	if result.Meta.Skipped != 1 {
		t.Fatalf("expected one skipped candidate, got %+v", result.Meta)
	}
}
```

```go
// pkg/secprobe/run.go
package secprobe

import "context"

func RunWithRegistry(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	result := RunResult{}
	result.Meta.Candidates = len(candidates)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		prober, ok := registry.Lookup(candidate)
		if !ok {
			result.Meta.Skipped++
			result.Results = append(result.Results, SecurityResult{
				Target:      candidate.Target,
				ResolvedIP:  candidate.ResolvedIP,
				Port:        candidate.Port,
				Service:     candidate.Service,
				FindingType: FindingTypeCredentialValid,
				Error:       "unsupported protocol",
			})
			continue
		}
		creds, err := CredentialsFor(candidate.Service, opts)
		if err != nil {
			result.Meta.Failed++
			result.Results = append(result.Results, SecurityResult{
				Target:      candidate.Target,
				ResolvedIP:  candidate.ResolvedIP,
				Port:        candidate.Port,
				Service:     candidate.Service,
				FindingType: FindingTypeCredentialValid,
				Error:       err.Error(),
			})
			continue
		}
		result.Meta.Attempted++
		item := prober.Probe(ctx, candidate, opts, creds)
		if item.Success {
			result.Meta.Succeeded++
		} else {
			result.Meta.Failed++
		}
		result.Results = append(result.Results, item)
	}
	return result
}
```

- [ ] **Step 5: Add credential resolution with simple precedence**

```go
func CredentialsFor(protocol string, opts CredentialProbeOptions) ([]Credential, error) {
	if len(opts.Credentials) > 0 {
		return dedupeCredentials(opts.Credentials), nil
	}
	return BuiltinCredentials(protocol)
}

func dedupeCredentials(in []Credential) []Credential {
	seen := map[string]struct{}{}
	out := make([]Credential, 0, len(in))
	for _, cred := range in {
		key := cred.Username + "\x00" + cred.Password
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cred)
	}
	return out
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./pkg/secprobe -run 'TestBuildCandidatesFiltersSupportedOpenPorts|TestNormalizeServiceNameUsesKnownPortFallback|TestRegisterAndLookupProber|TestRunSkipsUnsupportedCandidates' -v`

Expected:

```text
=== RUN   TestBuildCandidatesFiltersSupportedOpenPorts
--- PASS: TestBuildCandidatesFiltersSupportedOpenPorts
=== RUN   TestNormalizeServiceNameUsesKnownPortFallback
--- PASS: TestNormalizeServiceNameUsesKnownPortFallback
=== RUN   TestRegisterAndLookupProber
--- PASS: TestRegisterAndLookupProber
=== RUN   TestRunSkipsUnsupportedCandidates
--- PASS: TestRunSkipsUnsupportedCandidates
PASS
```

- [ ] **Step 7: Commit**

```bash
git add pkg/secprobe/candidates.go pkg/secprobe/registry.go pkg/secprobe/run.go pkg/secprobe/candidates_test.go pkg/secprobe/run_test.go
git commit -m "feat(secprobe): add candidate filtering and registry"
```

### Task 3: Add SSH, FTP, And Telnet Probers With Integration Tests

**Files:**
- Create: `internal/secprobe/ssh/prober.go`
- Create: `internal/secprobe/ftp/prober.go`
- Create: `internal/secprobe/telnet/prober.go`
- Create: `internal/secprobe/testutil/testcontainers.go`
- Create: `internal/secprobe/ssh/prober_test.go`
- Create: `internal/secprobe/ftp/prober_test.go`
- Create: `internal/secprobe/telnet/prober_test.go`
- Modify: `pkg/secprobe/run.go`
- Test: `internal/secprobe/ssh/prober_test.go`
- Test: `internal/secprobe/ftp/prober_test.go`
- Test: `internal/secprobe/telnet/prober_test.go`

- [ ] **Step 1: Write the failing SSH and FTP integration tests**

```go
package ssh_test

import (
	"context"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/ssh"
	"github.com/yrighc/gomap/internal/secprobe/testutil"
	"github.com/yrighc/gomap/pkg/secprobe"
)

func TestSSHProberFindsValidCredential(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "root",
		Password: "root",
		Services: []string{"ssh"},
	})
	prober := ssh.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("22/tcp"),
		Service:    "ssh",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "root", Password: "bad"},
		{Username: "root", Password: "root"},
	})
	if !result.Success {
		t.Fatalf("expected ssh success, got %+v", result)
	}
}
```

```go
package ftp_test

func TestFTPProberFindsValidCredential(t *testing.T) {
	container := testutil.StartLinuxServer(t, testutil.LinuxServerConfig{
		Username: "ftp",
		Password: "ftp",
		Services: []string{"ftp"},
	})
	prober := ftp.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.MappedPort("21/tcp"),
		Service:    "ftp",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "ftp", Password: "ftp"},
	})
	if !result.Success {
		t.Fatalf("expected ftp success, got %+v", result)
	}
}
```

- [ ] **Step 2: Add a telnet unit test that proves stop-on-success behavior**

```go
package telnet_test

func TestTelnetProberStopsAfterSuccess(t *testing.T) {
	server := testutil.StartFakeTelnet(t, "admin", "admin")
	prober := telnet.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     "127.0.0.1",
		ResolvedIP: "127.0.0.1",
		Port:       server.Port,
		Service:    "telnet",
	}, secprobe.CredentialProbeOptions{Timeout: 2 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "admin", Password: "wrong"},
		{Username: "admin", Password: "admin"},
	})
	if !result.Success {
		t.Fatalf("expected telnet success, got %+v", result)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/secprobe/ssh ./internal/secprobe/ftp ./internal/secprobe/telnet -v`

Expected: FAIL with missing packages and missing `testutil`

- [ ] **Step 4: Add the reusable test container helper**

```go
// internal/secprobe/testutil/testcontainers.go
package testutil

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type LinuxServerConfig struct {
	Username string
	Password string
	Services []string
}

type LinuxServer struct {
	Host string
	ports map[string]int
}

func (s LinuxServer) MappedPort(port string) int { return s.ports[port] }

func StartLinuxServer(t *testing.T, cfg LinuxServerConfig) LinuxServer {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "linuxserver/openssh-server:latest",
		ExposedPorts: []string{"22/tcp", "21/tcp"},
		Env: map[string]string{
			"USER_NAME": cfg.Username,
			"USER_PASSWORD": cfg.Password,
			"PASSWORD_ACCESS": "true",
		},
		WaitingFor: wait.ForListeningPort("22/tcp").WithStartupTimeout(60 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	ports := map[string]int{}
	for _, p := range []string{"22/tcp", "21/tcp"} {
		mapped, err := container.MappedPort(ctx, p)
		if err == nil {
			ports[p] = mapped.Int()
		}
	}
	return LinuxServer{Host: host, ports: ports}
}

type FakeTelnetServer struct{ Port int }

func StartFakeTelnet(t *testing.T, username, password string) FakeTelnetServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen telnet: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = fmt.Fprint(c, "login: ")
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				user := string(buf[:n-1])
				_, _ = fmt.Fprint(c, "Password: ")
				n, _ = c.Read(buf)
				pass := string(buf[:n-1])
				if user == username && pass == password {
					_, _ = fmt.Fprint(c, "\nWelcome\n")
					return
				}
				_, _ = fmt.Fprint(c, "\nLogin incorrect\n")
			}(conn)
		}
	}()
	return FakeTelnetServer{Port: ln.Addr().(*net.TCPAddr).Port}
}
```

- [ ] **Step 5: Implement the three protocol probers**

```go
// internal/secprobe/ssh/prober.go
package ssh

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "ssh" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "ssh" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	for _, cred := range creds {
		config := &ssh.ClientConfig{
			User:            cred.Username,
			Auth:            []ssh.AuthMethod{ssh.Password(cred.Password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         opts.Timeout,
		}
		addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			_ = client.Close()
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "SSH authentication succeeded"
			return result
		}
		result.Error = err.Error()
	}
	return result
}
```

```go
// internal/secprobe/ftp/prober.go
package ftp

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "ftp" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "ftp" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		conn, err := ftp.Dial(addr, ftp.DialWithTimeout(opts.Timeout))
		if err != nil {
			result.Error = err.Error()
			return result
		}
		err = conn.Login(cred.Username, cred.Password)
		_ = conn.Quit()
		if err == nil {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "FTP authentication succeeded"
			return result
		}
		result.Error = err.Error()
	}
	return result
}
```

```go
// internal/secprobe/telnet/prober.go
package telnet

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "telnet" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "telnet" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	for _, cred := range creds {
		addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
		conn, err := net.DialTimeout("tcp", addr, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = fmt.Fprintf(conn, "%s\n", cred.Username)
		_, _ = conn.Read(buf)
		_, _ = fmt.Fprintf(conn, "%s\n", cred.Password)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && strings.Contains(string(buf[:n]), "Welcome") {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "Telnet authentication succeeded"
			return result
		}
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "authentication failed"
		}
	}
	return result
}
```

- [ ] **Step 6: Register the probers in the default secprobe registry**

```go
// pkg/secprobe/run.go
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(ssh.New())
	r.Register(ftp.New())
	r.Register(telnet.New())
	return r
}
```

- [ ] **Step 7: Run protocol tests**

Run: `go test ./internal/secprobe/ssh ./internal/secprobe/ftp ./internal/secprobe/telnet -v`

Expected: PASS locally when Docker is available for SSH/FTP and the fake telnet server starts

- [ ] **Step 8: Commit**

```bash
git add internal/secprobe/ssh/prober.go internal/secprobe/ftp/prober.go internal/secprobe/telnet/prober.go internal/secprobe/testutil/testcontainers.go internal/secprobe/ssh/prober_test.go internal/secprobe/ftp/prober_test.go internal/secprobe/telnet/prober_test.go pkg/secprobe/run.go go.mod go.sum
git commit -m "feat(secprobe): add ssh ftp and telnet probers"
```

### Task 4: Add MySQL, PostgreSQL, And Redis Probers With Integration Tests

**Files:**
- Create: `internal/secprobe/mysql/prober.go`
- Create: `internal/secprobe/postgresql/prober.go`
- Create: `internal/secprobe/redis/prober.go`
- Create: `internal/secprobe/mysql/prober_test.go`
- Create: `internal/secprobe/postgresql/prober_test.go`
- Create: `internal/secprobe/redis/prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/run.go`
- Test: `internal/secprobe/mysql/prober_test.go`
- Test: `internal/secprobe/postgresql/prober_test.go`
- Test: `internal/secprobe/redis/prober_test.go`

- [ ] **Step 1: Write the failing database/redis tests**

```go
package mysql_test

func TestMySQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartMySQL(t, "root", "root")
	prober := mysql.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mysql",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "root", Password: "root"},
	})
	if !result.Success {
		t.Fatalf("expected mysql success, got %+v", result)
	}
}
```

```go
package postgresql_test

func TestPostgreSQLProberFindsValidCredential(t *testing.T) {
	container := testutil.StartPostgres(t, "postgres", "postgres")
	prober := postgresql.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "postgresql",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "postgres", Password: "postgres"},
	})
	if !result.Success {
		t.Fatalf("expected postgresql success, got %+v", result)
	}
}
```

```go
package redis_test

func TestRedisProberFindsValidCredential(t *testing.T) {
	container := testutil.StartRedis(t, "redis")
	prober := redis.New()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{Timeout: 5 * time.Second, StopOnSuccess: true}, []secprobe.Credential{
		{Username: "default", Password: "redis"},
	})
	if !result.Success {
		t.Fatalf("expected redis success, got %+v", result)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/secprobe/mysql ./internal/secprobe/postgresql ./internal/secprobe/redis -v`

Expected: FAIL because the probers and container helpers do not exist yet

- [ ] **Step 3: Extend test container helpers for MySQL, PostgreSQL, and Redis**

```go
type SimpleContainer struct {
	Host string
	Port int
}

func StartMySQL(t *testing.T, username, password string) SimpleContainer {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mysql:8.0",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": password,
		},
		WaitingFor: wait.ForLog("ready for connections").WithStartupTimeout(90 * time.Second),
	}
	return startSimpleContainer(t, ctx, req, "3306/tcp")
}

func StartPostgres(t *testing.T, username, password string) SimpleContainer {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     username,
			"POSTGRES_PASSWORD": password,
			"POSTGRES_DB":       "postgres",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(90 * time.Second),
	}
	return startSimpleContainer(t, ctx, req, "5432/tcp")
}

func StartRedis(t *testing.T, password string) SimpleContainer {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "redis:7",
		ExposedPorts: []string{"6379/tcp"},
		Cmd:          []string{"redis-server", "--requirepass", password},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
	}
	return startSimpleContainer(t, ctx, req, "6379/tcp")
}
```

- [ ] **Step 4: Implement the three probers**

```go
// internal/secprobe/mysql/prober.go
package mysql

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "mysql" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "mysql" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	for _, cred := range creds {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/mysql?timeout=%s", cred.Username, cred.Password, candidate.ResolvedIP, candidate.Port, opts.Timeout)
		db, err := sql.Open("mysql", dsn)
		if err == nil {
			err = db.PingContext(ctx)
			_ = db.Close()
		}
		if err == nil {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "MySQL authentication succeeded"
			return result
		}
		result.Error = err.Error()
	}
	return result
}
```

```go
// internal/secprobe/postgresql/prober.go
package postgresql

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "postgresql" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "postgresql" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	for _, cred := range creds {
		dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable", cred.Username, cred.Password, candidate.ResolvedIP, candidate.Port)
		db, err := sql.Open("postgres", dsn)
		if err == nil {
			err = db.PingContext(ctx)
			_ = db.Close()
		}
		if err == nil {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "PostgreSQL authentication succeeded"
			return result
		}
		result.Error = err.Error()
	}
	return result
}
```

```go
// internal/secprobe/redis/prober.go
package redis

func New() secprobe.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "redis" }
func (prober) Match(candidate secprobe.SecurityCandidate) bool { return candidate.Service == "redis" }

func (prober) Probe(ctx context.Context, candidate secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions, creds []secprobe.Credential) secprobe.SecurityResult {
	result := secprobe.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: secprobe.FindingTypeCredentialValid,
	}
	for _, cred := range creds {
		client := redis.NewClient(&redis.Options{
			Addr:     net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port)),
			Username: cred.Username,
			Password: cred.Password,
		})
		err := client.Ping(ctx).Err()
		_ = client.Close()
		if err == nil {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "Redis authentication succeeded"
			return result
		}
		result.Error = err.Error()
	}
	return result
}
```

- [ ] **Step 5: Register the probers**

```go
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(ssh.New())
	r.Register(ftp.New())
	r.Register(telnet.New())
	r.Register(mysql.New())
	r.Register(postgresql.New())
	r.Register(redis.New())
	return r
}
```

- [ ] **Step 6: Run the protocol tests**

Run: `go test ./internal/secprobe/mysql ./internal/secprobe/postgresql ./internal/secprobe/redis -v`

Expected: PASS locally when Docker is available

- [ ] **Step 7: Commit**

```bash
git add internal/secprobe/mysql/prober.go internal/secprobe/postgresql/prober.go internal/secprobe/redis/prober.go internal/secprobe/mysql/prober_test.go internal/secprobe/postgresql/prober_test.go internal/secprobe/redis/prober_test.go internal/secprobe/testutil/testcontainers.go pkg/secprobe/run.go go.mod go.sum
git commit -m "feat(secprobe): add mysql postgresql and redis probers"
```

### Task 5: Add Secprobe Runner, CLI Input Parsing, And `gomap weak`

**Files:**
- Create: `pkg/secprobe/run.go`
- Modify: `cmd/main.go`
- Modify: `pkg/secprobe/run_test.go`
- Test: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing run and CLI tests**

```go
package secprobe

import (
	"context"
	"testing"
	"time"
)

func TestRunUsesBuiltinCredentialsWhenOverridesMissing(t *testing.T) {
	registry := NewRegistry()
	registry.Register(stubSuccessProber{name: "ssh"})
	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       22,
		Service:    "ssh",
	}}, CredentialProbeOptions{Timeout: time.Second})
	if result.Meta.Attempted != 1 {
		t.Fatalf("expected attempted candidate, got %+v", result.Meta)
	}
}

type stubSuccessProber struct{ name string }

func (s stubSuccessProber) Name() string { return s.name }
func (s stubSuccessProber) Match(candidate SecurityCandidate) bool { return candidate.Service == s.name }
func (s stubSuccessProber) Probe(_ context.Context, candidate SecurityCandidate, _ CredentialProbeOptions, creds []Credential) SecurityResult {
	return SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: FindingTypeCredentialValid,
		Success:     len(creds) > 0,
		Username:    creds[0].Username,
		Password:    creds[0].Password,
	}
}
```

```go
// cmd/main.go test snippet to add near other tests or new cmd package tests
func TestCollectCredentialsParsesInlinePairs(t *testing.T) {
	got, err := collectCredentials("admin : admin,root : root", "")
	if err != nil {
		t.Fatalf("collect credentials: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/secprobe ./cmd -run 'TestRunUsesBuiltinCredentialsWhenOverridesMissing|TestCollectCredentialsParsesInlinePairs' -v`

Expected: FAIL with missing `collectCredentials` helper and incomplete run logic

- [ ] **Step 3: Complete the secprobe runner with worker-pool concurrency**

```go
// pkg/secprobe/run.go
package secprobe

import (
	"context"
	"sync"
	"time"
)

func applyDefaults(opts *CredentialProbeOptions) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if !opts.StopOnSuccess {
		opts.StopOnSuccess = true
	}
}

func Run(ctx context.Context, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	return RunWithRegistry(ctx, DefaultRegistry(), candidates, opts)
}

func RunWithRegistry(ctx context.Context, registry *Registry, candidates []SecurityCandidate, opts CredentialProbeOptions) RunResult {
	applyDefaults(&opts)
	result := RunResult{Meta: SecurityMeta{Candidates: len(candidates)}}
	if len(candidates) == 0 {
		return result
	}

	type indexed struct {
		index int
		item  SecurityCandidate
	}
	jobs := make(chan indexed, len(candidates))
	out := make([]SecurityResult, len(candidates))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				prober, ok := registry.Lookup(job.item)
				if !ok {
					mu.Lock()
					result.Meta.Skipped++
					out[job.index] = SecurityResult{
						Target:      job.item.Target,
						ResolvedIP:  job.item.ResolvedIP,
						Port:        job.item.Port,
						Service:     job.item.Service,
						FindingType: FindingTypeCredentialValid,
						Error:       "unsupported protocol",
					}
					mu.Unlock()
					continue
				}
				creds, err := CredentialsFor(job.item.Service, opts)
				if err != nil {
					mu.Lock()
					result.Meta.Failed++
					out[job.index] = SecurityResult{
						Target:      job.item.Target,
						ResolvedIP:  job.item.ResolvedIP,
						Port:        job.item.Port,
						Service:     job.item.Service,
						FindingType: FindingTypeCredentialValid,
						Error:       err.Error(),
					}
					mu.Unlock()
					continue
				}
				item := prober.Probe(ctx, job.item, opts, creds)
				mu.Lock()
				result.Meta.Attempted++
				if item.Success {
					result.Meta.Succeeded++
				} else {
					result.Meta.Failed++
				}
				out[job.index] = item
				mu.Unlock()
			}
		}()
	}

	for i, candidate := range candidates {
		jobs <- indexed{index: i, item: candidate}
	}
	close(jobs)
	wg.Wait()
	result.Results = out
	return result
}
```

- [ ] **Step 4: Add CLI parsers and `runWeak`**

```go
// cmd/main.go
import "github.com/yrighc/gomap/pkg/secprobe"

func runWeak(args []string) {
	fs := flag.NewFlagSet("weak", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	target := fs.String("target", "", "[必选，和 -ips 二选一] 扫描目标 IP 或域名")
	ips := fs.String("ips", "", "[必选，和 -target 二选一] 多个目标用逗号分隔")
	ports := fs.String("ports", "21,22,23,3306,5432,6379", "[可选] 端口表达式")
	protocols := fs.String("protocols", "", "[可选] 仅探测指定协议，逗号分隔")
	timeout := fs.Int("timeout", 3, "[可选] secprobe 超时秒数")
	weakConcurrency := fs.Int("weak-concurrency", 10, "[可选] secprobe 并发数")
	dictDir := fs.String("dict-dir", "", "[可选] 自定义协议字典目录")
	inlineCreds := fs.String("up", "", "[可选] 内联凭证，格式 'admin : admin,root : root'")
	credFile := fs.String("upf", "", "[可选] 凭证文件，一行一个 'admin : admin'")
	stopOnSuccess := fs.Bool("stop-on-success", true, "[可选] 单目标命中后停止继续尝试")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	targets := collectTargets(*target, *ips)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "target 不能为空，例如: gomap weak -target example.com")
		os.Exit(1)
	}
	creds, err := collectCredentials(*inlineCreds, *credFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	scanner, err := assetprobe.NewScanner(assetprobe.Options{Timeout: time.Duration(*timeout) * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	batchRes, err := scanner.ScanTargets(context.Background(), targets, assetprobe.ScanCommonOptions{
		PortSpec: *ports,
		Protocol: assetprobe.ProtocolTCP,
		Timeout:  time.Duration(*timeout) * time.Second,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
	}

	candidates := make([]secprobe.SecurityCandidate, 0)
	for _, item := range batchRes.Results {
		if item.Result != nil {
			candidates = append(candidates, secprobe.BuildCandidates(item.Result, secprobe.CredentialProbeOptions{
				Protocols:   splitComma(*protocols),
				Credentials: creds,
			})...)
		}
	}

	result := secprobe.Run(context.Background(), candidates, secprobe.CredentialProbeOptions{
		Protocols:     splitComma(*protocols),
		Concurrency:   *weakConcurrency,
		Timeout:       time.Duration(*timeout) * time.Second,
		StopOnSuccess: *stopOnSuccess,
		DictDir:       *dictDir,
		Credentials:   creds,
	})
	output, _ := result.ToJSON(true)
	fmt.Println(string(output))
}
```

```go
func collectCredentials(inline, file string) ([]secprobe.Credential, error) {
	var lines []string
	if strings.TrimSpace(inline) != "" {
		lines = append(lines, splitComma(inline)...)
	}
	if strings.TrimSpace(file) != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		lines = append(lines, strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")...)
	}
	out := make([]secprobe.Credential, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), " : ", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, secprobe.Credential{Username: strings.TrimSpace(parts[0]), Password: strings.TrimSpace(parts[1])})
	}
	return out, nil
}

func splitComma(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
```

- [ ] **Step 5: Wire the new command into the CLI root**

```go
switch os.Args[1] {
case "port":
	runPort(os.Args[2:])
case "web":
	runWeb(os.Args[2:])
case "dir":
	runDir(os.Args[2:])
case "weak":
	runWeak(os.Args[2:])
case "help", "-h", "--help":
	printRootUsage()
}
```

And update root usage:

```go
fmt.Println("  weak   协议账号口令探测")
fmt.Println("  gomap weak -target example.com -ports 21,22,3306,5432,6379")
```

- [ ] **Step 6: Run the unit tests**

Run: `go test ./pkg/secprobe ./cmd -run 'TestRunUsesBuiltinCredentialsWhenOverridesMissing|TestCollectCredentialsParsesInlinePairs' -v`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/secprobe/run.go pkg/secprobe/run_test.go cmd/main.go
git commit -m "feat(cli): add weak command"
```

### Task 6: Add `port --weak` Envelope Output And End-To-End Tests

**Files:**
- Modify: `cmd/main.go`
- Modify: `pkg/assetprobe/json.go`
- Modify: `README.md`
- Modify: `examples/library/main.go`
- Test: `cmd/main.go` test file or a new `cmd/main_test.go`

- [ ] **Step 1: Write the failing serialization test**

```go
func TestPortWithWeakWrapsAssetAndSecurityResults(t *testing.T) {
	payload := portWithWeakOutput{
		Asset: &assetprobe.ScanResult{Target: "demo"},
		Security: &secprobe.RunResult{
			Meta: secprobe.SecurityMeta{Candidates: 1, Attempted: 1, Succeeded: 1},
			Results: []secprobe.SecurityResult{{
				Target:      "demo",
				Service:     "ssh",
				FindingType: secprobe.FindingTypeCredentialValid,
				Success:     true,
				Username:    "root",
				Password:    "root",
			}},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !bytes.Contains(data, []byte(`"asset"`)) || !bytes.Contains(data, []byte(`"security"`)) {
		t.Fatalf("unexpected payload: %s", string(data))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd -run TestPortWithWeakWrapsAssetAndSecurityResults -v`

Expected: FAIL with `undefined: portWithWeakOutput`

- [ ] **Step 3: Add the output envelope and `-weak` flags**

```go
type portWithWeakOutput struct {
	Asset    *assetprobe.ScanResult `json:"asset"`
	Security *secprobe.RunResult    `json:"security"`
}
```

Add flags in `runPort`:

```go
	enableWeak := fs.Bool("weak", false, "[可选] 在端口扫描后执行账号口令探测")
	weakProtocols := fs.String("weak-protocols", "", "[可选] 限定 weak 探测协议，逗号分隔")
	weakConcurrency := fs.Int("weak-concurrency", 10, "[可选] weak 探测并发数")
	weakStopOnSuccess := fs.Bool("weak-stop-on-success", true, "[可选] weak 命中后停止继续尝试")
	weakDictDir := fs.String("weak-dict-dir", "", "[可选] 自定义 weak 字典目录")
```

Wrap the output:

```go
if *enableWeak {
	candidates := secprobe.BuildCandidates(res, secprobe.CredentialProbeOptions{
		Protocols: splitComma(*weakProtocols),
	})
	security := secprobe.Run(context.Background(), candidates, secprobe.CredentialProbeOptions{
		Protocols:     splitComma(*weakProtocols),
		Concurrency:   *weakConcurrency,
		Timeout:       time.Duration(*timeout) * time.Second,
		StopOnSuccess: *weakStopOnSuccess,
		DictDir:       *weakDictDir,
	})
	payload := portWithWeakOutput{Asset: res, Security: &security}
	output, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(output))
	continue
}
```

- [ ] **Step 4: Document the new CLI paths**

```md
## 弱口令探测（weak）

```bash
go run ./cmd weak -target example.com -ports 21,22,3306,5432,6379
```

## 端口扫描后附加弱口令探测

```bash
go run ./cmd port -target example.com -ports 21,22,3306,5432,6379 -weak
```
```

Update `examples/library/main.go` with a secprobe example:

```go
func runWeakExample(scanner *assetprobe.Scanner) error {
	result, err := scanner.Scan(context.Background(), assetprobe.ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: "21,22,3306,5432,6379",
		Protocol: assetprobe.ProtocolTCP,
	})
	if err != nil {
		return err
	}
	security := secprobe.Run(context.Background(), secprobe.BuildCandidates(result, secprobe.CredentialProbeOptions{}), secprobe.CredentialProbeOptions{})
	out, _ := security.ToJSON(true)
	fmt.Println(string(out))
	return nil
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./cmd -run TestPortWithWeakWrapsAssetAndSecurityResults -v`

Expected: PASS

Run: `go test ./...`

Expected: PASS, with integration tests passing when Docker is available

- [ ] **Step 6: Commit**

```bash
git add cmd/main.go README.md examples/library/main.go
git commit -m "feat(port): add optional weak scan output"
```

## Self-Review

### Spec coverage

- New `pkg/secprobe`: covered by Tasks 1, 2, 5.
- Six supported protocols: covered by Tasks 3 and 4.
- New `gomap weak`: covered by Task 5.
- `gomap port --weak`: covered by Task 6.
- No `assetprobe.PortResult` schema change: preserved by Tasks 5 and 6 because output uses a wrapper payload.
- Future unauthorized-access extension: supported by the shared `FindingType` model in Task 1 and registry layout in Task 2.

### Placeholder scan

- No `TODO`, `TBD`, or “similar to previous task” shortcuts remain.
- Every code step includes concrete code snippets.
- Every verification step includes a command and an expected result.

### Type consistency

- `SecurityCandidate`, `CredentialProbeOptions`, `SecurityResult`, and `RunResult` are introduced in Task 1 and reused consistently afterward.
- `NormalizeServiceName`, `BuildCandidates`, `Registry`, and `RunWithRegistry` are defined before later tasks reference them.
- `FindingTypeCredentialValid` is used consistently across public model, probers, and CLI envelope tasks.
