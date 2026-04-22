# GoMap secprobe v1.2 Weak Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade `pkg/secprobe` from credential-only probing to a unified weak-auth layer that supports `credential` and `unauthorized` findings, first-class `redis` / `mongodb` unauth checks, and optional post-success enrichment.

**Architecture:** Keep `pkg/secprobe` as the single public entrypoint. Internally split the work into candidate normalization, probe execution (`credential` vs `unauthorized`), and optional enrichment. Reuse the current registry pattern, but add `ProbeKind`-aware lookup and explicit CLI flags so default behavior stays backward-compatible.

**Tech Stack:** Go, existing `pkg/secprobe` / `internal/secprobe` packages, `redis/go-redis`, official MongoDB Go driver, testcontainers-go, existing CLI in `cmd/main.go`

---

## File Structure

### Existing files to modify

- `internal/secprobe/core/types.go`
  - Extend core types with `ProbeKind`, new `FindingType` values, and new probe options for unauth/enrichment.
- `internal/secprobe/core/registry.go`
  - Make registry lookup aware of probe kind while keeping current simple iteration model.
- `pkg/secprobe/types.go`
  - Re-export new types/constants from `internal/secprobe/core`.
- `pkg/secprobe/run.go`
  - Split run flow into candidate iteration, kind selection, and optional enrichment pass.
- `pkg/secprobe/run_test.go`
  - Add run-pipeline tests for kind routing, defaults, and enrichment behavior.
- `pkg/secprobe/candidates.go`
  - Expand service normalization aliases and keep filtered candidate generation stable.
- `pkg/secprobe/candidates_test.go`
  - Add alias normalization coverage for `postgres`, `pgsql`, `mongo`, `redis/tls`, `redis/ssl`.
- `cmd/main.go`
  - Add `-enable-unauth` and `-enable-enrichment` to `weak` and `port -weak`.
- `cmd/main_test.go`
  - Add command-path tests that verify new flags are forwarded and default behavior remains credential-only.
- `README.md`
  - Document `v1.2` flags and explain default vs opt-in behavior.
- `examples/library/main.go`
  - Show library usage with `EnableUnauthorized` and `EnableEnrichment`.
- `internal/secprobe/testutil/testcontainers.go`
  - Add a MongoDB container helper and, if needed, a Redis-no-auth helper.

### New files to create

- `internal/secprobe/redis/unauthorized_prober.go`
  - Redis unauth detector.
- `internal/secprobe/redis/unauthorized_prober_test.go`
  - Redis unauth integration tests.
- `internal/secprobe/redis/enrichment.go`
  - Redis enrichment helper that returns trimmed INFO data.
- `internal/secprobe/mongodb/prober.go`
  - MongoDB unauthorized detector.
- `internal/secprobe/mongodb/prober_test.go`
  - MongoDB unauth integration tests.
- `internal/secprobe/mongodb/enrichment.go`
  - MongoDB enrichment helper that lists database names.
- `pkg/secprobe/enrichment_test.go`
  - Public-layer tests for enrichment pass wiring.

### Files intentionally left alone

- `pkg/assetprobe/...`
  - No result-model backflow.
- `internal/connect/...` and old weak-password remnants
  - Out of scope for `secprobe v1.2`.

## Task 1: Add Probe Kind and Run-Pipeline Skeleton

**Files:**
- Modify: `internal/secprobe/core/types.go`
- Modify: `internal/secprobe/core/registry.go`
- Modify: `internal/secprobe/ftp/prober.go`
- Modify: `internal/secprobe/mysql/prober.go`
- Modify: `internal/secprobe/postgresql/prober.go`
- Modify: `internal/secprobe/redis/prober.go`
- Modify: `internal/secprobe/ssh/prober.go`
- Modify: `internal/secprobe/telnet/prober.go`
- Modify: `pkg/secprobe/types.go`
- Modify: `pkg/secprobe/run.go`
- Test: `pkg/secprobe/run_test.go`

- [ ] **Step 1: Write the failing run-pipeline tests**

```go
func TestRunWithRegistryRoutesCandidateToUnauthorizedProber(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
	})

	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	if result.Results[0].ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized probe kind, got %+v", result.Results[0])
	}
	if result.Results[0].FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result.Results[0])
	}
}

func TestRunWithRegistrySkipsUnauthorizedProbeWhenDisabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
		},
	})

	result := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{})

	if got := result.Results[0].Error; got != "unsupported protocol" {
		t.Fatalf("expected unsupported protocol when unauth disabled, got %+v", result.Results[0])
	}
}

type stubKindedProber struct {
	name    string
	kind    ProbeKind
	service string
	result  SecurityResult
}

func (s *stubKindedProber) Name() string { return s.name }
func (s *stubKindedProber) Kind() ProbeKind { return s.kind }
func (s *stubKindedProber) Match(candidate SecurityCandidate) bool {
	return candidate.Service == s.service
}
func (s *stubKindedProber) Probe(context.Context, SecurityCandidate, CredentialProbeOptions, []Credential) SecurityResult {
	return s.result
}
```

- [ ] **Step 2: Run the focused run tests to verify failure**

Run: `go test ./pkg/secprobe -run 'TestRunWithRegistryRoutesCandidateToUnauthorizedProber|TestRunWithRegistrySkipsUnauthorizedProbeWhenDisabled' -v`
Expected: FAIL with unknown fields/constants such as `EnableUnauthorized`, `ProbeKindUnauthorized`, or missing kind-aware lookup behavior.

- [ ] **Step 3: Extend core types with `ProbeKind` and new options**

```go
type ProbeKind string

const (
	ProbeKindCredential   ProbeKind = "credential"
	ProbeKindUnauthorized ProbeKind = "unauthorized"
)

const (
	FindingTypeCredentialValid   = "credential-valid"
	FindingTypeUnauthorizedAccess = "unauthorized-access"
)

type CredentialProbeOptions struct {
	Protocols          []string
	Concurrency        int
	Timeout            time.Duration
	StopOnSuccess      bool
	DictDir            string
	Credentials        []Credential
	EnableUnauthorized bool
	EnableEnrichment   bool
}

type SecurityResult struct {
	Target      string
	ResolvedIP  string
	Port        int
	Service     string
	ProbeKind   ProbeKind
	FindingType string
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Enrichment  map[string]any
	Error       string
}
```

- [ ] **Step 4: Make the registry kind-aware**

```go
type Prober interface {
	Name() string
	Kind() ProbeKind
	Match(candidate SecurityCandidate) bool
	Probe(ctx context.Context, candidate SecurityCandidate, opts CredentialProbeOptions, creds []Credential) SecurityResult
}

func (r *Registry) Lookup(candidate SecurityCandidate, kind ProbeKind) (Prober, bool) {
	for _, prober := range r.probers {
		if prober.Kind() != kind {
			continue
		}
		if prober.Match(candidate) {
			return prober, true
		}
	}
	return nil, false
}
```

- [ ] **Step 5: Update existing credential probers to satisfy the new interface**

```go
func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }
```

Add the same one-line method to:

- `internal/secprobe/ftp/prober.go`
- `internal/secprobe/mysql/prober.go`
- `internal/secprobe/postgresql/prober.go`
- `internal/secprobe/redis/prober.go`
- `internal/secprobe/ssh/prober.go`
- `internal/secprobe/telnet/prober.go`

- [ ] **Step 6: Update `pkg/secprobe` aliases and run loop**

```go
const (
	FindingTypeCredentialValid    = core.FindingTypeCredentialValid
	FindingTypeUnauthorizedAccess = core.FindingTypeUnauthorizedAccess
)

type ProbeKind = core.ProbeKind

const (
	ProbeKindCredential   = core.ProbeKindCredential
	ProbeKindUnauthorized = core.ProbeKindUnauthorized
)
```

```go
func normalizeResult(base SecurityResult, result SecurityResult, kind ProbeKind) SecurityResult {
	if result.Target == "" {
		result.Target = base.Target
	}
	if result.ResolvedIP == "" {
		result.ResolvedIP = base.ResolvedIP
	}
	if result.Port == 0 {
		result.Port = base.Port
	}
	if result.Service == "" {
		result.Service = base.Service
	}
	if result.ProbeKind == "" {
		result.ProbeKind = kind
	}
	if result.FindingType == "" {
		if kind == ProbeKindUnauthorized {
			result.FindingType = FindingTypeUnauthorizedAccess
		} else {
			result.FindingType = FindingTypeCredentialValid
		}
	}
	return result
}

func probeKindsForCandidate(opts CredentialProbeOptions) []ProbeKind {
	kinds := []ProbeKind{ProbeKindCredential}
	if opts.EnableUnauthorized {
		kinds = append(kinds, ProbeKindUnauthorized)
	}
	return kinds
}

func probeCandidate(ctx context.Context, registry *Registry, candidate SecurityCandidate, opts CredentialProbeOptions) (SecurityResult, probeStatus) {
	base := SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   ProbeKindCredential,
		FindingType: FindingTypeCredentialValid,
	}

	for _, kind := range probeKindsForCandidate(opts) {
		prober, ok := registry.Lookup(candidate, kind)
		if !ok {
			continue
		}

		var creds []Credential
		var err error
		if kind == ProbeKindCredential {
			creds, err = credentialsForCandidate(candidate.Service, opts)
			if err != nil {
				base.Error = err.Error()
				return base, probeFailedBeforeAttempt
			}
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		result := prober.Probe(probeCtx, candidate, opts, creds)
		cancel()
		if result.Success {
			return normalizeResult(base, result, kind), probeAttemptSucceeded
		}
		base = normalizeResult(base, result, kind)
	}

	if base.Error == "" {
		base.Error = "unsupported protocol"
	}
	return base, probeSkipped
}
```

- [ ] **Step 7: Re-run the focused run tests**

Run: `go test ./pkg/secprobe -run 'TestRunWithRegistryRoutesCandidateToUnauthorizedProber|TestRunWithRegistrySkipsUnauthorizedProbeWhenDisabled' -v`
Expected: PASS

- [ ] **Step 8: Run the package tests**

Run: `go test ./pkg/secprobe -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/secprobe/core/types.go internal/secprobe/core/registry.go internal/secprobe/ftp/prober.go internal/secprobe/mysql/prober.go internal/secprobe/postgresql/prober.go internal/secprobe/redis/prober.go internal/secprobe/ssh/prober.go internal/secprobe/telnet/prober.go pkg/secprobe/types.go pkg/secprobe/run.go pkg/secprobe/run_test.go
git commit -m "refactor(secprobe): add probe kind aware run pipeline"
```

## Task 2: Expand Candidate Normalization for Weak-Auth Routing

**Files:**
- Modify: `pkg/secprobe/candidates.go`
- Test: `pkg/secprobe/candidates_test.go`

- [ ] **Step 1: Write the failing normalization tests**

```go
func TestNormalizeServiceNameSupportsWeakAuthAliases(t *testing.T) {
	tests := []struct {
		service string
		port    int
		want    string
	}{
		{service: "postgres", port: 5432, want: "postgresql"},
		{service: "pgsql", port: 5432, want: "postgresql"},
		{service: "mongo", port: 27017, want: "mongodb"},
		{service: "redis/tls", port: 6379, want: "redis"},
		{service: "redis/ssl", port: 6379, want: "redis"},
	}

	for _, tt := range tests {
		if got := NormalizeServiceName(tt.service, tt.port); got != tt.want {
			t.Fatalf("NormalizeServiceName(%q, %d) = %q, want %q", tt.service, tt.port, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run the candidate tests to verify failure**

Run: `go test ./pkg/secprobe -run TestNormalizeServiceNameSupportsWeakAuthAliases -v`
Expected: FAIL for `postgres`, `pgsql`, or `mongo`.

- [ ] **Step 3: Extend supported-by-port and alias normalization**

```go
var supportedByPort = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	27017: "mongodb",
}

func NormalizeServiceName(service string, port int) string {
	service = strings.ToLower(strings.TrimSpace(service))
	service = strings.TrimSuffix(service, "?")
	service = strings.TrimSuffix(service, "/ssl")
	service = strings.TrimSuffix(service, "/tls")

	switch service {
	case "ftp", "ssh", "mysql", "postgresql", "redis", "telnet", "mongodb":
		return service
	case "postgres", "pgsql":
		return "postgresql"
	case "mongo":
		return "mongodb"
	case "":
		return supportedByPort[port]
	default:
		if v, ok := supportedByPort[port]; ok && strings.Contains(service, v) {
			return v
		}
		return supportedByPort[port]
	}
}
```

- [ ] **Step 4: Re-run the focused candidate test**

Run: `go test ./pkg/secprobe -run TestNormalizeServiceNameSupportsWeakAuthAliases -v`
Expected: PASS

- [ ] **Step 5: Run the package tests**

Run: `go test ./pkg/secprobe -run 'TestNormalizeServiceName|TestBuildCandidates' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add pkg/secprobe/candidates.go pkg/secprobe/candidates_test.go
git commit -m "feat(secprobe): expand candidate service normalization"
```

## Task 3: Add Redis and MongoDB Unauthorized Probers

**Files:**
- Create: `internal/secprobe/redis/unauthorized_prober.go`
- Create: `internal/secprobe/redis/unauthorized_prober_test.go`
- Create: `internal/secprobe/mongodb/prober.go`
- Create: `internal/secprobe/mongodb/prober_test.go`
- Modify: `internal/secprobe/testutil/testcontainers.go`
- Modify: `pkg/secprobe/run.go`

- [ ] **Step 1: Write the failing Redis unauthorized test**

```go
func TestRedisUnauthorizedProberFindsUnauthenticatedInstance(t *testing.T) {
	container := testutil.StartRedisNoAuth(t)

	prober := redisprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "redis",
	}, secprobe.CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	}, nil)

	if !result.Success {
		t.Fatalf("expected redis unauthorized success, got %+v", result)
	}
	if result.ProbeKind != secprobe.ProbeKindUnauthorized {
		t.Fatalf("expected unauthorized kind, got %+v", result)
	}
	if result.FindingType != secprobe.FindingTypeUnauthorizedAccess {
		t.Fatalf("expected unauthorized finding type, got %+v", result)
	}
}
```

- [ ] **Step 2: Write the failing MongoDB unauthorized test**

```go
func TestMongoDBUnauthorizedProberFindsAnonymousAccess(t *testing.T) {
	container := testutil.StartMongoDBNoAuth(t)

	prober := mongodbprobe.NewUnauthorized()
	result := prober.Probe(context.Background(), secprobe.SecurityCandidate{
		Target:     container.Host,
		ResolvedIP: container.Host,
		Port:       container.Port,
		Service:    "mongodb",
	}, secprobe.CredentialProbeOptions{
		Timeout:            5 * time.Second,
		EnableUnauthorized: true,
	}, nil)

	if !result.Success {
		t.Fatalf("expected mongodb unauthorized success, got %+v", result)
	}
}
```

- [ ] **Step 3: Run the focused unauthorized tests to verify failure**

Run: `go test ./internal/secprobe/redis ./internal/secprobe/mongodb -run 'TestRedisUnauthorizedProberFindsUnauthenticatedInstance|TestMongoDBUnauthorizedProberFindsAnonymousAccess' -v`
Expected: FAIL because the files/helpers do not exist yet.

- [ ] **Step 4: Add container helpers for unauth Redis and MongoDB**

```go
func StartRedisNoAuth(t *testing.T) ServiceContainer {
	t.Helper()
	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "redis:7.4.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Cmd:          []string{"redis-server", "--port", "6379"},
		WaitingFor: wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
	}, "6379/tcp")
}

func StartMongoDBNoAuth(t *testing.T) ServiceContainer {
	t.Helper()
	return startServiceContainer(t, testcontainers.ContainerRequest{
		Image:        "mongo:8.0.6",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor: wait.ForListeningPort("27017/tcp").WithStartupTimeout(120 * time.Second),
	}, "27017/tcp")
}
```

- [ ] **Step 5: Implement Redis unauthorized prober**

```go
func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "redis-unauthorized" }
func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }
func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "redis"
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

	client := gredis.NewClient(&gredis.Options{
		Addr:         net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port)),
		DialTimeout:  opts.Timeout,
		ReadTimeout:  opts.Timeout,
		WriteTimeout: opts.Timeout,
	})
	defer client.Close()

	info, err := client.Info(ctx).Result()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if strings.Contains(info, "redis_version") {
		result.Success = true
		result.Evidence = "INFO returned redis_version without authentication"
	}
	return result
}
```

- [ ] **Step 6: Implement MongoDB unauthorized prober**

```go
func NewUnauthorized() core.Prober { return unauthorizedProber{} }

type unauthorizedProber struct{}

func (unauthorizedProber) Name() string { return "mongodb-unauthorized" }
func (unauthorizedProber) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }
func (unauthorizedProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "mongodb"
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

	uri := fmt.Sprintf("mongodb://%s:%d", candidate.ResolvedIP, candidate.Port)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer client.Disconnect(ctx)

	names, err := client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.Evidence = fmt.Sprintf("listDatabases succeeded (%d databases)", len(names))
	return result
}
```

- [ ] **Step 7: Register the new unauthorized probers**

```go
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(sshprobe.New())
	r.Register(ftpprobe.New())
	r.Register(mysqlprobe.New())
	r.Register(postgresqlprobe.New())
	r.Register(redisprobe.New())
	r.Register(redisprobe.NewUnauthorized())
	r.Register(mongodbprobe.NewUnauthorized())
	r.Register(telnetprobe.New())
	return r
}
```

- [ ] **Step 8: Run the unauthorized package tests**

Run: `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb -v`
Expected: PASS

- [ ] **Step 9: Run the public package tests**

Run: `go test -count=1 ./pkg/secprobe -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/secprobe/redis/unauthorized_prober.go internal/secprobe/redis/unauthorized_prober_test.go internal/secprobe/mongodb/prober.go internal/secprobe/mongodb/prober_test.go internal/secprobe/testutil/testcontainers.go pkg/secprobe/run.go
git commit -m "feat(secprobe): add redis and mongodb unauthorized probers"
```

## Task 4: Add Optional Enrichment Pass for Successful Findings

**Files:**
- Create: `internal/secprobe/redis/enrichment.go`
- Create: `internal/secprobe/mongodb/enrichment.go`
- Create: `pkg/secprobe/enrichment_test.go`
- Modify: `pkg/secprobe/run.go`

- [ ] **Step 1: Write the failing enrichment tests**

```go
func TestRunWithRegistryAddsRedisEnrichmentWhenEnabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Success:     true,
			Evidence:    "INFO returned redis_version",
		},
	})

	restore := stubEnrichmentRunner(func(_ context.Context, result SecurityResult, _ CredentialProbeOptions) SecurityResult {
		result.Enrichment = map[string]any{"info_excerpt": "# Server\r\nredis_version:7.4.2"}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       6379,
		Service:    "redis",
	}}, CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	})

	if got.Results[0].Enrichment == nil {
		t.Fatalf("expected enrichment payload, got %+v", got.Results[0])
	}
}

func stubEnrichmentRunner(fn func(context.Context, SecurityResult, CredentialProbeOptions) SecurityResult) func() {
	old := runEnrichment
	runEnrichment = fn
	return func() { runEnrichment = old }
}
```

- [ ] **Step 2: Run the focused enrichment test to verify failure**

Run: `go test ./pkg/secprobe -run TestRunWithRegistryAddsRedisEnrichmentWhenEnabled -v`
Expected: FAIL because `EnableEnrichment` or enrichment wiring does not exist.

- [ ] **Step 3: Add an enrichment runner seam and pass**

```go
var runEnrichment = func(ctx context.Context, result SecurityResult, opts CredentialProbeOptions) SecurityResult {
	return enrichResult(ctx, result, opts)
}

func applyEnrichment(ctx context.Context, results []SecurityResult, opts CredentialProbeOptions) []SecurityResult {
	if !opts.EnableEnrichment {
		return results
	}
	out := make([]SecurityResult, len(results))
	copy(out, results)
	for i, item := range out {
		if !item.Success {
			continue
		}
		out[i] = runEnrichment(ctx, item, opts)
	}
	return out
}
```

- [ ] **Step 4: Add Redis and MongoDB enrichment helpers**

```go
func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	client := gredis.NewClient(&gredis.Options{
		Addr:         net.JoinHostPort(result.ResolvedIP, strconv.Itoa(result.Port)),
		Username:     result.Username,
		Password:     result.Password,
		DialTimeout:  opts.Timeout,
		ReadTimeout:  opts.Timeout,
		WriteTimeout: opts.Timeout,
	})
	defer client.Close()

	info, err := client.Info(ctx).Result()
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	result.Enrichment = map[string]any{"info_excerpt": trimInfo(info)}
	return result
}
```

```go
func Enrich(ctx context.Context, result core.SecurityResult, _ core.CredentialProbeOptions) core.SecurityResult {
	var uri string
	if result.Username != "" || result.Password != "" {
		uri = fmt.Sprintf("mongodb://%s:%s@%s:%d/?authMechanism=SCRAM-SHA-1", url.QueryEscape(result.Username), url.QueryEscape(result.Password), result.ResolvedIP, result.Port)
	} else {
		uri = fmt.Sprintf("mongodb://%s:%d", result.ResolvedIP, result.Port)
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	defer client.Disconnect(ctx)

	names, err := client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	result.Enrichment = map[string]any{"databases": names}
	return result
}
```

- [ ] **Step 5: Wire service-based enrichment dispatch into `pkg/secprobe/run.go`**

```go
func enrichResult(ctx context.Context, result SecurityResult, opts CredentialProbeOptions) SecurityResult {
	switch result.Service {
	case "redis":
		return redisprobe.Enrich(ctx, result, opts)
	case "mongodb":
		return mongodbprobe.Enrich(ctx, result, opts)
	default:
		return result
	}
}
```

- [ ] **Step 6: Re-run the focused enrichment test**

Run: `go test ./pkg/secprobe -run TestRunWithRegistryAddsRedisEnrichmentWhenEnabled -v`
Expected: PASS

- [ ] **Step 7: Run the package tests**

Run: `go test -count=1 ./pkg/secprobe ./internal/secprobe/redis ./internal/secprobe/mongodb -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/secprobe/redis/enrichment.go internal/secprobe/mongodb/enrichment.go pkg/secprobe/run.go pkg/secprobe/enrichment_test.go
git commit -m "feat(secprobe): add optional finding enrichment"
```

## Task 5: Wire CLI Flags for Unauthorized and Enrichment Modes

**Files:**
- Modify: `cmd/main.go`
- Modify: `cmd/main_test.go`

- [ ] **Step 1: Write the failing CLI-path tests**

```go
func TestBuildPortWeakProbeOptionsForwardsUnauthorizedAndEnrichment(t *testing.T) {
	opts := buildPortWeakProbeOptions("redis", 7, 3*time.Second, false, "./dicts", true, true)

	if !opts.EnableUnauthorized {
		t.Fatal("expected unauthorized probing enabled")
	}
	if !opts.EnableEnrichment {
		t.Fatal("expected enrichment enabled")
	}
}

func TestRunWeakDefaultsToCredentialOnly(t *testing.T) {
	scanner := &stubPortScanner{batch: &assetprobe.BatchScanResult{}}
	restoreScanner := stubWeakScannerFactory(scanner)
	defer restoreScanner()

	oldRunner := runWeakProbe
	var gotOpts secprobe.CredentialProbeOptions
	runWeakProbe = func(_ context.Context, _ []secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions) secprobe.RunResult {
		gotOpts = opts
		return secprobe.RunResult{}
	}
	defer func() { runWeakProbe = oldRunner }()

	runWeak([]string{"-target", "demo"})

	if gotOpts.EnableUnauthorized {
		t.Fatal("expected unauthorized disabled by default")
	}
	if gotOpts.EnableEnrichment {
		t.Fatal("expected enrichment disabled by default")
	}
}
```

- [ ] **Step 2: Run the focused CLI tests to verify failure**

Run: `go test ./cmd -run 'TestBuildPortWeakProbeOptionsForwardsUnauthorizedAndEnrichment|TestRunWeakDefaultsToCredentialOnly' -v`
Expected: FAIL with wrong helper signature or missing options.

- [ ] **Step 3: Add new flags to `weak` and `port -weak`**

```go
	enableUnauth := fs.Bool("enable-unauth", false, "[可选] 启用未授权访问探测")
	enableEnrichment := fs.Bool("enable-enrichment", false, "[可选] 启用命中后详情补采")
```

- [ ] **Step 4: Extend option builders and runner seams**

```go
var runWeakProbe = func(ctx context.Context, candidates []secprobe.SecurityCandidate, opts secprobe.CredentialProbeOptions) secprobe.RunResult {
	return secprobe.Run(ctx, candidates, opts)
}

func buildPortWeakProbeOptions(protocols string, concurrency int, timeout time.Duration, stopOnSuccess bool, dictDir string, enableUnauth bool, enableEnrichment bool) secprobe.CredentialProbeOptions {
	return secprobe.CredentialProbeOptions{
		Protocols:          splitComma(protocols),
		Concurrency:        concurrency,
		Timeout:            timeout,
		StopOnSuccess:      stopOnSuccess,
		DictDir:            strings.TrimSpace(dictDir),
		EnableUnauthorized: enableUnauth,
		EnableEnrichment:   enableEnrichment,
	}
}
```

- [ ] **Step 5: Add a weak-path scanner seam for tests**

```go
var newWeakTargetScanner = func(opts assetprobe.Options) (portTargetScanner, error) {
	return assetprobe.NewScanner(opts)
}
```

Use it inside `runWeak(...)` instead of calling `assetprobe.NewScanner(...)` directly.

- [ ] **Step 6: Add `runWeak` test helpers**

```go
func stubWeakScannerFactory(scanner portTargetScanner) func() {
	oldFactory := newWeakTargetScanner
	newWeakTargetScanner = func(assetprobe.Options) (portTargetScanner, error) {
		return scanner, nil
	}
	return func() {
		newWeakTargetScanner = oldFactory
	}
}
```

- [ ] **Step 7: Wire the flags through both CLI paths**

```go
secprobeOpts := secprobe.CredentialProbeOptions{
	Protocols:          splitComma(*protocols),
	Concurrency:        *weakConcurrency,
	Timeout:            discoveryTimeout,
	StopOnSuccess:      *stopOnSuccess,
	DictDir:            strings.TrimSpace(*dictDir),
	Credentials:        creds,
	EnableUnauthorized: *enableUnauth,
	EnableEnrichment:   *enableEnrichment,
}

result := runWeakProbe(context.Background(), candidates, secprobeOpts)
```

- [ ] **Step 8: Re-run the focused CLI tests**

Run: `go test ./cmd -run 'TestBuildPortWeakProbeOptionsForwardsUnauthorizedAndEnrichment|TestRunWeakDefaultsToCredentialOnly' -v`
Expected: PASS

- [ ] **Step 9: Run all command tests**

Run: `go test ./cmd -v`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add cmd/main.go cmd/main_test.go
git commit -m "feat(cli): add unauth and enrichment weak flags"
```

## Task 6: Update Docs and Library Example

**Files:**
- Modify: `README.md`
- Modify: `examples/library/main.go`

- [ ] **Step 1: Add README examples for `-enable-unauth` and `-enable-enrichment`**

```md
### 5.4 协议账号口令探测（weak）

```bash
gomap weak -target example.com -ports 6379,27017 -enable-unauth
```

- `-enable-unauth`: 启用 `redis` / `mongodb` 未授权访问探测
- `-enable-enrichment`: 对成功 finding 追加详情补采
- 默认仍只执行 credential 探测
```

- [ ] **Step 2: Update the library example**

```go
security := secprobe.Run(
	context.Background(),
	secprobe.BuildCandidates(scanResult, secprobe.CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	}),
	secprobe.CredentialProbeOptions{
		EnableUnauthorized: true,
		EnableEnrichment:   true,
	},
)
```

- [ ] **Step 3: Run the no-test example package check**

Run: `go test ./examples/library -run '^$'`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add README.md examples/library/main.go
git commit -m "docs(secprobe): document v1.2 weak auth flags"
```

## Task 7: Final Verification

**Files:**
- Verify only

- [ ] **Step 1: Run package verification for secprobe and CLI**

Run: `go test -count=1 ./pkg/secprobe ./cmd ./internal/secprobe/...`
Expected: PASS

- [ ] **Step 2: Run targeted container-backed unauth tests**

Run: `go test -count=1 ./internal/secprobe/redis ./internal/secprobe/mongodb -v`
Expected: PASS

- [ ] **Step 3: Run full repository tests and capture known failures**

Run: `go test ./...`
Expected: PASS, or if the pre-existing `pkg/assetprobe` `TestScanTargetsKeepsOrderAndPerTargetErrors` still fails, note it explicitly as an existing unrelated failure before closing the work.

- [ ] **Step 4: Commit final verification notes if code changed during fixes**

```bash
git status --short
```

Expected: clean working tree or only intentional follow-up edits.
