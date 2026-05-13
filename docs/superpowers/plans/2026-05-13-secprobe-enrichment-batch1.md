# secprobe Enrichment Batch 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add minimal enrichment implementations for `postgresql`, `mysql`, and `elasticsearch` that produce a short `enrichment.payload` proof string after successful authenticated probing.

**Architecture:** Keep the existing `secprobe` enrichment framework unchanged. Extend protocol metadata to declare enrichment support, add one focused enricher per protocol under `internal/secprobe/<protocol>/enrichment.go`, and route them through `pkg/secprobe/enrichment_router.go`. Each enricher performs one read-only request and returns either `{"payload": "<request>\n\n<response>"}` or `{"error": "..."}` without changing the original finding semantics.

**Tech Stack:** Go 1.24, existing `secprobe` runtime and tests, `database/sql` with existing PostgreSQL/MySQL drivers, existing Elasticsearch HTTP auth helper patterns

---

## File Structure

### New files

- `internal/secprobe/postgresql/enrichment.go`
  - PostgreSQL enrichment implementation executing `SELECT version();`
- `internal/secprobe/postgresql/enrichment_test.go`
  - PostgreSQL enrichment unit tests
- `internal/secprobe/mysql/enrichment.go`
  - MySQL enrichment implementation executing `SELECT @@version;`
- `internal/secprobe/mysql/enrichment_test.go`
  - MySQL enrichment unit tests
- `internal/secprobe/elasticsearch/enrichment.go`
  - Elasticsearch enrichment implementation executing `GET /_security/_authenticate`
- `internal/secprobe/elasticsearch/enrichment_test.go`
  - Elasticsearch enrichment unit tests

### Modified files

- `app/secprobe/protocols/postgresql.yaml`
  - Enable enrichment capability
- `app/secprobe/protocols/mysql.yaml`
  - Enable enrichment capability
- `app/secprobe/protocols/elasticsearch.yaml`
  - Enable enrichment capability
- `pkg/secprobe/enrichment_router.go`
  - Route new protocol enrichers
- `pkg/secprobe/enrichment_test.go`
  - Add router and runtime integration coverage for the new protocols

### Files intentionally not changed

- `pkg/secprobe/run.go`
  - Existing enrichment execution semantics already match the spec
- `pkg/secprobe/types.go`
  - `Enrichment` remains `map[string]any`
- `cmd/main.go`
  - Existing `EnableEnrichment` flag flow remains unchanged

## Task 1: Enable Metadata Capabilities For Batch 1 Protocols

**Files:**
- Modify: `app/secprobe/protocols/postgresql.yaml`
- Modify: `app/secprobe/protocols/mysql.yaml`
- Modify: `app/secprobe/protocols/elasticsearch.yaml`
- Test: `pkg/secprobe/metadata/loader_test.go`

- [ ] **Step 1: Write the failing metadata capability test**

Add this test to `pkg/secprobe/metadata/loader_test.go`:

```go
func TestLoadBuiltinEnablesEnrichmentForBatch1Protocols(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	for _, name := range []string{"postgresql", "mysql", "elasticsearch"} {
		spec, ok := specs[name]
		if !ok {
			t.Fatalf("expected %s spec", name)
		}
		if !spec.Capabilities.Enrichment {
			t.Fatalf("expected %s enrichment enabled, got %+v", name, spec.Capabilities)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe/metadata -run TestLoadBuiltinEnablesEnrichmentForBatch1Protocols -count=1`

Expected: FAIL with `expected postgresql enrichment enabled` or similar capability mismatch.

- [ ] **Step 3: Update protocol metadata**

Update these YAML snippets:

`app/secprobe/protocols/postgresql.yaml`

```yaml
capabilities:
  credential: true
  unauthorized: false
  enrichment: true
```

`app/secprobe/protocols/mysql.yaml`

```yaml
capabilities:
  credential: true
  unauthorized: false
  enrichment: true
```

`app/secprobe/protocols/elasticsearch.yaml`

```yaml
capabilities:
  credential: true
  unauthorized: false
  enrichment: true
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/secprobe/metadata -run TestLoadBuiltinEnablesEnrichmentForBatch1Protocols -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/metadata/loader_test.go app/secprobe/protocols/postgresql.yaml app/secprobe/protocols/mysql.yaml app/secprobe/protocols/elasticsearch.yaml
git commit -m "feat(secprobe): enable enrichment for batch1 protocols"
```

## Task 2: Add PostgreSQL Enrichment

**Files:**
- Create: `internal/secprobe/postgresql/enrichment.go`
- Create: `internal/secprobe/postgresql/enrichment_test.go`

- [ ] **Step 1: Write the failing PostgreSQL enrichment tests**

Create `internal/secprobe/postgresql/enrichment_test.go`:

```go
package postgresql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestEnrichReturnsPayloadForVersionQuery(t *testing.T) {
	restore := stubPostgresEnrichmentQuery(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "SELECT version();", "PostgreSQL 16.2", nil
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Target:     "db.local",
		ResolvedIP: "127.0.0.1",
		Port:       5432,
		Service:    "postgresql",
		Success:    true,
		Username:   "root",
		Password:   "secret",
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["payload"] != "SELECT version();\n\nPostgreSQL 16.2" {
		t.Fatalf("unexpected payload: %+v", got.Enrichment)
	}
}

func TestEnrichReturnsErrorPayloadOnFailure(t *testing.T) {
	restore := stubPostgresEnrichmentQuery(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "", "", errors.New("query failed")
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "postgresql",
		Success:  true,
		Username: "root",
		Password: "secret",
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["error"] != "query failed" {
		t.Fatalf("unexpected error payload: %+v", got.Enrichment)
	}
	if !got.Success {
		t.Fatalf("expected success to remain true, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/secprobe/postgresql -run 'TestEnrichReturnsPayloadForVersionQuery|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: FAIL with `undefined: Enrich` and `undefined: stubPostgresEnrichmentQuery`.

- [ ] **Step 3: Write minimal PostgreSQL enrichment implementation**

Create `internal/secprobe/postgresql/enrichment.go`:

```go
package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

var postgresEnrichmentQuery = func(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) (string, string, error) {
		host := result.ResolvedIP
		if host == "" {
			host = result.Target
		}

		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
			host,
			result.Port,
			result.Username,
			result.Password,
			max(1, int(opts.Timeout.Seconds())),
		)
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return "", "", err
		}
		defer func() { _ = db.Close() }()

		queryCtx := ctx
		cancel := func() {}
		if opts.Timeout > 0 {
			queryCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		}
		defer cancel()

		var version string
		if err := db.QueryRowContext(queryCtx, "SELECT version();").Scan(&version); err != nil {
			return "", "", err
		}
		return "SELECT version();", strings.TrimSpace(version), nil
	}

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	request, response, err := postgresEnrichmentQuery(ctx, result, opts)
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	result.Enrichment = map[string]any{"payload": request + "\n\n" + response}
	return result
}

func stubPostgresEnrichmentQuery(fn func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error)) func() {
	previous := postgresEnrichmentQuery
	postgresEnrichmentQuery = fn
	return func() {
		postgresEnrichmentQuery = previous
	}
}
```

Then remove unused imports and helpers the engineer accidentally added. Final imports should be only the ones actually used.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/secprobe/postgresql -run 'TestEnrichReturnsPayloadForVersionQuery|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/secprobe/postgresql/enrichment.go internal/secprobe/postgresql/enrichment_test.go
git commit -m "feat(secprobe): add postgresql enrichment payload"
```

## Task 3: Add MySQL Enrichment

**Files:**
- Create: `internal/secprobe/mysql/enrichment.go`
- Create: `internal/secprobe/mysql/enrichment_test.go`

- [ ] **Step 1: Write the failing MySQL enrichment tests**

Create `internal/secprobe/mysql/enrichment_test.go`:

```go
package mysql

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestEnrichReturnsPayloadForVersionQuery(t *testing.T) {
	restore := stubMySQLEnrichmentQuery(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "SELECT @@version;", "8.0.36", nil
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "mysql",
		Success:  true,
		Username: "root",
		Password: "secret",
		Port:     3306,
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["payload"] != "SELECT @@version;\n\n8.0.36" {
		t.Fatalf("unexpected payload: %+v", got.Enrichment)
	}
}

func TestEnrichReturnsErrorPayloadOnFailure(t *testing.T) {
	restore := stubMySQLEnrichmentQuery(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "", "", errors.New("query failed")
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "mysql",
		Success:  true,
		Username: "root",
		Password: "secret",
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["error"] != "query failed" {
		t.Fatalf("unexpected error payload: %+v", got.Enrichment)
	}
	if !got.Success {
		t.Fatalf("expected success to remain true, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/secprobe/mysql -run 'TestEnrichReturnsPayloadForVersionQuery|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: FAIL with `undefined: Enrich` and `undefined: stubMySQLEnrichmentQuery`.

- [ ] **Step 3: Write minimal MySQL enrichment implementation**

Create `internal/secprobe/mysql/enrichment.go`:

```go
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

var mysqlEnrichmentQuery = func(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) (string, string, error) {
		host := result.ResolvedIP
		if host == "" {
			host = result.Target
		}

		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=%s&readTimeout=%s&writeTimeout=%s",
			result.Username,
			result.Password,
			host,
			result.Port,
			opts.Timeout,
			opts.Timeout,
			opts.Timeout,
		)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			return "", "", err
		}
		defer func() { _ = db.Close() }()

		queryCtx := ctx
		cancel := func() {}
		if opts.Timeout > 0 {
			queryCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		}
		defer cancel()

		var version string
		if err := db.QueryRowContext(queryCtx, "SELECT @@version;").Scan(&version); err != nil {
			return "", "", err
		}
		return "SELECT @@version;", strings.TrimSpace(version), nil
	}

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	request, response, err := mysqlEnrichmentQuery(ctx, result, opts)
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	result.Enrichment = map[string]any{"payload": request + "\n\n" + response}
	return result
}

func stubMySQLEnrichmentQuery(fn func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error)) func() {
	previous := mysqlEnrichmentQuery
	mysqlEnrichmentQuery = fn
	return func() {
		mysqlEnrichmentQuery = previous
	}
}
```

Then remove unused imports and keep the file minimal.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/secprobe/mysql -run 'TestEnrichReturnsPayloadForVersionQuery|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/secprobe/mysql/enrichment.go internal/secprobe/mysql/enrichment_test.go
git commit -m "feat(secprobe): add mysql enrichment payload"
```

## Task 4: Add Elasticsearch Enrichment

**Files:**
- Create: `internal/secprobe/elasticsearch/enrichment.go`
- Create: `internal/secprobe/elasticsearch/enrichment_test.go`

- [ ] **Step 1: Write the failing Elasticsearch enrichment tests**

Create `internal/secprobe/elasticsearch/enrichment_test.go`:

```go
package elasticsearch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestEnrichReturnsPayloadForAuthenticateRequest(t *testing.T) {
	restore := stubElasticsearchEnrichmentRequest(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "GET /_security/_authenticate", "200 OK\nusername: elastic", nil
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "elasticsearch",
		Success:  true,
		Username: "elastic",
		Password: "secret",
		Port:     9200,
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["payload"] != "GET /_security/_authenticate\n\n200 OK\nusername: elastic" {
		t.Fatalf("unexpected payload: %+v", got.Enrichment)
	}
}

func TestEnrichReturnsErrorPayloadOnFailure(t *testing.T) {
	restore := stubElasticsearchEnrichmentRequest(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "", "", errors.New("request failed")
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "elasticsearch",
		Success:  true,
		Username: "elastic",
		Password: "secret",
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["error"] != "request failed" {
		t.Fatalf("unexpected error payload: %+v", got.Enrichment)
	}
	if !got.Success {
		t.Fatalf("expected success to remain true, got %+v", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/secprobe/elasticsearch -run 'TestEnrichReturnsPayloadForAuthenticateRequest|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: FAIL with `undefined: Enrich` and `undefined: stubElasticsearchEnrichmentRequest`.

- [ ] **Step 3: Write minimal Elasticsearch enrichment implementation**

Create `internal/secprobe/elasticsearch/enrichment.go`:

```go
package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type elasticsearchAuthenticateResponse struct {
	Username string `json:"username"`
}

var elasticsearchEnrichmentRequest = func(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) (string, string, error) {
		host := result.ResolvedIP
		if host == "" {
			host = result.Target
		}

		url := fmt.Sprintf("http://%s:%d/_security/_authenticate", host, result.Port)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", "", err
		}
		req.SetBasicAuth(result.Username, result.Password)

		client := &http.Client{Timeout: opts.Timeout}
		resp, err := client.Do(req)
		if err != nil {
			return "", "", err
		}
		defer func() { _ = resp.Body.Close() }()

		var body elasticsearchAuthenticateResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return "", "", err
		}

		response := fmt.Sprintf("%s\nusername: %s", resp.Status, strings.TrimSpace(body.Username))
		return "GET /_security/_authenticate", response, nil
	}

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	request, response, err := elasticsearchEnrichmentRequest(ctx, result, opts)
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	result.Enrichment = map[string]any{"payload": request + "\n\n" + response}
	return result
}

func stubElasticsearchEnrichmentRequest(fn func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error)) func() {
	previous := elasticsearchEnrichmentRequest
	elasticsearchEnrichmentRequest = fn
	return func() {
		elasticsearchEnrichmentRequest = previous
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/secprobe/elasticsearch -run 'TestEnrichReturnsPayloadForAuthenticateRequest|TestEnrichReturnsErrorPayloadOnFailure' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/secprobe/elasticsearch/enrichment.go internal/secprobe/elasticsearch/enrichment_test.go
git commit -m "feat(secprobe): add elasticsearch enrichment payload"
```

## Task 5: Route Batch 1 Enrichers Through secprobe

**Files:**
- Modify: `pkg/secprobe/enrichment_router.go`
- Test: `pkg/secprobe/enrichment_test.go`

- [ ] **Step 1: Write the failing router tests**

Add these tests to `pkg/secprobe/enrichment_test.go`:

```go
func TestEnrichResultRoutesPostgreSQLToPostgreSQLEnricher(t *testing.T) {
	restore := stubAllEnrichmentRoutersForBatch1(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			result.Enrichment = map[string]any{"payload": "postgresql"}
			return result
		},
		nil,
		nil,
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{Service: "postgresql"}, CredentialProbeOptions{})
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"payload": "postgresql"}) {
		t.Fatalf("unexpected postgresql enrichment: %+v", got.Enrichment)
	}
}

func TestEnrichResultRoutesMySQLToMySQLEnricher(t *testing.T) {
	restore := stubAllEnrichmentRoutersForBatch1(
		nil,
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			result.Enrichment = map[string]any{"payload": "mysql"}
			return result
		},
		nil,
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{Service: "mysql"}, CredentialProbeOptions{})
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"payload": "mysql"}) {
		t.Fatalf("unexpected mysql enrichment: %+v", got.Enrichment)
	}
}

func TestEnrichResultRoutesElasticsearchToElasticsearchEnricher(t *testing.T) {
	restore := stubAllEnrichmentRoutersForBatch1(
		nil,
		nil,
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			result.Enrichment = map[string]any{"payload": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{Service: "elasticsearch"}, CredentialProbeOptions{})
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"payload": "elasticsearch"}) {
		t.Fatalf("unexpected elasticsearch enrichment: %+v", got.Enrichment)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/secprobe -run 'TestEnrichResultRoutesPostgreSQLToPostgreSQLEnricher|TestEnrichResultRoutesMySQLToMySQLEnricher|TestEnrichResultRoutesElasticsearchToElasticsearchEnricher' -count=1`

Expected: FAIL with missing router stubs or unmatched route behavior.

- [ ] **Step 3: Update the enrichment router**

Update `pkg/secprobe/enrichment_router.go` so it looks like:

```go
package secprobe

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
	elasticsearchprobe "github.com/yrighc/gomap/internal/secprobe/elasticsearch"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
)

var (
	enrichRedisResult         = redisprobe.Enrich
	enrichMongoDBResult       = mongodbprobe.Enrich
	enrichPostgreSQLResult    = postgresqlprobe.Enrich
	enrichMySQLResult         = mysqlprobe.Enrich
	enrichElasticsearchResult = elasticsearchprobe.Enrich
)

func enrichResult(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	switch result.Service {
	case "redis":
		return enrichRedisResult(ctx, result, opts)
	case "mongodb":
		return enrichMongoDBResult(ctx, result, opts)
	case "postgresql":
		return enrichPostgreSQLResult(ctx, result, opts)
	case "mysql":
		return enrichMySQLResult(ctx, result, opts)
	case "elasticsearch":
		return enrichElasticsearchResult(ctx, result, opts)
	default:
		return result
	}
}
```

Add a helper stub in `pkg/secprobe/enrichment_test.go`:

```go
func stubAllEnrichmentRoutersForBatch1(
	postgresql func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	mysql func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	elasticsearch func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
) func() {
	previousPostgreSQL := enrichPostgreSQLResult
	previousMySQL := enrichMySQLResult
	previousElasticsearch := enrichElasticsearchResult
	if postgresql != nil {
		enrichPostgreSQLResult = postgresql
	}
	if mysql != nil {
		enrichMySQLResult = mysql
	}
	if elasticsearch != nil {
		enrichElasticsearchResult = elasticsearch
	}
	return func() {
		enrichPostgreSQLResult = previousPostgreSQL
		enrichMySQLResult = previousMySQL
		enrichElasticsearchResult = previousElasticsearch
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/secprobe -run 'TestEnrichResultRoutesPostgreSQLToPostgreSQLEnricher|TestEnrichResultRoutesMySQLToMySQLEnricher|TestEnrichResultRoutesElasticsearchToElasticsearchEnricher' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/enrichment_router.go pkg/secprobe/enrichment_test.go
git commit -m "feat(secprobe): route batch1 enrichment providers"
```

## Task 6: Verify Runtime Enrichment Semantics For Batch 1

**Files:**
- Modify: `pkg/secprobe/enrichment_test.go`

- [ ] **Step 1: Write the failing runtime integration test**

Add this test to `pkg/secprobe/enrichment_test.go`:

```go
func TestRunWithRegistryAddsPostgreSQLEnrichmentWhenEnabled(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "postgresql-credential",
		kind:    ProbeKindCredential,
		service: "postgresql",
		result: SecurityResult{
			Service:     "postgresql",
			ProbeKind:   ProbeKindCredential,
			FindingType: FindingTypeCredentialValid,
			Success:     true,
			Evidence:    "PostgreSQL authentication succeeded",
		},
	})

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		if result.Service == "postgresql" {
			result.Enrichment = map[string]any{"payload": "SELECT version();\n\nPostgreSQL 16.2"}
		}
		return result
	})
	defer restore()

	got := RunWithRegistry(context.Background(), registry, []SecurityCandidate{{
		Target:     "demo",
		ResolvedIP: "127.0.0.1",
		Port:       5432,
		Service:    "postgresql",
	}}, CredentialProbeOptions{
		EnableEnrichment: true,
		Credentials:      []Credential{{Username: "root", Password: "secret"}},
	})

	if got.Results[0].Enrichment["payload"] != "SELECT version();\n\nPostgreSQL 16.2" {
		t.Fatalf("unexpected enrichment payload: %+v", got.Results[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails if the route is not wired correctly**

Run: `go test ./pkg/secprobe -run TestRunWithRegistryAddsPostgreSQLEnrichmentWhenEnabled -count=1`

Expected: If routing is still broken, FAIL with missing enrichment payload; otherwise PASS after Task 5.

- [ ] **Step 3: Keep the runtime semantics unchanged**

Do not change `pkg/secprobe/run.go`. This task exists to verify the current semantics already satisfy the spec:

- enrichment only when enabled
- only on successful results
- errors remain non-fatal

No code block change required if the test passes after Task 5.

- [ ] **Step 4: Run the focused runtime tests**

Run: `go test ./pkg/secprobe -run 'TestRunWithRegistryAddsPostgreSQLEnrichmentWhenEnabled|TestRunWithRegistrySkipsEnrichmentWhenDisabled|TestRunWithRegistrySkipsEnrichmentForFailedResult|TestRunWithRegistryKeepsFindingSemanticsWhenEnrichmentReturnsError' -count=1`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/secprobe/enrichment_test.go
git commit -m "test(secprobe): verify batch1 enrichment runtime semantics"
```

## Task 7: Final Verification

**Files:**
- Test only; no new files

- [ ] **Step 1: Run protocol unit tests**

Run: `go test ./internal/secprobe/postgresql ./internal/secprobe/mysql ./internal/secprobe/elasticsearch -count=1`

Expected: PASS

- [ ] **Step 2: Run secprobe package tests**

Run: `go test ./pkg/secprobe ./pkg/secprobe/metadata -count=1`

Expected: PASS, except for unrelated pre-existing worktree changes if any are already known before execution.

- [ ] **Step 3: Run app metadata embedding tests**

Run: `go test ./app -count=1`

Expected: PASS

- [ ] **Step 4: Review spec coverage**

Check that the implementation covers:

- PostgreSQL enrichment payload
- MySQL enrichment payload
- Elasticsearch enrichment payload
- metadata capability enablement
- router wiring
- non-fatal enrichment error behavior

Expected: all covered with no missing spec items.

- [ ] **Step 5: Commit**

```bash
git add app/secprobe/protocols/postgresql.yaml app/secprobe/protocols/mysql.yaml app/secprobe/protocols/elasticsearch.yaml pkg/secprobe/enrichment_router.go pkg/secprobe/enrichment_test.go internal/secprobe/postgresql/enrichment.go internal/secprobe/postgresql/enrichment_test.go internal/secprobe/mysql/enrichment.go internal/secprobe/mysql/enrichment_test.go internal/secprobe/elasticsearch/enrichment.go internal/secprobe/elasticsearch/enrichment_test.go
git commit -m "feat(secprobe): add batch1 enrichment implementations"
```
