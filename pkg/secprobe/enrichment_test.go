package secprobe

import (
	"context"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestEnrichResultRoutesRedisToRedisEnricher(t *testing.T) {
	redisCalls := 0
	mongodbCalls := 0
	postgresqlCalls := 0
	mysqlCalls := 0
	elasticsearchCalls := 0
	restore := stubEnrichmentRouters(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			redisCalls++
			result.Enrichment = map[string]any{"source": "redis"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mongodbCalls++
			result.Enrichment = map[string]any{"source": "mongodb"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			postgresqlCalls++
			result.Enrichment = map[string]any{"source": "postgresql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mysqlCalls++
			result.Enrichment = map[string]any{"source": "mysql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			elasticsearchCalls++
			result.Enrichment = map[string]any{"source": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{
		Service: "redis",
	}, CredentialProbeOptions{})

	if redisCalls != 1 {
		t.Fatalf("expected redis enricher to be called once, got %d", redisCalls)
	}
	if mongodbCalls != 0 {
		t.Fatalf("expected mongodb enricher to stay idle, got %d", mongodbCalls)
	}
	if postgresqlCalls != 0 || mysqlCalls != 0 || elasticsearchCalls != 0 {
		t.Fatalf("expected only redis enricher to run, got postgresql=%d mysql=%d elasticsearch=%d", postgresqlCalls, mysqlCalls, elasticsearchCalls)
	}
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"source": "redis"}) {
		t.Fatalf("expected redis enrichment payload, got %+v", got)
	}
}

func TestEnrichResultRoutesMongoDBToMongoDBEnricher(t *testing.T) {
	redisCalls := 0
	mongodbCalls := 0
	postgresqlCalls := 0
	mysqlCalls := 0
	elasticsearchCalls := 0
	restore := stubEnrichmentRouters(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			redisCalls++
			result.Enrichment = map[string]any{"source": "redis"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mongodbCalls++
			result.Enrichment = map[string]any{"source": "mongodb"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			postgresqlCalls++
			result.Enrichment = map[string]any{"source": "postgresql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mysqlCalls++
			result.Enrichment = map[string]any{"source": "mysql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			elasticsearchCalls++
			result.Enrichment = map[string]any{"source": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{
		Service: "mongodb",
	}, CredentialProbeOptions{})

	if mongodbCalls != 1 {
		t.Fatalf("expected mongodb enricher to be called once, got %d", mongodbCalls)
	}
	if redisCalls != 0 {
		t.Fatalf("expected redis enricher to stay idle, got %d", redisCalls)
	}
	if postgresqlCalls != 0 || mysqlCalls != 0 || elasticsearchCalls != 0 {
		t.Fatalf("expected only mongodb enricher to run, got postgresql=%d mysql=%d elasticsearch=%d", postgresqlCalls, mysqlCalls, elasticsearchCalls)
	}
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"source": "mongodb"}) {
		t.Fatalf("expected mongodb enrichment payload, got %+v", got)
	}
}

func TestEnrichResultRoutesPostgreSQLToPostgreSQLEnricher(t *testing.T) {
	redisCalls := 0
	mongodbCalls := 0
	postgresqlCalls := 0
	mysqlCalls := 0
	elasticsearchCalls := 0
	restore := stubEnrichmentRouters(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			redisCalls++
			result.Enrichment = map[string]any{"source": "redis"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mongodbCalls++
			result.Enrichment = map[string]any{"source": "mongodb"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			postgresqlCalls++
			result.Enrichment = map[string]any{"source": "postgresql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mysqlCalls++
			result.Enrichment = map[string]any{"source": "mysql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			elasticsearchCalls++
			result.Enrichment = map[string]any{"source": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{
		Service: "postgresql",
	}, CredentialProbeOptions{})

	if postgresqlCalls != 1 {
		t.Fatalf("expected postgresql enricher to be called once, got %d", postgresqlCalls)
	}
	if redisCalls != 0 || mongodbCalls != 0 || mysqlCalls != 0 || elasticsearchCalls != 0 {
		t.Fatalf("expected other enrichers to stay idle, got redis=%d mongodb=%d mysql=%d elasticsearch=%d", redisCalls, mongodbCalls, mysqlCalls, elasticsearchCalls)
	}
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"source": "postgresql"}) {
		t.Fatalf("expected postgresql enrichment payload, got %+v", got)
	}
}

func TestEnrichResultRoutesMySQLToMySQLEnricher(t *testing.T) {
	redisCalls := 0
	mongodbCalls := 0
	postgresqlCalls := 0
	mysqlCalls := 0
	elasticsearchCalls := 0
	restore := stubEnrichmentRouters(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			redisCalls++
			result.Enrichment = map[string]any{"source": "redis"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mongodbCalls++
			result.Enrichment = map[string]any{"source": "mongodb"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			postgresqlCalls++
			result.Enrichment = map[string]any{"source": "postgresql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mysqlCalls++
			result.Enrichment = map[string]any{"source": "mysql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			elasticsearchCalls++
			result.Enrichment = map[string]any{"source": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{
		Service: "mysql",
	}, CredentialProbeOptions{})

	if mysqlCalls != 1 {
		t.Fatalf("expected mysql enricher to be called once, got %d", mysqlCalls)
	}
	if redisCalls != 0 || mongodbCalls != 0 || postgresqlCalls != 0 || elasticsearchCalls != 0 {
		t.Fatalf("expected other enrichers to stay idle, got redis=%d mongodb=%d postgresql=%d elasticsearch=%d", redisCalls, mongodbCalls, postgresqlCalls, elasticsearchCalls)
	}
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"source": "mysql"}) {
		t.Fatalf("expected mysql enrichment payload, got %+v", got)
	}
}

func TestEnrichResultRoutesElasticsearchToElasticsearchEnricher(t *testing.T) {
	redisCalls := 0
	mongodbCalls := 0
	postgresqlCalls := 0
	mysqlCalls := 0
	elasticsearchCalls := 0
	restore := stubEnrichmentRouters(
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			redisCalls++
			result.Enrichment = map[string]any{"source": "redis"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mongodbCalls++
			result.Enrichment = map[string]any{"source": "mongodb"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			postgresqlCalls++
			result.Enrichment = map[string]any{"source": "postgresql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			mysqlCalls++
			result.Enrichment = map[string]any{"source": "mysql"}
			return result
		},
		func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
			elasticsearchCalls++
			result.Enrichment = map[string]any{"source": "elasticsearch"}
			return result
		},
	)
	defer restore()

	got := enrichResult(context.Background(), core.SecurityResult{
		Service: "elasticsearch",
	}, CredentialProbeOptions{})

	if elasticsearchCalls != 1 {
		t.Fatalf("expected elasticsearch enricher to be called once, got %d", elasticsearchCalls)
	}
	if redisCalls != 0 || mongodbCalls != 0 || postgresqlCalls != 0 || mysqlCalls != 0 {
		t.Fatalf("expected other enrichers to stay idle, got redis=%d mongodb=%d postgresql=%d mysql=%d", redisCalls, mongodbCalls, postgresqlCalls, mysqlCalls)
	}
	if !reflect.DeepEqual(got.Enrichment, map[string]any{"source": "elasticsearch"}) {
		t.Fatalf("expected elasticsearch enrichment payload, got %+v", got)
	}
}

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
		result.Enrichment = map[string]any{"payload": "SELECT version();\n\nPostgreSQL 16.2"}
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
	})

	if got.Results[0].Enrichment == nil {
		t.Fatalf("expected enrichment payload, got %+v", got.Results[0])
	}
	if !reflect.DeepEqual(got.Results[0].Enrichment, map[string]any{"payload": "SELECT version();\n\nPostgreSQL 16.2"}) {
		t.Fatalf("expected postgresql enrichment payload, got %+v", got.Results[0])
	}
}

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

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
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

func TestRunWithRegistrySkipsEnrichmentWhenDisabled(t *testing.T) {
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

	calls := 0
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		calls++
		result.Enrichment = map[string]any{"info_excerpt": "should not run"}
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
	})

	if calls != 0 {
		t.Fatalf("expected enrichment runner to stay idle when disabled, got %d calls", calls)
	}
	if got.Results[0].Enrichment != nil {
		t.Fatalf("expected no enrichment payload when disabled, got %+v", got.Results[0])
	}
}

func TestRunWithRegistrySkipsEnrichmentForFailedResult(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&stubKindedProber{
		name:    "redis-unauth",
		kind:    ProbeKindUnauthorized,
		service: "redis",
		result: SecurityResult{
			Service:     "redis",
			ProbeKind:   ProbeKindUnauthorized,
			FindingType: FindingTypeUnauthorizedAccess,
			Error:       "dial failed",
		},
	})

	calls := 0
	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		calls++
		result.Enrichment = map[string]any{"info_excerpt": "should not run"}
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

	if calls != 0 {
		t.Fatalf("expected enrichment runner to skip failed result, got %d calls", calls)
	}
	if got.Results[0].Enrichment != nil {
		t.Fatalf("expected failed result to stay unenriched, got %+v", got.Results[0])
	}
}

func TestRunWithRegistryKeepsFindingSemanticsWhenEnrichmentReturnsError(t *testing.T) {
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

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"error": "enrichment failed"}
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

	item := got.Results[0]
	if !item.Success {
		t.Fatalf("expected finding success to remain true, got %+v", item)
	}
	if item.ProbeKind != ProbeKindUnauthorized {
		t.Fatalf("expected probe kind to remain unauthorized, got %+v", item)
	}
	if item.FindingType != FindingTypeUnauthorizedAccess {
		t.Fatalf("expected finding type to remain unauthorized-access, got %+v", item)
	}
	if !reflect.DeepEqual(item.Enrichment, map[string]any{"error": "enrichment failed"}) {
		t.Fatalf("expected non-fatal enrichment error payload, got %+v", item)
	}
}

func TestApplyEnrichmentReturnsCopy(t *testing.T) {
	original := []core.SecurityResult{{
		Service:     "redis",
		ProbeKind:   ProbeKindUnauthorized,
		FindingType: FindingTypeUnauthorizedAccess,
		Success:     true,
	}}

	restore := stubEnrichmentRunner(func(_ context.Context, result core.SecurityResult, _ CredentialProbeOptions) core.SecurityResult {
		result.Enrichment = map[string]any{"info_excerpt": "copied"}
		return result
	})
	defer restore()

	got := applyEnrichment(context.Background(), original, CredentialProbeOptions{
		EnableEnrichment: true,
	})

	if original[0].Enrichment != nil {
		t.Fatalf("expected original slice to remain untouched, got %+v", original[0])
	}
	if !reflect.DeepEqual(got[0].Enrichment, map[string]any{"info_excerpt": "copied"}) {
		t.Fatalf("expected copied slice to contain enrichment, got %+v", got[0])
	}
}

func stubEnrichmentRunner(fn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult) func() {
	old := runEnrichment
	runEnrichment = fn
	return func() { runEnrichment = old }
}

func stubEnrichmentRouters(
	redisFn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	mongodbFn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	postgresqlFn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	mysqlFn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
	elasticsearchFn func(context.Context, core.SecurityResult, CredentialProbeOptions) core.SecurityResult,
) func() {
	oldRedis := enrichRedisResult
	oldMongoDB := enrichMongoDBResult
	oldPostgreSQL := enrichPostgreSQLResult
	oldMySQL := enrichMySQLResult
	oldElasticsearch := enrichElasticsearchResult
	enrichRedisResult = redisFn
	enrichMongoDBResult = mongodbFn
	enrichPostgreSQLResult = postgresqlFn
	enrichMySQLResult = mysqlFn
	enrichElasticsearchResult = elasticsearchFn
	return func() {
		enrichRedisResult = oldRedis
		enrichMongoDBResult = oldMongoDB
		enrichPostgreSQLResult = oldPostgreSQL
		enrichMySQLResult = oldMySQL
		enrichElasticsearchResult = oldElasticsearch
	}
}
