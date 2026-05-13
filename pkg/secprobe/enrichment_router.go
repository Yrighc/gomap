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
