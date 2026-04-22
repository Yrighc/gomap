package secprobe

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
)

var (
	enrichRedisResult   = redisprobe.Enrich
	enrichMongoDBResult = mongodbprobe.Enrich
)

func enrichResult(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	switch result.Service {
	case "redis":
		return enrichRedisResult(ctx, result, opts)
	case "mongodb":
		return enrichMongoDBResult(ctx, result, opts)
	default:
		return result
	}
}
