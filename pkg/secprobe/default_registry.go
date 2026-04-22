package secprobe

import (
	"context"

	"github.com/yrighc/gomap/internal/secprobe/core"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	RegisterDefaultProbers(r)
	return r
}

func enrichResult(ctx context.Context, result core.SecurityResult, opts CredentialProbeOptions) core.SecurityResult {
	switch result.Service {
	case "redis":
		return redisprobe.Enrich(ctx, result, opts)
	case "mongodb":
		return mongodbprobe.Enrich(ctx, result, opts)
	default:
		return result
	}
}
