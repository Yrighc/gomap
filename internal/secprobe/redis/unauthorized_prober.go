package redis

import (
	"context"
	"net"
	"strconv"
	"strings"

	gredis "github.com/redis/go-redis/v9"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

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
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		return result
	}

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	client := gredis.NewClient(&gredis.Options{
		Addr:         addr,
		DialTimeout:  opts.Timeout,
		ReadTimeout:  opts.Timeout,
		WriteTimeout: opts.Timeout,
	})
	defer func() { _ = client.Close() }()

	infoCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	info, err := client.Info(infoCtx, "server").Result()
	cancel()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	if strings.Contains(info, "redis_version:") {
		result.Evidence = "INFO returned redis_version without authentication"
		return result
	}
	result.Evidence = "INFO succeeded without authentication"
	return result
}
