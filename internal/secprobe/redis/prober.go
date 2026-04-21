package redis

import (
	"context"
	"net"
	"strconv"

	gredis "github.com/redis/go-redis/v9"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "redis" }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "redis"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			return result
		}

		client := gredis.NewClient(&gredis.Options{
			Addr:         addr,
			Username:     cred.Username,
			Password:     cred.Password,
			DialTimeout:  opts.Timeout,
			ReadTimeout:  opts.Timeout,
			WriteTimeout: opts.Timeout,
		})

		pingCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		err := client.Ping(pingCtx).Err()
		cancel()
		_ = client.Close()
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "Redis authentication succeeded"
			successResult.Error = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
	}

	if successFound {
		return successResult
	}
	return result
}
