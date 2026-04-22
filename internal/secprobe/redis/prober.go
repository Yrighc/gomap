package redis

import (
	"context"
	"net"
	"strconv"
	"strings"

	gredis "github.com/redis/go-redis/v9"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "redis" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "redis"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyRedisCredentialFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
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
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifyRedisCredentialFailure(err)
		if result.FailureReason == core.FailureReasonCanceled || result.FailureReason == core.FailureReasonTimeout {
			if successFound {
				return successResult
			}
			return result
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func classifyRedisCredentialFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "wrongpass"), strings.Contains(text, "noauth"), strings.Contains(text, "authentication"), strings.Contains(text, "password"), strings.Contains(text, "user is disabled"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}
