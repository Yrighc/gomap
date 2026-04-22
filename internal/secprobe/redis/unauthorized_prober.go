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
		result.FailureReason = classifyRedisUnauthorizedFailure(err)
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

	result.Stage = core.StageAttempted

	pingCtx, pingCancel := context.WithTimeout(ctx, opts.Timeout)
	pong, err := client.Ping(pingCtx).Result()
	pingCancel()
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyRedisUnauthorizedFailure(err)
		return result
	}
	if pong != "PONG" {
		result.Error = "redis ping returned unexpected response"
		result.FailureReason = core.FailureReasonInsufficientConfirmation
		return result
	}

	infoCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	info, err := client.Info(infoCtx, "server").Result()
	cancel()
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyRedisUnauthorizedFailure(err)
		return result
	}

	if strings.Contains(info, "redis_version:") {
		result.Success = true
		result.Stage = core.StageConfirmed
		result.Capabilities = []core.Capability{core.CapabilityEnumerable, core.CapabilityReadable}
		result.Evidence = "INFO returned redis_version without authentication"
		return result
	}

	result.Error = "INFO server response missing redis_version"
	result.FailureReason = core.FailureReasonInsufficientConfirmation
	return result
}

func classifyRedisUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if errors := ctxFailureReason(err); errors != "" {
		return errors
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "noauth"), strings.Contains(text, "wrongpass"), strings.Contains(text, "authentication"), strings.Contains(text, "password"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errorsIsContextCanceled(err), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errorsIsDeadlineExceeded(err), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}

func errorsIsContextCanceled(err error) bool {
	return err == context.Canceled || strings.Contains(strings.ToLower(err.Error()), context.Canceled.Error())
}

func errorsIsDeadlineExceeded(err error) bool {
	return err == context.DeadlineExceeded || strings.Contains(strings.ToLower(err.Error()), context.DeadlineExceeded.Error())
}
