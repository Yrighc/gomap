package mssql

import (
	"context"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	ping func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(ping func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if ping == nil {
		ping = pingWithAuth
	}
	return Authenticator{ping: ping}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.ping(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyMSSQLFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "MSSQL authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func pingWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var lastErr error
	for _, dsn := range buildDSNAttempts(core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}, core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	}, core.CredentialProbeOptions{
		Timeout: timeoutFromContext(ctx),
	}) {
		db, err := openMSSQL(ctx, dsn)
		if err != nil {
			lastErr = err
			if shouldContinueDSNAttempts(classifyMSSQLFailure(err)) {
				continue
			}
			return err
		}

		pingCtx, cancel := pingContextFromParent(ctx)
		err = db.PingContext(pingCtx)
		cancel()
		_ = db.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		if shouldContinueDSNAttempts(classifyMSSQLFailure(err)) {
			continue
		}
		return err
	}
	if lastErr != nil {
		return lastErr
	}
	return context.DeadlineExceeded
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}

func pingContextFromParent(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := timeoutFromContext(ctx)
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}
