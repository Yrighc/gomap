package oracle

import (
	"context"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	login func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(login func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if login == nil {
		login = loginOnce
	}
	return Authenticator{login: login}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.login(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyOracleFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Oracle authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func loginOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}
	credential := core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	}
	timeout := oracleAuthTimeout(ctx)
	opts := core.CredentialProbeOptions{Timeout: timeout}

	var lastErr error
	for _, dsn := range buildOracleDSNAttempts(candidate, credential, opts) {
		db, err := openOracle(ctx, dsn)
		if err != nil {
			lastErr = err
			if shouldStopOracleAttempts(ctx, classifyOracleFailure(err)) {
				return err
			}
			continue
		}

		pingCtx, cancel := context.WithTimeout(ctx, oraclePerAttemptTimeout(timeout, len(oracleServiceNames)))
		err = db.PingContext(pingCtx)
		cancel()
		_ = db.Close()
		if err == nil {
			return nil
		}
		lastErr = err
		if shouldStopOracleAttempts(ctx, classifyOracleFailure(err)) {
			return err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return context.DeadlineExceeded
}

func oracleAuthTimeout(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
