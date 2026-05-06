package rdp

import (
	"context"

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
			ErrorCode:   result.ErrorCode(classifyRDPFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "RDP authentication succeeded",
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
	opts := core.CredentialProbeOptions{}

	attempts, err := transportAttempts(ctx, candidate, opts)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		err = loginRDP(ctx, candidate, credential, opts, attempt)
		if err == nil {
			return nil
		}
		if isTerminalContextError(err) {
			return err
		}
		if shouldTryNextTransport(classifyRDPFailure(err)) {
			continue
		}
		return err
	}
	return context.DeadlineExceeded
}
