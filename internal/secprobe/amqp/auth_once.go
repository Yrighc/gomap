package amqp

import (
	"context"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyAMQPFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "AMQP authentication succeeded and channel opened",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	client, err := dialAMQP(ctx, buildAMQPURL(core.SecurityCandidate{
		Target:     target.Host,
		ResolvedIP: target.IP,
		Port:       target.Port,
		Service:    target.Protocol,
	}, core.Credential{
		Username: cred.Username,
		Password: cred.Password,
	}), amqpConfig{timeout: timeoutFromContext(ctx)})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	channel, err := client.Channel()
	closeAMQPChannel(channel)
	return err
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
