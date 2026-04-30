package redis

import (
	"context"
	"net"
	"strconv"
	"time"

	gredis "github.com/redis/go-redis/v9"

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
			ErrorCode:   result.ErrorCode(classifyRedisCredentialFailure(err)),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Redis authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func pingWithAuth(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	timeout := timeoutFromContext(ctx)
	client := gredis.NewClient(&gredis.Options{
		Addr:         net.JoinHostPort(target.IP, strconv.Itoa(target.Port)),
		Username:     cred.Username,
		Password:     cred.Password,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	})
	defer func() { _ = client.Close() }()
	return client.Ping(ctx).Err()
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}
