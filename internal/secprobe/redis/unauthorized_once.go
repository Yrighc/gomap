package redis

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	gredis "github.com/redis/go-redis/v9"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type UnauthorizedChecker struct {
	ping func(context.Context, strategy.Target) error
}

func NewUnauthorizedChecker(ping func(context.Context, strategy.Target) error) UnauthorizedChecker {
	if ping == nil {
		ping = pingWithoutAuth
	}
	return UnauthorizedChecker{ping: ping}
}

func (c UnauthorizedChecker) CheckUnauthorizedOnce(ctx context.Context, target strategy.Target) registrybridge.Attempt {
	if err := c.ping(ctx, target); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   result.ErrorCode(classifyRedisUnauthorizedFailure(err)),
			FindingType: result.FindingTypeUnauthorizedAccess,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Evidence:    "INFO returned redis_version without authentication",
		FindingType: result.FindingTypeUnauthorizedAccess,
	}}
}

func pingWithoutAuth(ctx context.Context, target strategy.Target) error {
	timeout := timeoutFromContext(ctx)
	client := gredis.NewClient(&gredis.Options{
		Addr:         net.JoinHostPort(target.IP, strconv.Itoa(target.Port)),
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	})
	defer func() { _ = client.Close() }()

	pong, err := client.Ping(ctx).Result()
	if err != nil {
		return err
	}
	if pong != "PONG" {
		return errors.New("redis ping returned unexpected response")
	}
	info, err := client.Info(ctx, "server").Result()
	if err != nil {
		return err
	}
	if !strings.Contains(info, "redis_version:") {
		return errors.New("INFO server response missing redis_version")
	}
	return nil
}
