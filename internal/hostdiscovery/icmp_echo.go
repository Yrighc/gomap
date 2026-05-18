package hostdiscovery

import (
	"context"

	"github.com/yrighc/gomap/internal/achieve"
)

func newICMPEchoRunner(_ Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}
		if achieve.PingHost(ip) {
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
		return Result{}, nil
	})
}
