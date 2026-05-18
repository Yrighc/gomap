package hostdiscovery

import (
	"context"
	"time"

	"github.com/yrighc/gomap/internal/achieve"
)

func newICMPEchoRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resultCh := make(chan bool, 1)
		go func() {
			resultCh <- achieve.PingHost(ip)
		}()

		select {
		case <-pingCtx.Done():
			return Result{}, pingCtx.Err()
		case ok := <-resultCh:
			if !ok {
				return Result{}, nil
			}
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
	})
}
