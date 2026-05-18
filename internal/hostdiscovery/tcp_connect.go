package hostdiscovery

import (
	"context"
	"net"
	"strconv"
	"time"
)

func newTCPConnectRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		retries := opts.Retries
		if retries <= 0 {
			retries = 1
		}
		for attempt := 0; attempt < retries; attempt++ {
			for _, port := range opts.Ports {
				address := net.JoinHostPort(ip, strconv.Itoa(port))
				dialer := net.Dialer{Timeout: timeout}
				conn, err := dialer.DialContext(ctx, "tcp", address)
				if err == nil {
					conn.Close()
					return Result{Matched: true, Method: "tcp-connect"}, nil
				}
			}
		}
		return Result{}, nil
	})
}
