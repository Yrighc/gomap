package hostdiscovery

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxTCPConnectDiscoveryConcurrency = 8

var tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, network, address)
}

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
			result, err := raceTCPConnectPorts(ctx, ip, opts.Ports, timeout)
			if err != nil {
				return Result{}, err
			}
			if result.Matched {
				return result, nil
			}
		}
		return Result{}, nil
	})
}

func raceTCPConnectPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) (Result, error) {
	if len(ports) == 0 {
		return Result{}, nil
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := len(ports)
	if concurrency > maxTCPConnectDiscoveryConcurrency {
		concurrency = maxTCPConnectDiscoveryConcurrency
	}
	jobs := make(chan int, len(ports))
	matched := make(chan struct{}, 1)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-raceCtx.Done():
					return
				default:
				}
				address := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := tcpConnectDialContext(raceCtx, "tcp", address, timeout)
				if err != nil {
					continue
				}
				_ = conn.Close()
				select {
				case matched <- struct{}{}:
					cancel()
				default:
				}
				return
			}
		}()
	}

	for _, port := range ports {
		jobs <- port
	}
	close(jobs)
	wg.Wait()

	select {
	case <-matched:
		return Result{Matched: true, Method: "tcp-connect"}, nil
	default:
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	return Result{}, nil
}
