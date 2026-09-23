package hostdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const maxTCPConnectDiscoveryConcurrency = 8

type tcpConnectErrorClass uint8

const (
	tcpConnectNoSignal tcpConnectErrorClass = iota
	tcpConnectMatched
	tcpConnectUnavailable
	tcpConnectFailed
)

type tcpConnectJob struct {
	index int
	port  int
}

type tcpConnectOutcome struct {
	index    int
	matched  bool
	noSignal bool
	err      error
}

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
		return raceTCPConnectPorts(ctx, ip, opts.Ports, timeout)
	})
}

func raceTCPConnectPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(ports) == 0 {
		return Result{}, fmt.Errorf("%w: tcp-connect requires at least one port", ErrInvalidOptions)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := min(len(ports), maxTCPConnectDiscoveryConcurrency)
	jobs := make(chan tcpConnectJob)
	outcomes := make(chan tcpConnectOutcome, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if runCtx.Err() != nil {
					return
				}
				var job tcpConnectJob
				var ok bool
				select {
				case <-runCtx.Done():
					return
				case job, ok = <-jobs:
					if !ok {
						return
					}
				}
				if runCtx.Err() != nil {
					return
				}

				address := net.JoinHostPort(ip, strconv.Itoa(job.port))
				if runCtx.Err() != nil {
					return
				}
				conn, err := tcpConnectDialContext(runCtx, "tcp", address, timeout)
				if conn != nil {
					_ = conn.Close()
				}
				if ctx.Err() != nil {
					return
				}

				classification := classifyTCPConnectError(err)
				switch classification {
				case tcpConnectNoSignal:
					outcomes <- tcpConnectOutcome{index: job.index, noSignal: true}
				case tcpConnectMatched:
					outcomes <- tcpConnectOutcome{index: job.index, matched: true}
					cancel()
					return
				case tcpConnectUnavailable:
					outcomes <- tcpConnectOutcome{
						index: job.index,
						err: fmt.Errorf(
							"%w: tcp-connect port %d: %w",
							ErrModeUnavailable,
							job.port,
							err,
						),
					}
				case tcpConnectFailed:
					outcomes <- tcpConnectOutcome{
						index: job.index,
						err: fmt.Errorf(
							"%w: tcp-connect port %d: %w",
							ErrProbeFailed,
							job.port,
							err,
						),
					}
				}
			}
		}()
	}

	// A first match cancels in-flight dials; wait for all workers before reading
	// outcomes so their cleanup completes while error aggregation stays ordered.
sendJobs:
	for index, port := range ports {
		if runCtx.Err() != nil {
			break
		}
		select {
		case <-runCtx.Done():
			break sendJobs
		case jobs <- tcpConnectJob{index: index, port: port}:
		}
	}
	close(jobs)
	wg.Wait()
	close(outcomes)

	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	ordered := make([]tcpConnectOutcome, len(ports))
	seen := make([]bool, len(ports))
	matched := false
	for outcome := range outcomes {
		ordered[outcome.index] = outcome
		seen[outcome.index] = true
		matched = matched || outcome.matched
	}
	if matched {
		return Result{Matched: true, Method: "tcp-connect"}, nil
	}

	var issues []error
	failed := false
	unavailable := false
	usableNoSignal := false
	for index := range ordered {
		if !seen[index] {
			continue
		}
		usableNoSignal = usableNoSignal || ordered[index].noSignal
		if ordered[index].err == nil {
			continue
		}
		issues = append(issues, ordered[index].err)
		failed = failed || errors.Is(ordered[index].err, ErrProbeFailed)
		unavailable = unavailable || errors.Is(ordered[index].err, ErrModeUnavailable)
	}
	if usableNoSignal {
		return Result{}, nil
	}
	if failed {
		return Result{}, errors.Join(issues...)
	}
	if unavailable {
		return Result{}, errors.Join(issues...)
	}
	return Result{}, nil
}

func classifyTCPConnectError(err error) tcpConnectErrorClass {
	if err == nil {
		return tcpConnectMatched
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return tcpConnectNoSignal
	}
	// Explicit platform errno values take precedence: EAGAIN/EWOULDBLOCK can
	// report Timeout yet indicate local resource exhaustion rather than silence.
	if classification, recognized := classifyPlatformTCPConnectError(err); recognized {
		return classification
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return tcpConnectNoSignal
	}
	return tcpConnectFailed
}
