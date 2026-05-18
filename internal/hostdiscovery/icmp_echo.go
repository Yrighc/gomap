package hostdiscovery

import (
	"context"
	"net"
	"os/exec"
	"time"
)

var pingCommandContext = exec.CommandContext

func newICMPEchoRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		err := runPingCommand(pingCtx, ip)
		if err == nil {
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, nil
	})
}

func runPingCommand(ctx context.Context, host string) error {
	args := []string{"-c", "1", "-W", "3", host}
	name := "ping"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		if _, err := exec.LookPath("ping6"); err == nil {
			name = "ping6"
			args = []string{"-c", "1", "-w", "3", host}
		} else {
			args = []string{"-6", "-c", "1", "-W", "3", host}
		}
	}
	return pingCommandContext(ctx, name, args...).Run()
}
