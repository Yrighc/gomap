package hostdiscovery

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var execLookPath = exec.LookPath
var execCommandContext = exec.CommandContext

func newTCPSYNRunner(opts Options) Runner {
	return newNpingRunner("tcp-syn", []string{"--tcp", "-flags", "syn"}, opts)
}

func newTCPACKRunner(opts Options) Runner {
	return newNpingRunner("tcp-ack", []string{"--tcp", "-flags", "ack"}, opts)
}

func newNpingRunner(method string, baseArgs []string, opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		if _, err := execLookPath("nping"); err != nil {
			return Result{}, ErrModeUnavailable
		}
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		for _, port := range opts.Ports {
			args := append([]string{}, baseArgs...)
			args = append(args, "-c", "1", "-p", strconv.Itoa(port), ip)
			runCtx, cancel := context.WithTimeout(ctx, timeout)
			out, err := execCommandContext(runCtx, "nping", args...).CombinedOutput()
			cancel()
			if err == nil && strings.Contains(string(out), "RCVD") {
				return Result{Matched: true, Method: method}, nil
			}
		}
		return Result{}, nil
	})
}

func newARPRunner(opts Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		if _, err := execLookPath("arping"); err != nil {
			return Result{}, ErrModeUnavailable
		}
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = time.Second
		}
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		out, err := execCommandContext(runCtx, "arping", "-c", "1", ip).CombinedOutput()
		cancel()
		if err != nil {
			return Result{}, nil
		}
		response := strings.ToLower(string(out))
		if strings.Contains(response, "reply from") || strings.Contains(response, "bytes from") {
			return Result{Matched: true, Method: "arp"}, nil
		}
		return Result{}, nil
	})
}
