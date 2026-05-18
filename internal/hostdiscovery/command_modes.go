package hostdiscovery

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
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
		for _, port := range opts.Ports {
			args := append([]string{}, baseArgs...)
			args = append(args, "-c", "1", "-p", strconv.Itoa(port), ip)
			out, err := execCommandContext(ctx, "nping", args...).CombinedOutput()
			if err == nil && strings.Contains(string(out), "RCVD") {
				return Result{Matched: true, Method: method}, nil
			}
		}
		return Result{}, nil
	})
}

func newARPRunner(_ Options) Runner {
	return RunnerFunc(func(ctx context.Context, ip string) (Result, error) {
		if _, err := execLookPath("arping"); err != nil {
			return Result{}, ErrModeUnavailable
		}
		out, err := execCommandContext(ctx, "arping", "-c", "1", ip).CombinedOutput()
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
