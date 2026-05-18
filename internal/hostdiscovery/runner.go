package hostdiscovery

import (
	"context"
	"errors"
)

var modeFactories = map[string]func(Options) Runner{
	"tcp-connect": newTCPConnectRunner,
	"icmp-echo":   newICMPEchoRunner,
	"tcp-syn":     newTCPSYNRunner,
	"tcp-ack":     newTCPACKRunner,
	"arp":         newARPRunner,
}

func Run(ctx context.Context, ip string, opts Options) (Result, error) {
	usable := 0
	for _, mode := range opts.Modes {
		factory, ok := modeFactories[mode]
		if !ok {
			continue
		}
		result, err := factory(opts).Run(ctx, ip)
		if err != nil {
			if errors.Is(err, ErrModeUnavailable) {
				continue
			}
			return Result{}, err
		}
		usable++
		if result.Matched {
			return result, nil
		}
	}
	if usable == 0 {
		return Result{}, ErrNoUsableModes
	}
	return Result{}, nil
}

func unavailableRunner() Runner {
	return RunnerFunc(func(context.Context, string) (Result, error) {
		return Result{}, ErrModeUnavailable
	})
}
