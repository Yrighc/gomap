package hostdiscovery

import (
	"context"
	"time"
)

type Options struct {
	// Modes is an explicit, ordered probe list. Empty selects the internal
	// target-aware automatic policy.
	Modes []string
	// Timeout limits one ICMP/ARP round or one TCP port attempt.
	Timeout time.Duration
	// Retries is the maximum total number of normally completed no-signal rounds per explicit mode or automatic policy round.
	Retries int
	// Ports contains the TCP-family ports attempted in each round.
	Ports []int
}

type Result struct {
	Matched bool
	Method  string
}

type Runner interface {
	Run(ctx context.Context, ip string) (Result, error)
}

type RunnerFunc func(ctx context.Context, ip string) (Result, error)

func (f RunnerFunc) Run(ctx context.Context, ip string) (Result, error) {
	return f(ctx, ip)
}
