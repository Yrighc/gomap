package hostdiscovery

import (
	"context"
	"time"
)

type Options struct {
	Modes   []string
	Timeout time.Duration
	Retries int
	Ports   []int
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
