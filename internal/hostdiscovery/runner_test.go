package hostdiscovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunStopsOnFirstMatchedMode(t *testing.T) {
	orig := modeFactories
	t.Cleanup(func() { modeFactories = orig })

	modeFactories = map[string]func(Options) Runner{
		"first": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, nil
			})
		},
		"second": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{Matched: true, Method: "second"}, nil
			})
		},
	}

	result, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"first", "second"},
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "second" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunReturnsErrorWhenAllModesUnavailable(t *testing.T) {
	orig := modeFactories
	t.Cleanup(func() { modeFactories = orig })

	modeFactories = map[string]func(Options) Runner{
		"icmp-echo": func(Options) Runner {
			return RunnerFunc(func(context.Context, string) (Result, error) {
				return Result{}, ErrModeUnavailable
			})
		},
	}

	_, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"icmp-echo"},
		Timeout: time.Second,
	})
	if !errors.Is(err, ErrNoUsableModes) {
		t.Fatalf("expected ErrNoUsableModes, got %v", err)
	}
}
