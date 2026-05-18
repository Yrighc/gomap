package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestICMPEchoTimeoutReturnsNoSignal(t *testing.T) {
	origCommand := pingCommandContext
	t.Cleanup(func() { pingCommandContext = origCommand })

	pingCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "1")
	}

	result, err := newICMPEchoRunner(Options{
		Timeout: 10 * time.Millisecond,
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("expected timeout to be treated as no-signal, got error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no matched result, got %+v", result)
	}
}

func TestICMPEchoParentContextCancelReturnsError(t *testing.T) {
	origCommand := pingCommandContext
	t.Cleanup(func() { pingCommandContext = origCommand })

	pingCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "1")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newICMPEchoRunner(Options{
		Timeout: time.Second,
	}).Run(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
