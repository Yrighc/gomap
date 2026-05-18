package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestTCPSYNModeReturnsUnavailableWhenNpingMissing(t *testing.T) {
	origLookPath := execLookPath
	t.Cleanup(func() { execLookPath = origLookPath })
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	_, err := newTCPSYNRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80},
	}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected ErrModeUnavailable, got %v", err)
	}
}

func TestTCPACKModeReturnsUnavailableWhenNpingMissing(t *testing.T) {
	origLookPath := execLookPath
	t.Cleanup(func() { execLookPath = origLookPath })
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	_, err := newTCPACKRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80},
	}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected ErrModeUnavailable, got %v", err)
	}
}

func TestARPModeReturnsUnavailableWhenArpingMissing(t *testing.T) {
	origLookPath := execLookPath
	t.Cleanup(func() { execLookPath = origLookPath })
	execLookPath = func(string) (string, error) { return "", exec.ErrNotFound }

	_, err := newARPRunner(Options{Timeout: time.Second}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrModeUnavailable) {
		t.Fatalf("expected ErrModeUnavailable, got %v", err)
	}
}

func TestTCPSYNModeAppliesTimeoutToCommandContext(t *testing.T) {
	origLookPath := execLookPath
	origCommand := execCommandContext
	t.Cleanup(func() {
		execLookPath = origLookPath
		execCommandContext = origCommand
	})

	execLookPath = func(string) (string, error) { return "/bin/echo", nil }
	var gotDeadline bool
	var gotArgs []string
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		_, gotDeadline = ctx.Deadline()
		gotArgs = append([]string{name}, args...)
		return exec.CommandContext(ctx, "printf", "RCVD")
	}

	result, err := newTCPSYNRunner(Options{
		Timeout: 50 * time.Millisecond,
		Ports:   []int{80},
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected matched result, got %+v", result)
	}
	if !gotDeadline {
		t.Fatal("expected command context to include a deadline")
	}
	wantArgs := []string{"nping", "--tcp", "-flags", "syn", "-c", "1", "-p", "80", "127.0.0.1"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("unexpected command args: got %v want %v", gotArgs, wantArgs)
	}
}
