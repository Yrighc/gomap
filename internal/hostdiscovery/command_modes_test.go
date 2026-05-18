package hostdiscovery

import (
	"context"
	"errors"
	"os/exec"
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
