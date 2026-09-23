//go:build !linux

package hostdiscovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedNativeModesExplainPlatform(t *testing.T) {
	tests := []struct {
		name   string
		runner Runner
	}{
		{name: "tcp-syn", runner: newTCPSYNRunner(Options{Timeout: time.Second, Ports: []int{80}})},
		{name: "tcp-ack", runner: newTCPACKRunner(Options{Timeout: time.Second, Ports: []int{80}})},
		{name: "arp", runner: newARPRunner(Options{Timeout: time.Second})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.runner.Run(context.Background(), "127.0.0.1")
			if !errors.Is(err, ErrModeUnavailable) {
				t.Fatalf("expected ErrModeUnavailable, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.name) || !strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("expected platform diagnostic, got %v", err)
			}
		})
	}
}

func TestUnsupportedNativeModesAloneReturnNoUsableModes(t *testing.T) {
	_, err := Run(context.Background(), "127.0.0.1", Options{
		Modes:   []string{"tcp-syn", "tcp-ack", "arp"},
		Ports:   []int{80},
		Timeout: time.Second,
	})
	if !errors.Is(err, ErrNoUsableModes) {
		t.Fatalf("expected ErrNoUsableModes, got %v", err)
	}
	for _, mode := range []string{"tcp-syn", "tcp-ack", "arp"} {
		if !strings.Contains(err.Error(), mode) {
			t.Fatalf("expected %s reason in error: %v", mode, err)
		}
	}
}
