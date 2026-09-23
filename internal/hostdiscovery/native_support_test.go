package hostdiscovery

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUnsupportedNativeModeMatrixDoesNotOpenNetwork(t *testing.T) {
	tests := []struct {
		mode  string
		ip    string
		ports []int
		skip  bool
	}{
		{mode: "tcp-syn", ip: "::1", ports: []int{80}},
		{mode: "tcp-ack", ip: "::1", ports: []int{80}},
		{mode: "arp", ip: "::1"},
		{mode: "tcp-syn", ip: "127.0.0.1", ports: []int{80}, skip: runtime.GOOS == "linux"},
		{mode: "tcp-ack", ip: "127.0.0.1", ports: []int{80}, skip: runtime.GOOS == "linux"},
		{mode: "arp", ip: "127.0.0.1", skip: runtime.GOOS == "linux"},
		{mode: "icmp-echo", ip: "127.0.0.1", skip: runtime.GOOS == "linux" || runtime.GOOS == "darwin"},
		{mode: "icmp-echo", ip: "::1", skip: runtime.GOOS == "linux" || runtime.GOOS == "darwin"},
	}

	for _, tt := range tests {
		t.Run(tt.mode+"/"+tt.ip, func(t *testing.T) {
			if tt.skip {
				t.Skip("this platform implements the mode; protocol tests cover it without live network access")
			}
			_, err := modeFactories[tt.mode](Options{Timeout: time.Second, Ports: tt.ports}).Run(context.Background(), tt.ip)
			if !errors.Is(err, ErrModeUnavailable) {
				t.Fatalf("expected ErrModeUnavailable on %s, got %v", runtime.GOOS, err)
			}
			if strings.Contains(err.Error(), "paused") {
				t.Fatalf("stale paused-adapter reason: %v", err)
			}
		})
	}
}
