//go:build windows

package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTCPConnectWindowsErrorClassification(t *testing.T) {
	tests := []struct {
		name      string
		errno     windows.Errno
		wantMatch bool
		wantErrIs error
	}{
		{name: "connection refused is alive", errno: windows.WSAECONNREFUSED, wantMatch: true},
		{name: "host unreachable is no signal", errno: windows.WSAEHOSTUNREACH},
		{name: "network unreachable is local failure", errno: windows.WSAENETUNREACH, wantErrIs: ErrProbeFailed},
		{name: "connection reset is no signal", errno: windows.WSAECONNRESET},
		{name: "permission denied is unavailable", errno: windows.WSAEACCES, wantErrIs: ErrModeUnavailable},
		{name: "address family unsupported is unavailable", errno: windows.WSAEAFNOSUPPORT, wantErrIs: ErrModeUnavailable},
		{name: "buffers exhausted is failure", errno: windows.WSAENOBUFS, wantErrIs: ErrProbeFailed},
		{name: "address unavailable is failure", errno: windows.WSAEADDRNOTAVAIL, wantErrIs: ErrProbeFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tcpConnectDialContext
			t.Cleanup(func() { tcpConnectDialContext = original })
			tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: tt.errno}
			}

			result, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80}}).Run(context.Background(), "127.0.0.1")
			if result.Matched != tt.wantMatch {
				t.Fatalf("matched: want %v, got %+v", tt.wantMatch, result)
			}
			if tt.wantErrIs == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("expected %v, got %v", tt.wantErrIs, err)
			}
		})
	}
}
