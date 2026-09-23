//go:build unix

package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func wrappedDialErr(errno error) error {
	return &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: errno},
	}
}

func TestTCPConnectUnavailablePortPlusUsableNoSignalReturnsNormalNoMatch(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })
	tcpConnectDialContext = func(_ context.Context, _, address string, _ time.Duration) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
		if port == 80 {
			return nil, wrappedDialErr(unix.EACCES)
		}
		return nil, timeoutDialError{}
	}

	result, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80, 443}}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("expected usable no-signal port to keep the mode usable, got %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
}

func TestTCPConnectFailedPortPlusUsableNoSignalReturnsUnconfirmed(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })
	tcpConnectDialContext = func(_ context.Context, _, address string, _ time.Duration) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if port == "80" {
			return nil, wrappedDialErr(unix.ENETUNREACH)
		}
		return nil, timeoutDialError{}
	}
	result, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80, 443}}).Run(context.Background(), "127.0.0.1")
	if err != nil || result.Matched {
		t.Fatalf("expected effective no-signal port to keep target unconfirmed: result=%+v err=%v", result, err)
	}
}

func TestTCPConnectUnixEAGAINIsProbeFailureBeforeGenericTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct errno", err: unix.EAGAIN},
		{name: "syscall wrapper", err: &os.SyscallError{Syscall: "connect", Err: unix.EAGAIN}},
		{name: "network operation wrapper", err: wrappedDialErr(unix.EAGAIN)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tcpConnectDialContext
			t.Cleanup(func() { tcpConnectDialContext = original })
			tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				return nil, tt.err
			}

			_, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80}}).Run(context.Background(), "127.0.0.1")
			if !errors.Is(err, ErrProbeFailed) {
				t.Fatalf("expected EAGAIN to remain a probe failure, got %v", err)
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("expected original error to be retained, got %v", err)
			}
		})
	}
}

func TestTCPConnectUnixErrorClassification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantMatch bool
		wantErrIs error
	}{
		{name: "connection refused is alive", err: wrappedDialErr(unix.ECONNREFUSED), wantMatch: true},
		{name: "host unreachable is no signal", err: wrappedDialErr(unix.EHOSTUNREACH)},
		{name: "network unreachable is local failure", err: wrappedDialErr(unix.ENETUNREACH), wantErrIs: ErrProbeFailed},
		{name: "connection reset is no signal", err: wrappedDialErr(unix.ECONNRESET)},
		{name: "permission denied is unavailable", err: wrappedDialErr(unix.EACCES), wantErrIs: ErrModeUnavailable},
		{name: "address family unsupported is unavailable", err: wrappedDialErr(unix.EAFNOSUPPORT), wantErrIs: ErrModeUnavailable},
		{name: "file descriptors exhausted is failure", err: wrappedDialErr(unix.EMFILE), wantErrIs: ErrProbeFailed},
		{name: "buffers exhausted is failure", err: wrappedDialErr(unix.ENOBUFS), wantErrIs: ErrProbeFailed},
		{name: "address unavailable is failure", err: wrappedDialErr(unix.EADDRNOTAVAIL), wantErrIs: ErrProbeFailed},
		{name: "unknown error is failure", err: errors.New("unexpected dial failure"), wantErrIs: ErrProbeFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tcpConnectDialContext
			t.Cleanup(func() { tcpConnectDialContext = original })
			tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
				return nil, tt.err
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
			if !errors.Is(err, tt.err) {
				t.Fatalf("expected original error to be retained, got %v", err)
			}
		})
	}
}
