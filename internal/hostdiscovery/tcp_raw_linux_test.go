//go:build linux

package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxNativeTCPOpenWithoutRouteIsProbeFailure(t *testing.T) {
	original := dialLinuxNativeTCP
	t.Cleanup(func() { dialLinuxNativeTCP = original })
	dialLinuxNativeTCP = func(context.Context, string) (net.Conn, error) {
		return nil, unix.ENETUNREACH
	}
	_, err := openLinuxNativeTCPSession(context.Background(), net.IPv4(192, 0, 2, 10), time.Second)
	if !errors.Is(err, ErrProbeFailed) || !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("expected route failure with original cause, got %v", err)
	}
}

func TestLinuxNativeTCPOpenHostUnreachableIsProbeFailure(t *testing.T) {
	original := dialLinuxNativeTCP
	t.Cleanup(func() { dialLinuxNativeTCP = original })
	dialLinuxNativeTCP = func(context.Context, string) (net.Conn, error) {
		return nil, unix.EHOSTUNREACH
	}
	_, err := openLinuxNativeTCPSession(context.Background(), net.IPv4(192, 0, 2, 10), time.Second)
	if !errors.Is(err, ErrProbeFailed) || !errors.Is(err, unix.EHOSTUNREACH) {
		t.Fatalf("expected unsent probe to fail with original cause, got %v", err)
	}
}

func TestOpenLinuxNativeTCPSessionPreservesCallerCancellation(t *testing.T) {
	original := dialLinuxNativeTCP
	t.Cleanup(func() { dialLinuxNativeTCP = original })
	ctx, cancel := context.WithCancel(context.Background())
	dialLinuxNativeTCP = func(dialCtx context.Context, _ string) (net.Conn, error) {
		cancel()
		<-dialCtx.Done()
		return nil, dialCtx.Err()
	}
	_, err := openLinuxNativeTCPSession(ctx, net.IPv4(192, 0, 2, 10), time.Second)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected original caller cancellation, got %v", err)
	}
}

func TestOpenLinuxNativeTCPSessionClassifiesOwnPreparationTimeout(t *testing.T) {
	original := dialLinuxNativeTCP
	t.Cleanup(func() { dialLinuxNativeTCP = original })
	dialLinuxNativeTCP = func(dialCtx context.Context, _ string) (net.Conn, error) {
		<-dialCtx.Done()
		return nil, dialCtx.Err()
	}
	_, err := openLinuxNativeTCPSession(context.Background(), net.IPv4(192, 0, 2, 10), time.Millisecond)
	if !errors.Is(err, ErrProbeFailed) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected local preparation failure, got %v", err)
	}
}
