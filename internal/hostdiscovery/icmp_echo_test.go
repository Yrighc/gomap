//go:build linux || darwin

package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type fakeICMPRead struct {
	packet []byte
	addr   net.Addr
	err    error
}

type fakeICMPConn struct {
	mu        sync.Mutex
	local     net.Addr
	reads     chan fakeICMPRead
	closed    chan struct{}
	closeOnce sync.Once
	writes    int
	deadline  time.Time
	writeFn   func([]byte, net.Addr) (int, error)
}

func newFakeICMPConn(local net.Addr) *fakeICMPConn {
	return &fakeICMPConn{local: local, reads: make(chan fakeICMPRead, 8), closed: make(chan struct{})}
}

func (c *fakeICMPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case read := <-c.reads:
		n := copy(buffer, read.packet)
		return n, read.addr, read.err
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *fakeICMPConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes++
	fn := c.writeFn
	c.mu.Unlock()
	if fn != nil {
		return fn(packet, addr)
	}
	return len(packet), nil
}

func (c *fakeICMPConn) LocalAddr() net.Addr { return c.local }

func (c *fakeICMPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *fakeICMPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func installICMPSeams(t *testing.T) {
	t.Helper()
	originalListen := listenICMPPacket
	originalRandom := readICMPRandom
	originalGOOS := icmpGOOS
	t.Cleanup(func() {
		listenICMPPacket = originalListen
		readICMPRandom = originalRandom
		icmpGOOS = originalGOOS
	})
	readICMPRandom = func(buffer []byte) (int, error) {
		for i := range buffer {
			buffer[i] = byte(i + 1)
		}
		return len(buffer), nil
	}
}

func TestNativeICMPEchoMatchesReplyAndUsesLinuxSocketIdentifier(t *testing.T) {
	installICMPSeams(t)
	icmpGOOS = "linux"
	target := net.ParseIP("192.0.2.10")
	conn := newFakeICMPConn(&net.UDPAddr{IP: net.IPv4zero, Port: 4321})
	conn.writeFn = func(packet []byte, destination net.Addr) (int, error) {
		udpDestination, ok := destination.(*net.UDPAddr)
		if !ok || !udpDestination.IP.Equal(target) {
			t.Fatalf("unexpected destination: %#v", destination)
		}
		message, err := icmp.ParseMessage(1, packet)
		if err != nil {
			t.Fatal(err)
		}
		echo := message.Body.(*icmp.Echo)
		if echo.ID != 4321 {
			t.Fatalf("expected kernel ping socket ID 4321, got %d", echo.ID)
		}
		reply, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: append([]byte(nil), echo.Data...)}}).Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		conn.reads <- fakeICMPRead{packet: []byte{1, 2}, addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.11")}}
		conn.reads <- fakeICMPRead{packet: reply, addr: &net.UDPAddr{IP: target}}
		return len(packet), nil
	}
	listenICMPPacket = func(network, address string) (icmpPacketConn, error) {
		if network != "udp4" || address != "0.0.0.0" {
			t.Fatalf("unexpected listen: %s %s", network, address)
		}
		return conn, nil
	}

	result, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), target.String())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched || result.Method != "icmp-echo" {
		t.Fatalf("unexpected result: %#v", result)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("connection was not closed")
	}
}

func TestNativeICMPFallsBackOnlyForCapabilityFailure(t *testing.T) {
	installICMPSeams(t)
	calls := []string{}
	raw := newFakeICMPConn(&net.IPAddr{IP: net.IPv4zero})
	raw.writeFn = func(packet []byte, _ net.Addr) (int, error) {
		message, err := icmp.ParseMessage(1, packet)
		if err != nil {
			t.Fatal(err)
		}
		echo := message.Body.(*icmp.Echo)
		reply, _ := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data}}).Marshal(nil)
		raw.reads <- fakeICMPRead{packet: reply, addr: &net.IPAddr{IP: net.ParseIP("192.0.2.10")}}
		return len(packet), nil
	}
	listenICMPPacket = func(network, _ string) (icmpPacketConn, error) {
		calls = append(calls, network)
		if network == "udp4" {
			return nil, os.ErrPermission
		}
		return raw, nil
	}
	result, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if err != nil || !result.Matched {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(calls) != 2 || calls[0] != "udp4" || calls[1] != "ip4:icmp" {
		t.Fatalf("unexpected fallback sequence: %v", calls)
	}

	calls = nil
	listenICMPPacket = func(network, _ string) (icmpPacketConn, error) {
		calls = append(calls, network)
		return nil, syscall.EMFILE
	}
	_, err = newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if !errors.Is(err, ErrProbeFailed) || len(calls) != 1 {
		t.Fatalf("expected one resource failure without fallback, calls=%v err=%v", calls, err)
	}
}

func TestNativeICMPCancellationClosesInflightRead(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	wrote := make(chan struct{})
	conn.writeFn = func(packet []byte, _ net.Addr) (int, error) {
		close(wrote)
		return len(packet), nil
	}
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(ctx, "192.0.2.10")
		done <- err
	}()
	<-wrote
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock read")
	}
}

type nativeICMPTimeoutError struct{}

func (nativeICMPTimeoutError) Error() string   { return "timeout" }
func (nativeICMPTimeoutError) Timeout() bool   { return true }
func (nativeICMPTimeoutError) Temporary() bool { return true }

func TestNativeICMPWriteWithoutRouteIsProbeFailure(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	conn.writeFn = func([]byte, net.Addr) (int, error) { return 0, syscall.ENETUNREACH }
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }
	_, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if !errors.Is(err, ErrProbeFailed) || !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("expected local route failure with original cause, got %v", err)
	}
}

func TestNativeICMPWriteHostUnreachableIsProbeFailure(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	conn.writeFn = func([]byte, net.Addr) (int, error) { return 0, syscall.EHOSTUNREACH }
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }
	_, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if !errors.Is(err, ErrProbeFailed) || !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("expected unsent request to fail with original cause, got %v", err)
	}
}

func TestNativeICMPReadUnreachableRemainsNoSignal(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	conn.writeFn = func(packet []byte, _ net.Addr) (int, error) {
		conn.reads <- fakeICMPRead{err: syscall.ENETUNREACH}
		return len(packet), nil
	}
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }
	result, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if err != nil || result.Matched {
		t.Fatalf("read-side unreachable should remain no-signal: result=%+v err=%v", result, err)
	}
}

func TestNativeICMPTimeoutIsNormalNoSignal(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	conn.writeFn = func(packet []byte, _ net.Addr) (int, error) {
		conn.reads <- fakeICMPRead{err: nativeICMPTimeoutError{}}
		return len(packet), nil
	}
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }
	result, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if err != nil || result.Matched {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestNativeICMPRandomFailureDoesNotSend(t *testing.T) {
	installICMPSeams(t)
	conn := newFakeICMPConn(&net.UDPAddr{Port: 1234})
	listenICMPPacket = func(string, string) (icmpPacketConn, error) { return conn, nil }
	readICMPRandom = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	_, err := newICMPEchoRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if !errors.Is(err, ErrProbeFailed) || conn.writes != 0 {
		t.Fatalf("writes=%d err=%v", conn.writes, err)
	}
}

func TestNativeICMPRejectsLinkLocalIPv6WithoutOpeningSocket(t *testing.T) {
	installICMPSeams(t)
	called := false
	listenICMPPacket = func(string, string) (icmpPacketConn, error) {
		called = true
		return nil, errors.New("unexpected")
	}
	_, err := newICMPEchoRunner(Options{}).Run(context.Background(), "fe80::1")
	if !errors.Is(err, ErrModeUnavailable) || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestNativeICMPCanceledBeforeOpenDoesNotCreateSocket(t *testing.T) {
	installICMPSeams(t)
	called := false
	listenICMPPacket = func(string, string) (icmpPacketConn, error) {
		called = true
		return nil, errors.New("unexpected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newICMPEchoRunner(Options{}).Run(ctx, "192.0.2.10")
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}
