package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeNativeTCPSession struct {
	mu          sync.Mutex
	localIP     net.IP
	localPort   uint16
	sent        []tcpProbe
	sendFn      func(tcpProbe) error
	receiveFn   func(time.Time) (nativeTCPInbound, error)
	sendResetFn func(tcpProbe, tcpResponse, time.Time) error
	closed      chan struct{}
	closeOnce   sync.Once
	resets      int
}

func (s *fakeNativeTCPSession) LocalIP() net.IP   { return s.localIP }
func (s *fakeNativeTCPSession) LocalPort() uint16 { return s.localPort }
func (s *fakeNativeTCPSession) Send(probe tcpProbe) error {
	s.mu.Lock()
	s.sent = append(s.sent, probe)
	fn := s.sendFn
	s.mu.Unlock()
	if fn != nil {
		return fn(probe)
	}
	return nil
}
func (s *fakeNativeTCPSession) Receive(deadline time.Time) (nativeTCPInbound, error) {
	return s.receiveFn(deadline)
}
func (s *fakeNativeTCPSession) SendReset(probe tcpProbe, response tcpResponse, deadline time.Time) error {
	s.mu.Lock()
	s.resets++
	fn := s.sendResetFn
	s.mu.Unlock()
	if fn != nil {
		return fn(probe, response, deadline)
	}
	return nil
}
func (s *fakeNativeTCPSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func installTCPRandom(t *testing.T) {
	t.Helper()
	original := readTCPRandom
	counter := byte(1)
	readTCPRandom = func(buffer []byte) (int, error) {
		for i := range buffer {
			buffer[i] = counter
			counter++
		}
		return len(buffer), nil
	}
	t.Cleanup(func() { readTCPRandom = original })
}

func TestNativeTCPRunnerUsesEightPortWindowAndStopsOnMatch(t *testing.T) {
	installTCPRandom(t)
	target := net.ParseIP("192.0.2.10")
	local := net.ParseIP("192.0.2.1")
	session := &fakeNativeTCPSession{localIP: local, localPort: 41000, closed: make(chan struct{})}
	session.receiveFn = func(time.Time) (nativeTCPInbound, error) {
		session.mu.Lock()
		defer session.mu.Unlock()
		if len(session.sent) != maxNativeTCPInflight {
			t.Fatalf("received before window filled: %d", len(session.sent))
		}
		probe := session.sent[3]
		return nativeTCPInbound{
			sourceIP: target,
			targetIP: local,
			response: tcpResponse{
				sourcePort:      probe.remotePort,
				destinationPort: session.localPort,
				ack:             probe.seq + 1,
				flags:           tcpFlagSYN | tcpFlagACK,
			},
		}, nil
	}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	runner := newNativeTCPRunner("tcp-syn", Options{Ports: ports, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		return session, nil
	})
	result, err := runner.Run(context.Background(), target.String())
	if err != nil || !result.Matched || result.Method != "tcp-syn" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(session.sent) != 8 {
		t.Fatalf("sent %d probes after early match", len(session.sent))
	}
	if session.resets != 1 {
		t.Fatalf("expected one SYN cleanup RST, got %d", session.resets)
	}
}

type nativeTCPTimeoutError struct{}

func (nativeTCPTimeoutError) Error() string   { return "timeout" }
func (nativeTCPTimeoutError) Timeout() bool   { return true }
func (nativeTCPTimeoutError) Temporary() bool { return true }

func TestNativeTCPRunnerCancellationDuringSYNACKCleanupWins(t *testing.T) {
	installTCPRandom(t)
	target := net.ParseIP("192.0.2.10")
	local := net.ParseIP("192.0.2.1")
	ctx, cancel := context.WithCancel(context.Background())
	session := &fakeNativeTCPSession{localIP: local, localPort: 41000, closed: make(chan struct{})}
	session.receiveFn = func(time.Time) (nativeTCPInbound, error) {
		probe := session.sent[0]
		return nativeTCPInbound{sourceIP: target, targetIP: local, response: tcpResponse{
			sourcePort: probe.remotePort, destinationPort: 41000, ack: probe.seq + 1, flags: tcpFlagSYN | tcpFlagACK,
		}}, nil
	}
	session.sendResetFn = func(tcpProbe, tcpResponse, time.Time) error {
		cancel()
		return net.ErrClosed
	}
	runner := newNativeTCPRunner("tcp-syn", Options{Ports: []int{443}, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		return session, nil
	})
	result, err := runner.Run(ctx, target.String())
	if !errors.Is(err, context.Canceled) || result.Matched {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestNativeTCPRunnerReplenishesWindowAfterPerPortTimeout(t *testing.T) {
	installTCPRandom(t)
	current := time.Unix(100, 0)
	session := &fakeNativeTCPSession{localIP: net.ParseIP("192.0.2.1"), localPort: 41000, closed: make(chan struct{})}
	receiveCalls := 0
	session.receiveFn = func(deadline time.Time) (nativeTCPInbound, error) {
		receiveCalls++
		if receiveCalls == 1 && len(session.sent) != maxNativeTCPInflight {
			t.Fatalf("first window size=%d", len(session.sent))
		}
		current = deadline
		return nativeTCPInbound{}, nativeTCPTimeoutError{}
	}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	runner := &nativeTCPRunner{
		mode: "tcp-syn", opts: Options{Ports: ports, Timeout: time.Second},
		opener: func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) { return session, nil },
		now:    func() time.Time { return current },
	}
	result, err := runner.Run(context.Background(), "192.0.2.10")
	if err != nil || result.Matched {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(session.sent) != len(ports) || receiveCalls != 2 {
		t.Fatalf("sent=%d receiveCalls=%d", len(session.sent), receiveCalls)
	}
}

func TestNativeTCPRunnerACKMatchesBareRSTWithoutCleanup(t *testing.T) {
	installTCPRandom(t)
	target := net.ParseIP("192.0.2.10")
	local := net.ParseIP("192.0.2.1")
	session := &fakeNativeTCPSession{localIP: local, localPort: 41000, closed: make(chan struct{})}
	session.receiveFn = func(time.Time) (nativeTCPInbound, error) {
		probe := session.sent[0]
		return nativeTCPInbound{sourceIP: target, targetIP: local, response: tcpResponse{
			sourcePort: probe.remotePort, destinationPort: 41000, seq: probe.ack, flags: tcpFlagRST,
		}}, nil
	}
	runner := newNativeTCPRunner("tcp-ack", Options{Ports: []int{443}, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		return session, nil
	})
	result, err := runner.Run(context.Background(), target.String())
	if err != nil || !result.Matched || session.resets != 0 {
		t.Fatalf("result=%#v resets=%d err=%v", result, session.resets, err)
	}
}

func TestNativeTCPRunnerCancellationClosesReceive(t *testing.T) {
	installTCPRandom(t)
	local := net.ParseIP("192.0.2.1")
	session := &fakeNativeTCPSession{localIP: local, localPort: 41000, closed: make(chan struct{})}
	started := make(chan struct{})
	session.receiveFn = func(time.Time) (nativeTCPInbound, error) {
		close(started)
		<-session.closed
		return nativeTCPInbound{}, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		runner := newNativeTCPRunner("tcp-syn", Options{Ports: []int{443}, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
			return session, nil
		})
		_, err := runner.Run(ctx, "192.0.2.10")
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close receive")
	}
}

func TestNativeTCPRunnerTreatsUnsentPerPortUnreachableAsFailure(t *testing.T) {
	installTCPRandom(t)
	session := &fakeNativeTCPSession{
		localIP: net.ParseIP("192.0.2.1"), localPort: 41000, closed: make(chan struct{}),
		sendFn: func(tcpProbe) error { return syscall.ENETUNREACH },
	}
	runner := newNativeTCPRunner("tcp-syn", Options{Ports: []int{80, 443}, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		return session, nil
	})
	result, err := runner.Run(context.Background(), "192.0.2.10")
	if result.Matched || !errors.Is(err, ErrProbeFailed) || !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("expected unsent probe to fail with route cause: result=%#v err=%v", result, err)
	}
}

func TestNativeTCPRunnerTreatsUnsentHostUnreachableAsFailure(t *testing.T) {
	installTCPRandom(t)
	session := &fakeNativeTCPSession{
		localIP: net.ParseIP("192.0.2.1"), localPort: 41000, closed: make(chan struct{}),
		sendFn: func(tcpProbe) error { return syscall.EHOSTUNREACH },
	}
	runner := newNativeTCPRunner("tcp-syn", Options{Ports: []int{443}, Timeout: time.Second}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		return session, nil
	})
	result, err := runner.Run(context.Background(), "192.0.2.10")
	if result.Matched || !errors.Is(err, ErrProbeFailed) || !errors.Is(err, syscall.EHOSTUNREACH) {
		t.Fatalf("unsent probe must fail with original cause: result=%+v err=%v", result, err)
	}
}

func TestNativeTCPRunnerMixedUnsentFailureAndSilentSentPort(t *testing.T) {
	installTCPRandom(t)
	now := time.Unix(100, 0)
	session := &fakeNativeTCPSession{localIP: net.ParseIP("192.0.2.1"), localPort: 41000, closed: make(chan struct{})}
	session.sendFn = func(probe tcpProbe) error {
		if probe.remotePort == 80 {
			return syscall.ENETUNREACH
		}
		return nil
	}
	session.receiveFn = func(deadline time.Time) (nativeTCPInbound, error) {
		now = deadline
		return nativeTCPInbound{}, nativeTCPTimeoutError{}
	}
	runner := &nativeTCPRunner{
		mode: "tcp-syn", opts: Options{Ports: []int{80, 443}, Timeout: time.Second},
		opener: func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) { return session, nil },
		now:    func() time.Time { return now },
	}
	result, err := runner.Run(context.Background(), "192.0.2.10")
	if err != nil || result.Matched {
		t.Fatalf("expected effective silent port to keep target unconfirmed: result=%+v err=%v", result, err)
	}
}

func TestNativeTCPReceiveUnreachableRemainsNoSignal(t *testing.T) {
	for _, cause := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH} {
		t.Run(cause.Error(), func(t *testing.T) {
			installTCPRandom(t)
			now := time.Unix(100, 0)
			session := &fakeNativeTCPSession{localIP: net.ParseIP("192.0.2.1"), localPort: 41000, closed: make(chan struct{})}
			session.receiveFn = func(deadline time.Time) (nativeTCPInbound, error) {
				now = deadline
				return nativeTCPInbound{}, cause
			}
			replaceModeFactories(t, map[string]func(Options) Runner{
				"tcp-syn": func(opts Options) Runner {
					return &nativeTCPRunner{
						mode: "tcp-syn", opts: opts,
						opener: func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) { return session, nil },
						now:    func() time.Time { return now },
					}
				},
			})
			result, err := Run(context.Background(), "192.0.2.10", Options{Modes: []string{"tcp-syn"}, Ports: []int{443}, Timeout: time.Second})
			if err != nil || result.Matched {
				t.Fatalf("response-side unreachable after send must be no-signal: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestNativeTCPRunnerRejectsIPv6WithoutOpeningSession(t *testing.T) {
	called := false
	runner := newNativeTCPRunner("tcp-syn", Options{Ports: []int{443}}, func(context.Context, net.IP, time.Duration) (nativeTCPSession, error) {
		called = true
		return nil, errors.New("unexpected")
	})
	_, err := runner.Run(context.Background(), "2001:db8::1")
	if !errors.Is(err, ErrModeUnavailable) || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}
