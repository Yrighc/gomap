package hostdiscovery

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type timeoutDialError struct{}

func (timeoutDialError) Error() string   { return "timeout" }
func (timeoutDialError) Timeout() bool   { return true }
func (timeoutDialError) Temporary() bool { return true }

func TestTCPConnectMatchesOnSuccessfulConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	result, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{port},
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("expected matched result, got %+v", result)
	}
}

func TestTCPConnectReturnsNoMatchForTimeout(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })
	tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutDialError{}}
	}

	result, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80}}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
}

func TestTCPConnectReturnsAfterFirstMatchedPortAndCancelsInflightDial(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })

	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	var peer net.Conn
	tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
		switch port {
		case 80:
			close(slowStarted)
			<-ctx.Done()
			close(slowCanceled)
			return nil, ctx.Err()
		case 443:
			select {
			case <-slowStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			server, client := net.Pipe()
			peer = server
			return client, nil
		default:
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80, 443, 22, 445, 3389},
	}).Run(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected result: %+v", result)
	}
	<-slowCanceled
	if peer == nil {
		t.Fatal("expected port 443 to be attempted")
	}
	defer peer.Close()
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected matched connection to be closed, got %v", err)
	}
}

func TestTCPConnectAttemptsEveryPortAcrossConcurrencyWaves(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })

	var calls atomic.Int32
	tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		calls.Add(1)
		return nil, timeoutDialError{}
	}
	ports := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	result, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: ports}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
	if got := calls.Load(); got != int32(len(ports)) {
		t.Fatalf("expected all %d ports to be attempted, got %d", len(ports), got)
	}
}

func TestTCPConnectAggregatesPortErrorsInConfiguredOrder(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })
	tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("resource failure")
	}

	_, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{443, 80, 22}}).Run(context.Background(), "127.0.0.1")
	if !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected ErrProbeFailed, got %v", err)
	}
	message := err.Error()
	first := strings.Index(message, "port 443")
	second := strings.Index(message, "port 80")
	third := strings.Index(message, "port 22")
	if first < 0 || second < 0 || third < 0 || first > second || second > third {
		t.Fatalf("expected configured port order in error, got %v", err)
	}
}

func TestTCPConnectParentContextCancelReturnsErrorWithoutDial(t *testing.T) {
	original := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = original })

	var calls atomic.Int32
	tcpConnectDialContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newTCPConnectRunner(Options{Timeout: time.Second, Ports: []int{80, 443}}).Run(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("expected no dial after cancellation, got %d", calls.Load())
	}
}
