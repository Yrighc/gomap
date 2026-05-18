package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestTCPConnectMatchesOnSuccessfulConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	runner := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{port},
	})

	result, err := runner.Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched {
		t.Fatalf("expected matched result, got %+v", result)
	}
}

func TestTCPConnectReturnsNoMatchWhenAllPortsTimeout(t *testing.T) {
	runner := newTCPConnectRunner(Options{
		Timeout: 50 * time.Millisecond,
		Ports:   []int{65001},
	})

	result, err := runner.Run(context.Background(), "203.0.113.254")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Matched {
		t.Fatalf("expected no match, got %+v", result)
	}
}

func TestTCPConnectReturnsAfterFirstMatchedPort(t *testing.T) {
	origDial := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = origDial })

	hit := make(chan int, 8)
	tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		_, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
		hit <- port
		if port == 443 {
			server, client := net.Pipe()
			_ = server.Close()
			return client, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	result, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80, 443, 22, 445, 3389},
	}).Run(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("unexpected result: %+v", result)
	}

	seen443 := false
	for len(hit) > 0 {
		if <-hit == 443 {
			seen443 = true
		}
	}
	if !seen443 {
		t.Fatal("expected port 443 to be attempted")
	}
}

func TestTCPConnectParentContextCancelReturnsError(t *testing.T) {
	origDial := tcpConnectDialContext
	t.Cleanup(func() { tcpConnectDialContext = origDial })

	tcpConnectDialContext = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := newTCPConnectRunner(Options{
		Timeout: time.Second,
		Ports:   []int{80, 443},
	}).Run(ctx, "127.0.0.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
