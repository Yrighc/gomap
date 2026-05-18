package hostdiscovery

import (
	"context"
	"net"
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
