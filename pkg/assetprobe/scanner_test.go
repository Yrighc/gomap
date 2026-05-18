package assetprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/hostdiscovery"
)

func TestApplyDefaults(t *testing.T) {
	opts := Options{}
	applyDefaults(&opts)

	if opts.PortConcurrency != 200 {
		t.Fatalf("unexpected default port concurrency: %d", opts.PortConcurrency)
	}
	if opts.PortRateLimit != 0 {
		t.Fatalf("unexpected default port rate limit: %d", opts.PortRateLimit)
	}
	if opts.Timeout != 2*time.Second {
		t.Fatalf("unexpected default timeout: %s", opts.Timeout)
	}
	if opts.HostDiscovery.Disabled {
		t.Fatal("expected host discovery enabled by default")
	}
	if len(opts.HostDiscovery.Modes) == 0 {
		t.Fatal("expected default host discovery modes")
	}
	if len(opts.HostDiscovery.Ports) == 0 {
		t.Fatal("expected default host discovery ports")
	}
}

func TestZeroConfigScannerCanScanTCPWithoutHostDiscoveryConfigError(t *testing.T) {
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scanner.Scan(context.Background(), ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: "65001",
		Protocol: ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{
			Disabled: true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected zero-config tcp scan error: %v", err)
	}
}

func TestGetPortRateLimiterSharedByRate(t *testing.T) {
	limiterA := getPortRateLimiter(100)
	limiterB := getPortRateLimiter(100)
	limiterC := getPortRateLimiter(200)

	if limiterA == nil || limiterB == nil || limiterC == nil {
		t.Fatal("expected non-nil limiter")
	}
	if limiterA != limiterB {
		t.Fatal("expected same rate to share one global limiter")
	}
	if limiterA == limiterC {
		t.Fatal("expected different rates to use different limiters")
	}
}

func TestWaitPortRateLimitNoLimiter(t *testing.T) {
	if err := waitPortRateLimit(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitPortRateLimitRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitPortRateLimit(ctx, getPortRateLimiter(1)); err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestDiscoverTCPPortReturnsTrueForListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	if !discoverTCPPort("127.0.0.1", addr.Port, time.Second) {
		t.Fatal("expected listening port to be discovered as open")
	}

	<-done
}

func TestDetectHomepageWithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("<html><head><title>demo</title></head><body>abcdef</body></html>"))
	}))
	defer server.Close()

	scanner, err := NewScanner(Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.DetectHomepageWithOptions(context.Background(), server.URL, HomepageOptions{
		IncludeHeaders: true,
		MaxBodyBytes:   10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.Header.ContentType == "" {
		t.Fatal("expected content type")
	}
	if result.Response.HeaderMap == "" {
		t.Fatal("expected header map text to be returned")
	}
	if len(result.Response.Body) != 10 {
		t.Fatalf("expected truncated body length 10, got %d", len(result.Response.Body))
	}
}

func TestNormalizeTargets(t *testing.T) {
	got := normalizeTargets([]string{" 127.0.0.1 ", "", "127.0.0.1", "example.com"})
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got))
	}
	if got[0] != "127.0.0.1" || got[1] != "example.com" {
		t.Fatalf("unexpected target order: %#v", got)
	}
}

func TestScanSkipsPortScanWhenHostDiscoveryReturnsNoSignal(t *testing.T) {
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

	scanner, err := NewScanner(Options{
		Timeout: 100 * time.Millisecond,
		HostDiscovery: HostDiscoveryOptions{
			Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Ports: []int{65001},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		Protocol: ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{
			Modes:   []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Timeout: 20 * time.Millisecond,
			Ports:   []int{65001},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Ports) != 0 {
		t.Fatalf("expected no ports after host discovery skip, got %+v", result.Ports)
	}
}

func TestScanTargetsKeepsOrderAndPerTargetErrors(t *testing.T) {
	scanner, err := NewScanner(Options{Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{
		"127.0.0.1",
		"invalid.invalid",
	}, ScanCommonOptions{
		PortSpec:      "1",
		Protocol:      ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{Disabled: true},
	})
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(result.Results))
	}
	if result.Results[0].Target != "127.0.0.1" {
		t.Fatalf("unexpected first target: %s", result.Results[0].Target)
	}
	if result.Results[0].Result == nil {
		t.Fatal("expected first target result")
	}
	if result.Results[1].Target != "invalid.invalid" {
		t.Fatalf("unexpected second target: %s", result.Results[1].Target)
	}
	if result.Results[1].Error == "" {
		t.Fatal("expected second target error")
	}
}

func TestScanTargetsReturnsResultsInInputOrder(t *testing.T) {
	scanner, err := NewScanner(Options{Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{
		"example.com",
		"127.0.0.1",
	}, ScanCommonOptions{
		PortSpec:        "1",
		Protocol:        ProtocolTCP,
		PortConcurrency: 4,
		HostDiscovery:   HostDiscoveryOptions{Disabled: true},
	})
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(result.Results))
	}
	if result.Results[0].Target != "example.com" || result.Results[1].Target != "127.0.0.1" {
		t.Fatalf("unexpected result order: %#v", result.Results)
	}
}

func TestScanTargetsSkipsPortScanWhenHostDiscoveryReturnsNoSignal(t *testing.T) {
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

	scanner, err := NewScanner(Options{
		Timeout: 100 * time.Millisecond,
		HostDiscovery: HostDiscoveryOptions{
			Modes: []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Ports: []int{65001},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1"}, ScanCommonOptions{
		PortSpec: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		Protocol: ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{
			Modes:   []HostDiscoveryMode{HostDiscoveryTCPConnect},
			Timeout: 20 * time.Millisecond,
			Ports:   []int{65001},
		},
	})
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 batch result, got %d", len(result.Results))
	}
	if result.Results[0].Error != "" {
		t.Fatalf("expected no per-target error, got %s", result.Results[0].Error)
	}
	if result.Results[0].Result == nil {
		t.Fatal("expected target result")
	}
	if len(result.Results[0].Result.Ports) != 0 {
		t.Fatalf("expected no ports after host discovery skip, got %+v", result.Results[0].Result.Ports)
	}
}

func TestScanTargetsRunsHostDiscoveryConcurrentlyAndKeepsOrder(t *testing.T) {
	origRunHostDiscovery := runHostDiscovery
	t.Cleanup(func() { runHostDiscovery = origRunHostDiscovery })

	started := make(chan string, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseDiscovery := func() {
		releaseOnce.Do(func() { close(release) })
	}
	t.Cleanup(releaseDiscovery)
	runHostDiscovery = func(ctx context.Context, ip string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		started <- ip
		<-release
		return hostdiscovery.Result{}, nil
	}
	waitForStarted := func(label string) string {
		t.Helper()
		select {
		case ip := <-started:
			return ip
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %s host discovery to start", label)
			return ""
		}
	}

	scanner, err := NewScanner(Options{
		Timeout:         50 * time.Millisecond,
		PortConcurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan *BatchScanResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, ScanCommonOptions{
			PortSpec:        "65001",
			Protocol:        ProtocolTCP,
			PortConcurrency: 2,
		})
		if err != nil {
			errCh <- err
			return
		}
		done <- result
	}()

	first := waitForStarted("first")
	second := waitForStarted("second")
	if first == second {
		t.Fatalf("expected two distinct targets to start discovery, got %q and %q", first, second)
	}
	releaseDiscovery()

	select {
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case result := <-done:
		if len(result.Results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(result.Results))
		}
		if result.Results[0].Target != "127.0.0.1" || result.Results[1].Target != "127.0.0.2" {
			t.Fatalf("unexpected result order: %#v", result.Results)
		}
		if result.Results[0].Result == nil || result.Results[1].Result == nil {
			t.Fatalf("expected skipped targets to have empty results: %#v", result.Results)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ScanTargets")
	}
}
