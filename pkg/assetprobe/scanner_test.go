package assetprobe

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/hostdiscovery"
	"github.com/yrighc/gomap/internal/updservices"
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
	if opts.HostDiscovery.Modes != nil {
		t.Fatalf("expected automatic host discovery defaults, got explicit modes: %#v", opts.HostDiscovery.Modes)
	}
	if len(opts.HostDiscovery.Ports) == 0 {
		t.Fatal("expected default host discovery ports")
	}
}

func TestMergeHostDiscoveryOptionsDistinguishesInheritedAndExplicitAutomaticModes(t *testing.T) {
	base := HostDiscoveryOptions{
		Modes: []HostDiscoveryMode{HostDiscoveryICMPEcho, HostDiscoveryTCPConnect},
	}

	inherited := mergeHostDiscoveryOptions(base, HostDiscoveryOptions{})
	if !reflect.DeepEqual(inherited.Modes, base.Modes) {
		t.Fatalf("nil Modes should inherit scanner configuration: %#v", inherited.Modes)
	}

	automatic := mergeHostDiscoveryOptions(base, HostDiscoveryOptions{Modes: []HostDiscoveryMode{}})
	if automatic.Modes == nil || len(automatic.Modes) != 0 {
		t.Fatalf("non-nil empty Modes should select automatic policy: %#v", automatic.Modes)
	}
}

func TestMergeHostDiscoveryOptionsClonesInheritedEmptySlices(t *testing.T) {
	baseModes := make([]HostDiscoveryMode, 0, 1)
	basePorts := make([]int, 0, 1)
	merged := mergeHostDiscoveryOptions(HostDiscoveryOptions{
		Modes: baseModes,
		Ports: basePorts,
	}, HostDiscoveryOptions{})

	merged.Modes = append(merged.Modes, HostDiscoveryICMPEcho)
	merged.Ports = append(merged.Ports, 443)
	if got := baseModes[:1][0]; got != "" {
		t.Fatalf("merged empty Modes shares base backing array: %q", got)
	}
	if got := basePorts[:1][0]; got != 0 {
		t.Fatalf("merged empty Ports shares base backing array: %d", got)
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

func TestScanCanDisableServiceFingerprint(t *testing.T) {
	port, accepted := startControlledTCPListener(t)
	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:                    "127.0.0.1",
		Ports:                     []int{port},
		Protocol:                  ProtocolTCP,
		DisableServiceFingerprint: true,
		HostDiscovery:             controlledHostDiscovery(port),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	assertPortOnlyResult(t, result, port)
	waitForAcceptedConnections(t, accepted, 2)
	if got := accepted.Load(); got != 2 {
		t.Fatalf("expected host and port discovery to open 2 connections, got %d", got)
	}
}

func TestScanDefaultsToServiceFingerprint(t *testing.T) {
	port, accepted := startControlledTCPListener(t)
	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:        "127.0.0.1",
		Ports:         []int{port},
		Protocol:      ProtocolTCP,
		HostDiscovery: controlledHostDiscovery(port),
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	assertFingerprintResult(t, result, port)
	waitForAcceptedConnections(t, accepted, 3)
}

func TestScanTargetsCanDisableServiceFingerprint(t *testing.T) {
	port, accepted := startControlledTCPListener(t)
	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1", "localhost"}, ScanCommonOptions{
		Ports:                     []int{port},
		Protocol:                  ProtocolTCP,
		PortConcurrency:           2,
		DisableServiceFingerprint: true,
		HostDiscovery:             controlledHostDiscovery(port),
	})
	if err != nil {
		t.Fatalf("batch scan failed: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(result.Results))
	}
	for _, targetResult := range result.Results {
		if targetResult.Error != "" {
			t.Fatalf("target %s failed: %s", targetResult.Target, targetResult.Error)
		}
		assertPortOnlyResult(t, targetResult.Result, port)
	}
	waitForAcceptedConnections(t, accepted, 4)
	if got := accepted.Load(); got != 4 {
		t.Fatalf("expected host and port discovery connections for each target, got %d", got)
	}
}

func TestScanTargetsDefaultToServiceFingerprint(t *testing.T) {
	port, accepted := startControlledTCPListener(t)
	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1", "localhost"}, ScanCommonOptions{
		Ports:           []int{port},
		Protocol:        ProtocolTCP,
		PortConcurrency: 2,
		HostDiscovery:   controlledHostDiscovery(port),
	})
	if err != nil {
		t.Fatalf("batch scan failed: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(result.Results))
	}
	for _, targetResult := range result.Results {
		if targetResult.Error != "" {
			t.Fatalf("target %s failed: %s", targetResult.Target, targetResult.Error)
		}
		assertFingerprintResult(t, targetResult.Result, port)
	}
	waitForAcceptedConnections(t, accepted, 6)
}

func controlledHostDiscovery(port int) HostDiscoveryOptions {
	return HostDiscoveryOptions{
		Modes:   []HostDiscoveryMode{HostDiscoveryTCPConnect},
		Timeout: time.Second,
		Ports:   []int{port},
	}
}

func startControlledTCPListener(t *testing.T) (int, *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	return ln.Addr().(*net.TCPAddr).Port, accepted
}

func waitForAcceptedConnections(t *testing.T, accepted *atomic.Int32, want int32) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for accepted.Load() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := accepted.Load(); got < want {
		t.Fatalf("expected at least %d accepted connections, got %d", want, got)
	}
}

func assertPortOnlyResult(t *testing.T, result *ScanResult, port int) {
	t.Helper()

	if result == nil {
		t.Fatal("expected scan result")
	}
	if result.Meta.OpenPorts != 1 || result.Meta.FingerprintedOpenPorts != 0 || result.Meta.SkippedFingerprintPorts != 1 {
		t.Fatalf("unexpected port-only statistics: %#v", result.Meta)
	}
	if len(result.Ports) != 1 || result.Ports[0].Port != port || !result.Ports[0].Open {
		t.Fatalf("unexpected open port result: %#v", result.Ports)
	}
	got := result.Ports[0]
	if got.Service != "" || got.Version != "" || got.Banner != "" || got.Subject != "" || len(got.DNSNames) != 0 {
		t.Fatalf("expected no service fingerprint fields, got %#v", got)
	}
}

func assertFingerprintResult(t *testing.T, result *ScanResult, port int) {
	t.Helper()

	if result == nil {
		t.Fatal("expected scan result")
	}
	if result.Meta.OpenPorts != 1 || result.Meta.FingerprintedOpenPorts != 1 || result.Meta.SkippedFingerprintPorts != 0 {
		t.Fatalf("unexpected fingerprint statistics: %#v", result.Meta)
	}
	if len(result.Ports) != 1 || result.Ports[0].Port != port || !result.Ports[0].Open {
		t.Fatalf("unexpected open port result: %#v", result.Ports)
	}
	got := result.Ports[0]
	if got.Service == "" || got.Service == "open" || got.Service == "unknown" || got.Banner == "" {
		t.Fatalf("expected service fingerprint fields, got %#v", got)
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

func TestScanEmitsOpenPortEventBeforeReturning(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	doneAccept := make(chan struct{})
	go func() {
		defer close(doneAccept)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	events := make(chan ScanEvent, 1)
	scanner, err := NewScanner(Options{
		Timeout: 2 * time.Second,
		OnEvent: func(evt ScanEvent) {
			events <- evt
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		_, _ = scanner.Scan(context.Background(), ScanRequest{
			Target:   "127.0.0.1",
			Ports:    []int{ln.Addr().(*net.TCPAddr).Port},
			Protocol: ProtocolTCP,
			HostDiscovery: HostDiscoveryOptions{
				Disabled: true,
			},
		})
	}()

	select {
	case evt := <-events:
		if evt.Kind != ScanEventOpenPort {
			t.Fatalf("expected open port event, got %#v", evt)
		}
		if evt.Port != ln.Addr().(*net.TCPAddr).Port {
			t.Fatalf("expected event port %d, got %d", ln.Addr().(*net.TCPAddr).Port, evt.Port)
		}
	case <-time.After(time.Second):
		t.Fatal("expected open port event before scan completion")
	}

	<-scanDone
	<-doneAccept
}

func TestScanEmitsServiceMatchEventForHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "scanner-test")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}

	events := make(chan ScanEvent, 8)
	scanner, err := NewScanner(Options{
		Timeout: 2 * time.Second,
		OnEvent: func(evt ScanEvent) {
			events <- evt
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scanner.Scan(context.Background(), ScanRequest{
		Target:   u.Hostname(),
		Ports:    []int{port},
		Protocol: ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{
			Disabled: true,
		},
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	found := false
	for {
		select {
		case evt := <-events:
			if evt.Kind == ScanEventServiceMatch && evt.Port == port {
				found = true
				if evt.Service == "" || evt.Service == "unknown" || evt.Service == "open" {
					t.Fatalf("expected concrete service match, got %#v", evt)
				}
				return
			}
		default:
			if !found {
				t.Fatal("expected service match event")
			}
			return
		}
	}
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

func TestNormalizeTargetsExpandsCIDRAndDeduplicates(t *testing.T) {
	got := normalizeTargets([]string{"127.0.0.0/30", "127.0.0.2", " example.com "})
	want := []string{"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected targets:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestScanSkipsPortScanWhenHostDiscoveryReturnsNoSignal(t *testing.T) {
	original := runHostDiscovery
	runHostDiscovery = func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		return hostdiscovery.Result{}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	scanner, err := NewScanner(Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		Protocol: ProtocolTCP,
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

func TestScanTargetsExpandsCIDRTargets(t *testing.T) {
	scanner, err := NewScanner(Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{
		"127.0.0.0/30",
		"127.0.0.2",
	}, ScanCommonOptions{
		PortSpec:      "1",
		Protocol:      ProtocolTCP,
		HostDiscovery: HostDiscoveryOptions{Disabled: true},
	})
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}

	wantTargets := []string{"127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"}
	if len(result.Results) != len(wantTargets) {
		t.Fatalf("expected %d results, got %d", len(wantTargets), len(result.Results))
	}
	for i, want := range wantTargets {
		if result.Results[i].Target != want {
			t.Fatalf("unexpected target at index %d: want %s, got %s", i, want, result.Results[i].Target)
		}
		if result.Results[i].Error != "" {
			t.Fatalf("expected no error for %s, got %s", want, result.Results[i].Error)
		}
		if result.Results[i].Result == nil {
			t.Fatalf("expected result for %s", want)
		}
	}
}

func TestScanTargetsSkipsPortScanWhenHostDiscoveryReturnsNoSignal(t *testing.T) {
	original := runHostDiscovery
	runHostDiscovery = func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		return hostdiscovery.Result{}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	scanner, err := NewScanner(Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1"}, ScanCommonOptions{
		PortSpec: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		Protocol: ProtocolTCP,
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

func TestScanEmitsHostDiscoveryMatchedEvent(t *testing.T) {
	origRunHostDiscovery := runHostDiscovery
	t.Cleanup(func() { runHostDiscovery = origRunHostDiscovery })

	runHostDiscovery = func(ctx context.Context, ip string, opts HostDiscoveryOptions) (hostdiscovery.Result, error) {
		return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
	}

	events := make(chan ScanEvent, 4)
	scanner, err := NewScanner(Options{
		Timeout: 100 * time.Millisecond,
		OnEvent: func(evt ScanEvent) {
			events <- evt
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scanner.Scan(context.Background(), ScanRequest{
		Target:   "127.0.0.1",
		PortSpec: "1",
		Protocol: ProtocolTCP,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for {
		select {
		case evt := <-events:
			if evt.Kind == ScanEventHostDiscoveryMatched {
				if evt.Method != "tcp-connect" {
					t.Fatalf("expected method tcp-connect, got %#v", evt)
				}
				return
			}
		default:
			t.Fatal("expected host discovery matched event")
		}
	}
}

func TestScanEventCallbackCancellationStopsBeforePortScan(t *testing.T) {
	original := runHostDiscovery
	runHostDiscovery = func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	ctx, cancel := context.WithCancel(context.Background())
	scanner, err := NewScanner(Options{
		Timeout: time.Second,
		OnEvent: func(evt ScanEvent) {
			if evt.Kind == ScanEventHostDiscoveryMatched {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scanner.Scan(ctx, ScanRequest{
		Target:                    "127.0.0.1",
		Ports:                     []int{ln.Addr().(*net.TCPAddr).Port},
		Protocol:                  ProtocolTCP,
		DisableServiceFingerprint: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("port scan started after event callback canceled the context")
	default:
	}
}

func TestScanCancellationDuringPortStageReturnsContextError(t *testing.T) {
	port, accepted := startControlledTCPListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	scanner, err := NewScanner(Options{
		Timeout: time.Second,
		OnEvent: func(evt ScanEvent) {
			if evt.Kind == ScanEventOpenPort {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scanner.Scan(ctx, ScanRequest{
		Target:                    "127.0.0.1",
		Ports:                     []int{port},
		Protocol:                  ProtocolTCP,
		DisableServiceFingerprint: true,
		HostDiscovery:             HostDiscoveryOptions{Disabled: true},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	waitForAcceptedConnections(t, accepted, 1)
}

func TestScanTargetsCancellationStopsBufferedPreparationJobs(t *testing.T) {
	original := runHostDiscovery
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	runHostDiscovery = func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		calls.Add(1)
		cancel()
		return hostdiscovery.Result{}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	scanner, err := NewScanner(Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanTargets(ctx, []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, ScanCommonOptions{
		Ports:           []int{80},
		Protocol:        ProtocolTCP,
		PortConcurrency: 1,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected only the received preparation job to start discovery, got %d calls", calls.Load())
	}
	if result == nil || len(result.Results) != 3 {
		t.Fatalf("unexpected partial result: %#v", result)
	}
	for i, targetResult := range result.Results {
		if targetResult.Target == "" {
			t.Fatalf("target %d was not prefilled: %#v", i, result.Results)
		}
		if targetResult.Error != context.Canceled.Error() {
			t.Fatalf("target %d: expected cancellation error, got %q", i, targetResult.Error)
		}
		if targetResult.Result != nil {
			t.Fatalf("target %d: expected no port result after preparation cancellation", i)
		}
	}
}

func TestScanTargetsDiscoveryFailureIsNotReportedAsSkipped(t *testing.T) {
	original := runHostDiscovery
	runHostDiscovery = func(_ context.Context, ip string, _ HostDiscoveryOptions) (hostdiscovery.Result, error) {
		if ip == "127.0.0.1" {
			return hostdiscovery.Result{}, errors.Join(hostdiscovery.ErrProbeFailed, errors.New("probe broke"))
		}
		return hostdiscovery.Result{}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	var summary *HostDiscoverySummary
	scanner, err := NewScanner(Options{
		Timeout: time.Second,
		OnEvent: func(evt ScanEvent) {
			if evt.Kind == ScanEventHostDiscoverySummary {
				summary = evt.Summary
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, ScanCommonOptions{
		Ports:           []int{80},
		Protocol:        ProtocolTCP,
		PortConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("unexpected batch error: %v", err)
	}
	if !strings.Contains(result.Results[0].Error, "probe broke") {
		t.Fatalf("expected target-level discovery failure, got %#v", result.Results[0])
	}
	if result.Results[1].Result == nil || result.Results[1].Error != "" {
		t.Fatalf("expected second target to retain normal no-signal result, got %#v", result.Results[1])
	}
	if summary == nil {
		t.Fatal("expected host discovery summary")
	}
	if len(summary.Alive) != 0 || len(summary.Skipped) != 1 || summary.Skipped[0].Target != "127.0.0.2" {
		t.Fatalf("failure must not be counted as skipped: %#v", summary)
	}
}

func TestHostDiscoveryMatchDoesNotMarkRefusedScanPortOpen(t *testing.T) {
	original := runHostDiscovery
	runHostDiscovery = func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		return hostdiscovery.Result{Matched: true, Method: "tcp-connect"}, nil
	}
	t.Cleanup(func() { runHostDiscovery = original })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	scanner, err := NewScanner(Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), ScanRequest{
		Target:                    "127.0.0.1",
		Ports:                     []int{port},
		Protocol:                  ProtocolTCP,
		DisableServiceFingerprint: true,
	})
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}
	if len(result.Ports) != 0 || result.Meta.OpenPorts != 0 {
		t.Fatalf("connection refusal must not become an open port: %#v", result)
	}
}

func replaceUDPProbe(t *testing.T, fn func(context.Context, string, int, time.Duration) updservices.ProbeResult) {
	t.Helper()
	original := udpProbe
	udpProbe = fn
	t.Cleanup(func() { udpProbe = original })
}

func TestScanUDPRequiresResponseEvidence(t *testing.T) {
	var events []ScanEvent
	scanner := &Scanner{opts: Options{OnEvent: func(event ScanEvent) { events = append(events, event) }}}
	replaceUDPProbe(t, func(context.Context, string, int, time.Duration) updservices.ProbeResult {
		return updservices.ProbeResult{Service: "domain?"}
	})

	result := scanner.scanUDPPort(context.Background(), "target", "192.0.2.1", 53, time.Second)
	if result.Open || result.Service != "" || len(events) != 0 {
		t.Fatalf("service metadata without response emitted an open UDP result: result=%#v events=%#v", result, events)
	}
}

func TestScanUDPResponseEvidenceProducesCompatibleResultAndEvents(t *testing.T) {
	events := make([]ScanEvent, 0, 2)
	scanner := &Scanner{opts: Options{OnEvent: func(event ScanEvent) { events = append(events, event) }}}
	replaceUDPProbe(t, func(context.Context, string, int, time.Duration) updservices.ProbeResult {
		return updservices.ProbeResult{Responded: true, Banner: "reply", Service: "domain?", Version: "1"}
	})

	result := scanner.scanUDPPort(context.Background(), "target", "192.0.2.1", 53, time.Second)
	if !result.Open || result.Service != "domain" || result.Banner != "reply" || result.Version != "1" {
		t.Fatalf("response evidence did not retain UDP metadata: %#v", result)
	}
	if len(events) != 2 || events[0].Kind != ScanEventOpenPort || events[1].Kind != ScanEventServiceMatch {
		t.Fatalf("expected compatible UDP open and service events, got %#v", events)
	}
}

func TestUDPScanAndBatchSkipHostDiscoveryAndShareResponseRule(t *testing.T) {
	var discoveryCalls atomic.Int32
	replaceRunHostDiscovery(t, func(context.Context, string, HostDiscoveryOptions) (hostdiscovery.Result, error) {
		discoveryCalls.Add(1)
		return hostdiscovery.Result{}, nil
	})
	replaceUDPProbe(t, func(context.Context, string, int, time.Duration) updservices.ProbeResult {
		return updservices.ProbeResult{Responded: true}
	})
	scanner := &Scanner{opts: Options{PortConcurrency: 1, Timeout: time.Second}}

	single, err := scanner.Scan(context.Background(), ScanRequest{
		Target: "127.0.0.1", Ports: []int{53006}, Protocol: ProtocolUDP,
	})
	if err != nil {
		t.Fatalf("UDP Scan returned error: %v", err)
	}
	if len(single.Ports) != 1 || !single.Ports[0].Open || single.Ports[0].Service != "unknown" {
		t.Fatalf("unexpected UDP Scan result: %#v", single)
	}

	batch, err := scanner.ScanTargets(context.Background(), []string{"127.0.0.1"}, ScanCommonOptions{
		Ports: []int{53006}, Protocol: ProtocolUDP, PortConcurrency: 1,
	})
	if err != nil {
		t.Fatalf("UDP ScanTargets returned error: %v", err)
	}
	if len(batch.Results) != 1 || batch.Results[0].Result == nil || len(batch.Results[0].Result.Ports) != 1 || !batch.Results[0].Result.Ports[0].Open {
		t.Fatalf("unexpected UDP ScanTargets result: %#v", batch)
	}
	if got := discoveryCalls.Load(); got != 0 {
		t.Fatalf("UDP paths called Host Discovery %d times", got)
	}
}

func TestResolveTargetContextCancelsLookup(t *testing.T) {
	original := lookupTargetIPs
	started := make(chan struct{})
	lookupTargetIPs = func(ctx context.Context, network, host string) ([]net.IP, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { lookupTargetIPs = original })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := resolveTargetContext(ctx, "context-test.invalid")
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
