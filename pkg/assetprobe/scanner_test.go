package assetprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestScanTargetsKeepsOrderAndPerTargetErrors(t *testing.T) {
	scanner, err := NewScanner(Options{Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanTargets(context.Background(), []string{
		"127.0.0.1",
		"invalid.invalid",
	}, ScanCommonOptions{
		PortSpec: "1",
		Protocol: ProtocolTCP,
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
