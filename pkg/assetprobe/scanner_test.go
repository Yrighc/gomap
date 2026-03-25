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
