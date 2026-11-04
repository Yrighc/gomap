package assetprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDetectHomepagePreservesConnectionError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	listener.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.DetectHomepage(context.Background(), target)
	var urlErr *url.Error
	var opErr *net.OpError
	if !errors.As(err, &urlErr) || !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("expected preserved URL/dial error chain, got %v", err)
	}
	if !strings.Contains(err.Error(), "homepage not reachable") {
		t.Fatalf("missing homepage context: %v", err)
	}
}

func TestDetectHomepagePreservesResponseReadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.DetectHomepage(context.Background(), server.URL)
	var opErr *net.OpError
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.As(err, &opErr) || opErr.Op != "read" {
		t.Fatalf("expected preserved body read error chain, got %v", err)
	}
}

func TestDetectHomepagePreservesHTTPSProtocolError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.DetectHomepage(context.Background(), strings.Replace(server.URL, "http://", "https://", 1))
	if !errors.Is(err, http.ErrSchemeMismatch) {
		t.Fatalf("expected preserved HTTPS protocol error, got %v", err)
	}
}

func TestDetectHomepageCancellationIsNotReachabilityFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		_, _ = w.Write([]byte("page"))
	}))
	defer server.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.DetectHomepage(ctx, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
