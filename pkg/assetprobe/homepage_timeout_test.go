package assetprobe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDetectHomepageDeadlineClosesUnderlyingRequest(t *testing.T) {
	stopped := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(stopped)
	}))
	defer server.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = scanner.DetectHomepage(ctx, server.URL)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("SDK returned but request stayed active")
	}
}

// 特意验证真实默认 10 秒：调用方没有 deadline，超时发生在附属请求而非主页面。
func TestDetectHomepageDefaultDeadlineDuringFavicon(t *testing.T) {
	iconStarted, iconStopped := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/icon" {
			close(iconStarted)
			<-r.Context().Done()
			close(iconStopped)
			return
		}
		select {
		case <-time.After(8 * time.Second):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(`<html><title>page</title><link rel="icon" href="/icon"></html>`))
	}))
	defer server.Close()
	scanner, err := NewScanner(Options{})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.DetectHomepage(context.Background(), server.URL)
	if page != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("default deadline during favicon returned success: page=%+v err=%v", page, err)
	}
	select {
	case <-iconStarted:
	default:
		t.Fatal("deadline did not occur during favicon")
	}
	select {
	case <-iconStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("default deadline did not cancel favicon")
	}
}

func TestDetectHomepageDoesNotUsePortTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte("page"))
	}))
	defer server.Close()
	scanner, err := NewScanner(Options{Timeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.DetectHomepage(context.Background(), server.URL)
	if err != nil || page == nil || page.Response.Body != "page" {
		t.Fatalf("homepage used port timeout: page=%+v err=%v", page, err)
	}
	if scanner.opts.Timeout != time.Millisecond {
		t.Fatalf("port timeout changed: %v", scanner.opts.Timeout)
	}
}
