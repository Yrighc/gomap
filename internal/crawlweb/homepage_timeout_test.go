package crawlweb

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yrighc/gomap/config/logger"
)

func TestHomepageContextDefaultAndOverride(t *testing.T) {
	ctx, cancel := homepageContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second || time.Until(deadline) < 9*time.Second {
		t.Fatalf("expected default 10s deadline, got %v", deadline)
	}
	for _, duration := range []time.Duration{time.Second, 20 * time.Second} {
		parent, stop := context.WithTimeout(context.Background(), duration)
		child, finish := homepageContext(parent)
		want, _ := parent.Deadline()
		got, _ := child.Deadline()
		finish()
		stop()
		if !got.Equal(want) {
			t.Fatalf("caller deadline changed: got %v want %v", got, want)
		}
	}
	client := createHTTPClient(false)
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if client.Timeout != 0 || transport.TLSHandshakeTimeout != 0 || transport.ResponseHeaderTimeout != 0 {
		t.Fatal("hidden client/stage timeout overrides request context")
	}
}

func TestFetchHomepageCancellationReachesRequest(t *testing.T) {
	for _, stage := range []string{"headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			started, stopped := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "body" {
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte("partial"))
					w.(http.Flusher).Flush()
				}
				close(started)
				<-r.Context().Done()
				close(stopped)
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := FetchWebInfoWithContext(ctx, server.URL, false); result <- err }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation chain, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request ignored cancellation")
			}
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not observe connection cancellation")
			}
		})
	}
}

func TestFetchHomepageRedirectSharesDeadline(t *testing.T) {
	finalStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		close(finalStarted)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := FetchWebInfoWithContext(ctx, server.URL, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected shared deadline, got %v", err)
	}
	select {
	case <-finalStarted:
	default:
		t.Fatal("redirect target not visited")
	}
}

func TestFetchHomepageFaviconTimeoutSemantics(t *testing.T) {
	// 内部包测试未经过 SDK 的日志初始化，不创建真实日志文件。
	oldWarnf := logger.Warnf
	logger.Warnf = func(string, ...interface{}) {}
	t.Cleanup(func() { logger.Warnf = oldWarnf })
	for _, overallTimeout := range []bool{false, true} {
		name := "favicon-only timeout keeps page"
		if overallTimeout {
			name = "overall timeout fails homepage"
		}
		t.Run(name, func(t *testing.T) {
			iconStarted, iconStopped := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/icon" {
					close(iconStarted)
					<-r.Context().Done()
					close(iconStopped)
					return
				}
				_, _ = w.Write([]byte(`<html><title>page</title><link rel="icon" href="/icon"></html>`))
			}))
			defer server.Close()
			ctx := context.Background()
			if overallTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 200*time.Millisecond)
				defer cancel()
			}
			page, err := FetchWebInfoWithContext(ctx, server.URL, false)
			if overallTimeout {
				if page != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("overall deadline returned success: page=%+v err=%v", page, err)
				}
			} else if err != nil || page == nil || page.Http.Title != "page" || page.Http.StatusCode != 200 {
				t.Fatalf("favicon-only failure lost main page: page=%+v err=%v", page, err)
			}
			select {
			case <-iconStarted:
			default:
				t.Fatal("favicon not requested")
			}
			select {
			case <-iconStopped:
			case <-time.After(2 * time.Second):
				t.Fatal("favicon exceeded deadline")
			}
		})
	}
}

func TestFetchHomepageTLSRetrySharesDeadline(t *testing.T) {
	oldWarnf := logger.Warnf
	logger.Warnf = func(string, ...interface{}) {}
	t.Cleanup(func() { logger.Warnf = oldWarnf })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	// 首次默认客户端不启用此旧套件，兼容客户端才可握手成功。
	server.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var handshakes atomic.Int32
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeStart: func() { handshakes.Add(1) }})
	started := time.Now()
	_, err := FetchWebInfoWithContext(ctx, server.URL, true)
	if !errors.Is(err, context.DeadlineExceeded) || handshakes.Load() != 2 {
		t.Fatalf("expected compatible retry under same deadline, handshakes=%d err=%v", handshakes.Load(), err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("TLS retry refreshed total timeout")
	}
}

// 覆盖旧实现的 3 秒响应头、5 秒单请求上限；总耗时仍在新的默认整体 10 秒内。
func TestFetchHomepageNoHiddenThreeOrFiveSecondLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Length", "4")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-time.After(2100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("page"))
	}))
	defer server.Close()
	page, err := FetchWebInfo(server.URL, false)
	if err != nil || page == nil || page.Http.Body != "page" {
		t.Fatalf("hidden phase limit: page=%+v err=%v", page, err)
	}
}
