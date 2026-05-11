package zabbix

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestZabbixAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "Admin" || cred.Password != "zabbix" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "zbx.local",
		IP:       "127.0.0.1",
		Port:     80,
		Protocol: "zabbix",
	}, strategy.Credential{Username: "Admin", Password: "zabbix"})

	if !out.Result.Success || out.Result.Evidence != "Zabbix HTTP login succeeded" {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestZabbixAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errZabbixAuthenticationFailed, want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:80: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "insufficient confirmation", err: errZabbixMissingToken, want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "zbx.local",
				IP:       "127.0.0.1",
				Port:     80,
				Protocol: "zabbix",
			}, strategy.Credential{Username: "Admin", Password: "wrong"})

			if out.Result.Success {
				t.Fatalf("expected failure, got %+v", out)
			}
			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}

func TestZabbixAuthenticatorAuthenticateOnceUsesJSONRPCLogin(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/api_jsonrpc.php" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		params, ok := payload["params"].(map[string]any)
		if !ok {
			t.Fatalf("missing params: %#v", payload)
		}
		if params["username"] != "Admin" || params["password"] != "zabbix" {
			t.Fatalf("unexpected params %#v", params)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","result":"token-123","id":1}`)
	}))
	defer srv.Close()

	target := zabbixTargetFromURL(t, srv.URL)
	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), target, strategy.Credential{
		Username: "Admin",
		Password: "zabbix",
	})

	if !called {
		t.Fatal("expected real login request")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestZabbixAuthenticatorAuthenticateOnceUsesHTTPSOnPort8443(t *testing.T) {
	var called bool
	srv, cleanup := newZabbixTLSServer(t, "127.0.0.1:8443", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.TLS == nil {
			t.Fatal("expected tls request")
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","result":"token-8443","id":1}`)
	}))
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "127.0.0.1",
		IP:       "127.0.0.1",
		Port:     8443,
		Protocol: "zabbix",
	}, strategy.Credential{Username: "Admin", Password: "zabbix"})

	if !called {
		t.Fatal("expected tls login request")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	_ = srv
}

func TestZabbixAuthenticatorAuthenticateOnceRealAuthenticationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Login name or password is incorrect"},"id":1}`)
	}))
	defer srv.Close()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), zabbixTargetFromURL(t, srv.URL), strategy.Credential{
		Username: "Admin",
		Password: "wrong",
	})

	if out.Result.Success {
		t.Fatalf("expected authentication failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out.Result)
	}
}

func TestZabbixAuthenticatorAuthenticateOnceRealConnectionFailure(t *testing.T) {
	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), closedZabbixTarget(t), strategy.Credential{
		Username: "Admin",
		Password: "zabbix",
	})

	if out.Result.Success {
		t.Fatalf("expected connection failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeConnection {
		t.Fatalf("expected connection error code, got %+v", out.Result)
	}
}

func TestZabbixAuthenticatorAuthenticateOnceRealTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","result":"late","id":1}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, zabbixTargetFromURL(t, srv.URL), strategy.Credential{
		Username: "Admin",
		Password: "zabbix",
	})

	if out.Result.Success {
		t.Fatalf("expected timeout, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeTimeout {
		t.Fatalf("expected timeout error code, got %+v", out.Result)
	}
}

func TestZabbixAuthenticatorAuthenticateOnceRealCanceled(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result.Attempt, 1)
	go func() {
		out := NewAuthenticator(nil).AuthenticateOnce(ctx, zabbixTargetFromURL(t, srv.URL), strategy.Credential{
			Username: "Admin",
			Password: "zabbix",
		})
		done <- out.Result
	}()

	<-started
	cancel()
	out := <-done
	if out.Success {
		t.Fatalf("expected canceled failure, got %+v", out)
	}
	if out.ErrorCode != result.ErrorCodeCanceled {
		t.Fatalf("expected canceled error code, got %+v", out)
	}
}

func zabbixTargetFromURL(t *testing.T, rawURL string) strategy.Target {
	t.Helper()

	host, port := mustParseHostPort(t, rawURL)
	return strategy.Target{
		Host:     host,
		IP:       host,
		Port:     mustAtoi(t, port),
		Protocol: "zabbix",
	}
}

func mustAtoi(t *testing.T, raw string) int {
	t.Helper()

	value, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("atoi %q: %v", raw, err)
	}
	return value
}

func mustParseHostPort(t *testing.T, rawURL string) (string, string) {
	t.Helper()

	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	host, port, ok := strings.Cut(trimmed, ":")
	if !ok {
		t.Fatalf("unexpected test server url %q", rawURL)
	}
	return host, port
}

func closedZabbixTarget(t *testing.T) strategy.Target {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	return strategy.Target{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, Protocol: "zabbix"}
}

func newZabbixTLSServer(t *testing.T, addr string, handler http.Handler) (*httptest.Server, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("listen %s: %v", addr, err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = listener
	srv.StartTLS()

	return srv, func() {
		srv.Close()
	}
}
