package neo4j

import (
	"context"
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

func TestNeo4jAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) error {
		if cred.Username != "neo4j" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "neo.local",
		IP:       "127.0.0.1",
		Port:     7474,
		Protocol: "neo4j",
	}, strategy.Credential{Username: "neo4j", Password: "secret"})

	if !out.Result.Success || out.Result.Evidence != "Neo4j HTTP login succeeded" {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceMapsFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want result.ErrorCode
	}{
		{name: "authentication", err: errNeo4jAuthenticationFailed, want: result.ErrorCodeAuthentication},
		{name: "connection", err: errors.New("dial tcp 127.0.0.1:7474: connect: connection refused"), want: result.ErrorCodeConnection},
		{name: "timeout", err: context.DeadlineExceeded, want: result.ErrorCodeTimeout},
		{name: "canceled", err: context.Canceled, want: result.ErrorCodeCanceled},
		{name: "insufficient confirmation", err: errNeo4jMissingConfirmation, want: result.ErrorCodeInsufficientConfirmation},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
				return tt.err
			})

			out := auth.AuthenticateOnce(context.Background(), strategy.Target{
				Host:     "neo.local",
				IP:       "127.0.0.1",
				Port:     7474,
				Protocol: "neo4j",
			}, strategy.Credential{Username: "neo4j", Password: "wrong"})

			if out.Result.Success {
				t.Fatalf("expected failure, got %+v", out)
			}
			if out.Result.ErrorCode != tt.want {
				t.Fatalf("expected %q, got %+v", tt.want, out)
			}
		})
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceUsesBasicAuthRequest(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/db/neo4j/tx/commit" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth")
		}
		if user != "neo4j" || pass != "secret" {
			t.Fatalf("unexpected basic auth values %q/%q", user, pass)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type %q", got)
		}
		_, _ = io.WriteString(w, `{"results":[{}],"errors":[]}`)
	}))
	defer srv.Close()

	target := neo4jTargetFromURL(t, srv.URL)
	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), target, strategy.Credential{
		Username: "neo4j",
		Password: "secret",
	})

	if !called {
		t.Fatal("expected real login request")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceUsesHTTPSOnPort7473(t *testing.T) {
	var called bool
	srv, cleanup := newNeo4jTLSServer(t, "127.0.0.1:7473", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.TLS == nil {
			t.Fatal("expected tls request")
		}
		_, _ = io.WriteString(w, `{"results":[{}],"errors":[]}`)
	}))
	defer cleanup()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "127.0.0.1",
		IP:       "127.0.0.1",
		Port:     7473,
		Protocol: "neo4j",
	}, strategy.Credential{Username: "neo4j", Password: "secret"})

	if !called {
		t.Fatal("expected tls login request")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}

	_ = srv
}

func TestNeo4jAuthenticatorAuthenticateOnceRealAuthenticationFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), neo4jTargetFromURL(t, srv.URL), strategy.Credential{
		Username: "neo4j",
		Password: "wrong",
	})

	if out.Result.Success {
		t.Fatalf("expected authentication failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out.Result)
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceRealConnectionFailure(t *testing.T) {
	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), closedNeo4jTarget(t), strategy.Credential{
		Username: "neo4j",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected connection failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeConnection {
		t.Fatalf("expected connection error code, got %+v", out.Result)
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceRealTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, `{"results":[{}],"errors":[]}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, neo4jTargetFromURL(t, srv.URL), strategy.Credential{
		Username: "neo4j",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected timeout, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeTimeout {
		t.Fatalf("expected timeout error code, got %+v", out.Result)
	}
}

func TestNeo4jAuthenticatorAuthenticateOnceRealCanceled(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result.Attempt, 1)
	go func() {
		out := NewAuthenticator(nil).AuthenticateOnce(ctx, neo4jTargetFromURL(t, srv.URL), strategy.Credential{
			Username: "neo4j",
			Password: "secret",
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

func neo4jTargetFromURL(t *testing.T, rawURL string) strategy.Target {
	t.Helper()

	host, port := mustParseHostPort(t, rawURL)
	return strategy.Target{
		Host:     host,
		IP:       host,
		Port:     mustAtoi(t, port),
		Protocol: "neo4j",
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

func closedNeo4jTarget(t *testing.T) strategy.Target {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	return strategy.Target{Host: "127.0.0.1", IP: "127.0.0.1", Port: port, Protocol: "neo4j"}
}

func newNeo4jTLSServer(t *testing.T, addr string, handler http.Handler) (*httptest.Server, func()) {
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
