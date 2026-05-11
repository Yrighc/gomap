package neo4j

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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

func neo4jTargetFromURL(t *testing.T, rawURL string) strategy.Target {
	t.Helper()

	parts := strings.TrimPrefix(rawURL, "http://")
	host, port, ok := strings.Cut(parts, ":")
	if !ok {
		t.Fatalf("unexpected test server url %q", rawURL)
	}
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
