package zabbix

import (
	"context"
	"encoding/json"
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

func zabbixTargetFromURL(t *testing.T, rawURL string) strategy.Target {
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
