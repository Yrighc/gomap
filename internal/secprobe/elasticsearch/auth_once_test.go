package elasticsearch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestElasticsearchAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(_ context.Context, _ strategy.Target, cred strategy.Credential) (registrybridge.Attempt, error) {
		if cred.Username != "elastic" || cred.Password != "secret" {
			t.Fatalf("unexpected credential: %+v", cred)
		}
		return registrybridge.Attempt{
			Result: result.Attempt{
				Success:  true,
				Evidence: "Elasticsearch authentication succeeded via /_security/_authenticate",
			},
		}, nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
	if out.Result.Username != "elastic" || out.Result.Password != "secret" {
		t.Fatalf("expected credential echo, got %+v", out.Result)
	}
	if out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", out.Result)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error) {
		return registrybridge.Attempt{}, errors.New("401 unauthorized")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "wrong",
	})

	if out.Result.Success {
		t.Fatalf("expected authentication failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceMapsConnectionFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) (registrybridge.Attempt, error) {
		return registrybridge.Attempt{}, errors.New("dial tcp 127.0.0.1:9200: connect: connection refused")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if out.Result.ErrorCode != result.ErrorCodeConnection {
		t.Fatalf("expected connection error code, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceUsesRealAuthenticatePath(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	called := false
	doHTTP = func(req *http.Request) (*http.Response, error) {
		called = true
		if req.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", req.Method)
		}
		if req.URL.String() != "https://127.0.0.1:9200/_security/_authenticate" {
			t.Fatalf("unexpected request url: %s", req.URL.String())
		}
		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Fatal("expected basic auth")
		}
		if user != "elastic" || pass != "secret" {
			t.Fatalf("unexpected basic auth values %q/%q", user, pass)
		}
		if got := req.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("expected Accept application/json, got %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"username":"elastic"}`)),
			Header:     make(http.Header),
		}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := NewAuthenticator(nil).AuthenticateOnce(ctx, strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if !called {
		t.Fatal("expected real authenticateOnce path to perform an HTTP request")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceMapsMissingUsernameToInsufficientConfirmation(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	doHTTP = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"roles":["superuser"]}`)),
			Header:     make(http.Header),
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if out.Result.Success {
		t.Fatalf("expected insufficient confirmation failure, got %+v", out)
	}
	if out.Result.ErrorCode != result.ErrorCodeInsufficientConfirmation {
		t.Fatalf("expected insufficient confirmation error code, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceUsesHTTPSPathFirst(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	called := false
	doHTTP = func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.String() != "https://127.0.0.1:9200/_security/_authenticate" {
			t.Fatalf("unexpected request url: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"username":"elastic"}`)),
			Header:     make(http.Header),
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if !called {
		t.Fatal("expected https request to be attempted")
	}
	if !out.Result.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceFallsBackToHTTPWhenHTTPSGetsPlainHTTPError(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	var urls []string
	doHTTP = func(req *http.Request) (*http.Response, error) {
		urls = append(urls, req.URL.String())
		if len(urls) == 1 {
			return nil, errors.New("http: server gave HTTP response to HTTPS client")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"username":"elastic"}`)),
			Header:     make(http.Header),
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if len(urls) != 2 {
		t.Fatalf("expected https then http attempts, got %v", urls)
	}
	if urls[0] != "https://127.0.0.1:9200/_security/_authenticate" {
		t.Fatalf("unexpected first url: %s", urls[0])
	}
	if urls[1] != "http://127.0.0.1:9200/_security/_authenticate" {
		t.Fatalf("unexpected fallback url: %s", urls[1])
	}
	if !out.Result.Success {
		t.Fatalf("expected fallback success, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceDoesNotFallbackToHTTPOnAuthenticationFailure(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	var urls []string
	doHTTP = func(req *http.Request) (*http.Response, error) {
		urls = append(urls, req.URL.String())
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"error":"security_exception"}`)),
			Header:     make(http.Header),
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "wrong",
	})

	if len(urls) != 1 {
		t.Fatalf("expected no fallback on authentication failure, got %v", urls)
	}
	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication error code, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceRetriesHTTPSWithInsecureTLSOnCertificateError(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	var urls []string
	doHTTP = func(req *http.Request) (*http.Response, error) {
		urls = append(urls, req.URL.String())
		if len(urls) == 1 {
			return nil, errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")
		}
		if got := req.Header.Get("X-Secprobe-Insecure-TLS"); got != "true" {
			t.Fatalf("expected insecure tls retry marker, got %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"username":"elastic"}`)),
			Header:     make(http.Header),
		}, nil
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if len(urls) != 2 {
		t.Fatalf("expected two https attempts, got %v", urls)
	}
	if urls[0] != "https://127.0.0.1:9200/_security/_authenticate" || urls[1] != urls[0] {
		t.Fatalf("expected https retry on same url, got %v", urls)
	}
	if !out.Result.Success {
		t.Fatalf("expected insecure tls retry success, got %+v", out)
	}
}

func TestElasticsearchAuthenticatorAuthenticateOnceDoesNotFallbackToHTTPOnGenericTLSHandshakeFailure(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	var urls []string
	doHTTP = func(req *http.Request) (*http.Response, error) {
		urls = append(urls, req.URL.String())
		return nil, errors.New("remote error: tls handshake failure")
	}

	out := NewAuthenticator(nil).AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "es.local",
		IP:       "127.0.0.1",
		Port:     9200,
		Protocol: "elasticsearch",
	}, strategy.Credential{
		Username: "elastic",
		Password: "secret",
	})

	if len(urls) != 1 {
		t.Fatalf("expected no retry or http fallback on generic tls handshake failure, got %v", urls)
	}
	if out.Result.ErrorCode != result.ErrorCodeConnection {
		t.Fatalf("expected connection error code, got %+v", out)
	}
}
