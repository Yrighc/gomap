package elasticsearch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestEnrichReturnsPayloadForAuthenticateRequest(t *testing.T) {
	restore := stubElasticsearchEnrichmentRequest(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "GET /_security/_authenticate", "200 OK\nusername: elastic", nil
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "elasticsearch",
		Success:  true,
		Username: "elastic",
		Password: "secret",
		Port:     9200,
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["payload"] != "GET /_security/_authenticate\n\n200 OK\nusername: elastic" {
		t.Fatalf("unexpected payload: %+v", got.Enrichment)
	}
}

func TestEnrichReturnsErrorPayloadOnFailure(t *testing.T) {
	restore := stubElasticsearchEnrichmentRequest(func(context.Context, core.SecurityResult, core.CredentialProbeOptions) (string, string, error) {
		return "", "", errors.New("request failed")
	})
	defer restore()

	got := Enrich(context.Background(), core.SecurityResult{
		Service:  "elasticsearch",
		Success:  true,
		Username: "elastic",
		Password: "secret",
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment["error"] != "request failed" {
		t.Fatalf("unexpected error payload: %+v", got.Enrichment)
	}
	if !got.Success {
		t.Fatalf("expected success to remain true, got %+v", got)
	}
}

func TestEnrichUsesAuthenticatePathWithHTTPSFallback(t *testing.T) {
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
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"username":"elastic"}`)),
			Header:     make(http.Header),
		}, nil
	}

	got := Enrich(context.Background(), core.SecurityResult{
		Target:      "es.local",
		ResolvedIP:  "127.0.0.1",
		Service:     "elasticsearch",
		Success:     true,
		Username:    "elastic",
		Password:    "secret",
		Port:        9200,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if len(urls) != 2 {
		t.Fatalf("expected https then http fallback, got %v", urls)
	}
	if urls[0] != "https://127.0.0.1:9200/_security/_authenticate" {
		t.Fatalf("unexpected first request URL %q", urls[0])
	}
	if urls[1] != "http://127.0.0.1:9200/_security/_authenticate" {
		t.Fatalf("unexpected fallback request URL %q", urls[1])
	}
	if got.Enrichment["payload"] != "GET /_security/_authenticate\n\n200 OK\nusername: elastic" {
		t.Fatalf("unexpected payload after fallback: %+v", got.Enrichment)
	}
}

func TestEnrichReturnsErrorPayloadForAuthenticateFailure(t *testing.T) {
	originalDo := doHTTP
	t.Cleanup(func() {
		doHTTP = originalDo
	})

	doHTTP = func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"security_exception"}}`)),
			Header:     make(http.Header),
		}, nil
	}

	got := Enrich(context.Background(), core.SecurityResult{
		Target:      "es.local",
		ResolvedIP:  "127.0.0.1",
		Service:     "elasticsearch",
		Success:     true,
		Username:    "elastic",
		Password:    "wrong",
		Port:        9200,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}, core.CredentialProbeOptions{Timeout: time.Second})

	if got.Enrichment == nil || got.Enrichment["error"] == nil {
		t.Fatalf("expected enrichment error payload, got %+v", got)
	}
	if _, ok := got.Enrichment["payload"]; ok {
		t.Fatalf("expected no payload on authenticate failure, got %+v", got.Enrichment)
	}
	if !got.Success {
		t.Fatalf("expected enrichment failure to stay non-fatal, got %+v", got)
	}
}

func TestBuildAuthenticateURLSupportsIPv6Literal(t *testing.T) {
	got := buildAuthenticateURL(strategy.Target{
		IP:   "2001:db8::1",
		Port: 9200,
	}, "https")

	if got != "https://[2001:db8::1]:9200/_security/_authenticate" {
		t.Fatalf("unexpected IPv6 authenticate URL: %s", got)
	}
}
