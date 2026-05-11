package httpauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientDoFormLoginPreservesCookies(t *testing.T) {
	var sessionSeen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
			w.WriteHeader(http.StatusOK)
		case "/profile":
			_, err := r.Cookie("sid")
			sessionSeen = err == nil
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: time.Second})
	if _, err := client.Do(context.Background(), Request{
		Method: http.MethodPost,
		URL:    srv.URL + "/login",
	}); err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if _, err := client.Do(context.Background(), Request{
		Method: http.MethodGet,
		URL:    srv.URL + "/profile",
	}); err != nil {
		t.Fatalf("profile request failed: %v", err)
	}
	if !sessionSeen {
		t.Fatal("expected cookie jar to preserve session cookie")
	}
}

func TestClientDoCarriesHeadersAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("expected content-type header, got %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if string(body) != `{"user":"admin"}` {
			t.Fatalf("unexpected request body %q", string(body))
		}
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"token":"abc"}`)
	}))
	defer srv.Close()

	client := NewClient(Config{Timeout: time.Second})
	resp, err := client.Do(context.Background(), Request{
		Method: http.MethodPost,
		URL:    srv.URL,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: []byte(`{"user":"admin"}`),
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, resp.StatusCode)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("expected response header, got %q", got)
	}
	if strings.TrimSpace(string(resp.Body)) != `{"token":"abc"}` {
		t.Fatalf("unexpected response body %q", string(resp.Body))
	}
}
