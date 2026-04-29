package mongodb

import (
	"testing"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestMongoURIFormatsIPv6Hosts(t *testing.T) {
	got := mongoURI("2001:db8::1", 27017)
	want := "mongodb://[2001:db8::1]:27017/?directConnection=true"
	if got != want {
		t.Fatalf("mongoURI() = %q, want %q", got, want)
	}
}

func TestMongoCredentialURIFormatsAuthAndIPv6(t *testing.T) {
	got := mongoCredentialURI(core.SecurityCandidate{
		ResolvedIP: "2001:db8::1",
		Port:       27017,
	}, core.Credential{
		Username: "user@example.com",
		Password: "p@ss:word",
	})

	want := "mongodb://user%40example.com:p%40ss%3Aword@[2001:db8::1]:27017/?directConnection=true"
	if got != want {
		t.Fatalf("mongoCredentialURI() = %q, want %q", got, want)
	}
}

func TestMongoEnrichmentURIFormatsAuthAndIPv6(t *testing.T) {
	got := mongoEnrichmentURI(core.SecurityResult{
		ResolvedIP: "2001:db8::1",
		Port:       27017,
		Username:   "user@example.com",
		Password:   "p@ss:word",
	})

	want := "mongodb://user%40example.com:p%40ss%3Aword@[2001:db8::1]:27017/?directConnection=true"
	if got != want {
		t.Fatalf("mongoEnrichmentURI() = %q, want %q", got, want)
	}
}
