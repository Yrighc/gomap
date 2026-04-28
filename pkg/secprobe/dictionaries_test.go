package secprobe

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestCredentialDictionaryCandidatesUsesCatalogDictNames(t *testing.T) {
	got := CredentialDictionaryCandidates("postgresql", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "postgresql.txt"),
		filepath.Join("/tmp/dicts", "postgres.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCredentialDictionaryCandidatesUsesCatalogDictNamesForAlias(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     []string
	}{
		{
			name:     "postgres alias",
			protocol: "postgres",
			want: []string{
				filepath.Join("/tmp/dicts", "postgresql.txt"),
				filepath.Join("/tmp/dicts", "postgres.txt"),
			},
		},
		{
			name:     "redis tls alias",
			protocol: "redis/tls",
			want: []string{
				filepath.Join("/tmp/dicts", "redis.txt"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CredentialDictionaryCandidates(tt.protocol, "/tmp/dicts"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CredentialDictionaryCandidates(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol(t *testing.T) {
	got := CredentialDictionaryCandidates("CustomSvc", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "CustomSvc.txt"),
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCredentialDictionaryCandidatesSkipsEmptyProtocol(t *testing.T) {
	if got := CredentialDictionaryCandidates("", "/tmp/dicts"); len(got) != 0 {
		t.Fatalf("expected no candidates for empty protocol, got %v", got)
	}
}
