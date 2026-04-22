package secprobe

import (
	"path/filepath"
	"testing"
)

func TestCredentialDictionaryCandidatesUsesCatalogDictNames(t *testing.T) {
	got := CredentialDictionaryCandidates("postgresql", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "postgresql.txt"),
		filepath.Join("/tmp/dicts", "secprobe-postgresql.txt"),
		filepath.Join("/tmp/dicts", "postgres.txt"),
		filepath.Join("/tmp/dicts", "secprobe-postgres.txt"),
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

func TestCredentialDictionaryCandidatesFallsBackForUnknownProtocol(t *testing.T) {
	got := CredentialDictionaryCandidates("customsvc", "/tmp/dicts")
	want := []string{
		filepath.Join("/tmp/dicts", "customsvc.txt"),
		filepath.Join("/tmp/dicts", "secprobe-customsvc.txt"),
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
