package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectCredentialsParsesInlinePairs(t *testing.T) {
	got, err := collectCredentials("admin : admin,root : root", "")
	if err != nil {
		t.Fatalf("collect credentials: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}

func TestCollectCredentialsRejectsInvalidInlinePair(t *testing.T) {
	if _, err := collectCredentials("admin", ""); err == nil {
		t.Fatal("expected invalid inline credential to fail")
	}
}

func TestCollectCredentialsParsesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte("admin : admin\nroot : root\n"), 0o600); err != nil {
		t.Fatalf("write creds file: %v", err)
	}

	got, err := collectCredentials("", path)
	if err != nil {
		t.Fatalf("collect credentials from file: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}
