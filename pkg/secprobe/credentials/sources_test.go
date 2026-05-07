package credentials

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestLoadDirectorySourceLoadsFirstAvailableCandidate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "postgres.txt"), []byte("pg : secret\n"), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "postgresql.txt"), []byte("root : root\n"), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}

	got, desc, err := LoadDirectorySource("postgres", dir)
	if err != nil {
		t.Fatalf("LoadDirectorySource() error = %v", err)
	}

	wantCreds := []strategy.Credential{{Username: "root", Password: "root"}}
	if !reflect.DeepEqual(got, wantCreds) {
		t.Fatalf("LoadDirectorySource() creds = %v, want %v", got, wantCreds)
	}
	if desc.Kind != SourceDictDir || desc.Name != "postgresql" {
		t.Fatalf("LoadDirectorySource() desc = %+v", desc)
	}
}

func TestLoadDirectorySourceReturnsMissingErrorWhenCandidatesAbsent(t *testing.T) {
	_, _, err := LoadDirectorySource("custom", t.TempDir())
	if err == nil {
		t.Fatal("expected missing directory source error")
	}
	if !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestLoadBuiltinSourceUsesBuiltinLoader(t *testing.T) {
	restore := stubBuiltinLoader(func(protocol string) ([]strategy.Credential, error) {
		if protocol != "ssh" {
			t.Fatalf("protocol = %q, want %q", protocol, "ssh")
		}
		return []strategy.Credential{{Username: "builtin", Password: "cred"}}, nil
	})
	defer restore()

	got, desc, err := LoadBuiltinSource("ssh")
	if err != nil {
		t.Fatalf("LoadBuiltinSource() error = %v", err)
	}
	want := []strategy.Credential{{Username: "builtin", Password: "cred"}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadBuiltinSource() = %v, want %v", got, want)
	}
	if desc.Kind != SourceBuiltin || desc.Name != "ssh" {
		t.Fatalf("LoadBuiltinSource() desc = %+v", desc)
	}
}
