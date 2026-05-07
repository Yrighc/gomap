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

func TestLoadDirectorySourceSupportsAliasCandidates(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		file     string
		wantName string
	}{
		{name: "redis tls alias", protocol: "redis/tls", file: "redis.txt", wantName: "redis"},
		{name: "redis ssl alias", protocol: "redis/ssl", file: "redis.txt", wantName: "redis"},
		{name: "mongo alias", protocol: "mongo", file: "mongodb.txt", wantName: "mongodb"},
		{name: "oracle tns alias", protocol: "oracle-tns", file: "oracle.txt", wantName: "oracle"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tt.file), []byte("user : pass\n"), 0o600); err != nil {
				t.Fatalf("write dict: %v", err)
			}

			got, desc, err := LoadDirectorySource(tt.protocol, dir)
			if err != nil {
				t.Fatalf("LoadDirectorySource() error = %v", err)
			}
			wantCreds := []strategy.Credential{{Username: "user", Password: "pass"}}
			if !reflect.DeepEqual(got, wantCreds) {
				t.Fatalf("LoadDirectorySource() creds = %v, want %v", got, wantCreds)
			}
			if desc.Name != tt.wantName {
				t.Fatalf("LoadDirectorySource() desc = %+v, want name %q", desc, tt.wantName)
			}
		})
	}
}

func TestLoadBuiltinSourceSupportsAliasCandidates(t *testing.T) {
	tests := []struct {
		name         string
		protocol     string
		wantAttempts []string
	}{
		{name: "redis tls alias", protocol: "redis/tls", wantAttempts: []string{"redis"}},
		{name: "redis ssl alias", protocol: "redis/ssl", wantAttempts: []string{"redis"}},
		{name: "mongo alias", protocol: "mongo", wantAttempts: []string{"mongodb"}},
		{name: "oracle tns alias", protocol: "oracle-tns", wantAttempts: []string{"oracle"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts []string
			restore := stubBuiltinLoader(func(protocol string) ([]strategy.Credential, error) {
				attempts = append(attempts, protocol)
				return []strategy.Credential{{Username: "builtin", Password: "cred"}}, nil
			})
			defer restore()

			got, desc, err := LoadBuiltinSource(tt.protocol)
			if err != nil {
				t.Fatalf("LoadBuiltinSource() error = %v", err)
			}
			wantCreds := []strategy.Credential{{Username: "builtin", Password: "cred"}}
			if !reflect.DeepEqual(got, wantCreds) {
				t.Fatalf("LoadBuiltinSource() = %v, want %v", got, wantCreds)
			}
			if !reflect.DeepEqual(attempts, tt.wantAttempts) {
				t.Fatalf("builtin attempts = %v, want %v", attempts, tt.wantAttempts)
			}
			if desc.Name != tt.wantAttempts[0] {
				t.Fatalf("LoadBuiltinSource() desc = %+v, want name %q", desc, tt.wantAttempts[0])
			}
		})
	}
}
