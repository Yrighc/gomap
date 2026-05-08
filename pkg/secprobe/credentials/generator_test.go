package credentials

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestGeneratorUsesInlineBeforeDirectoryAndBuiltin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh.txt"), []byte("root : root\n"), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}

	builtinCalled := false
	restore := stubBuiltinLoader(func(string) ([]strategy.Credential, error) {
		builtinCalled = true
		return []strategy.Credential{{Username: "builtin", Password: "builtin"}}, nil
	})
	defer restore()

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:         "ssh",
			DefaultSources:   []string{"ssh"},
			DefaultTiers:     []Tier{TierTop, TierCommon},
			ScanProfile:      ScanProfileFull,
			ExpansionProfile: "none",
		},
		DictDir: dir,
		Inline: []strategy.Credential{
			{Username: "inline", Password: "secret"},
			{Username: "inline", Password: "secret"},
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wantCreds := []strategy.Credential{{Username: "inline", Password: "secret"}}
	if !reflect.DeepEqual(got, wantCreds) {
		t.Fatalf("Generate() creds = %v, want %v", got, wantCreds)
	}
	if meta.Source.Kind != SourceInline {
		t.Fatalf("Generate() source = %+v, want inline", meta.Source)
	}
	if builtinCalled {
		t.Fatal("expected builtin loader to stay unused when inline credentials exist")
	}
}

func TestGeneratorUsesDirectoryBeforeBuiltin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "redis.txt"), []byte("default : password\n"), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}

	builtinCalled := false
	restore := stubBuiltinLoader(func(string) ([]strategy.Credential, error) {
		builtinCalled = true
		return []strategy.Credential{{Username: "builtin", Password: "builtin"}}, nil
	})
	defer restore()

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultSources:     []string{"redis"},
			DefaultTiers:       []Tier{TierTop, TierCommon},
			ScanProfile:        ScanProfileDefault,
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "none",
		},
		DictDir: dir,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wantCreds := []strategy.Credential{{Username: "default", Password: "password"}}
	if !reflect.DeepEqual(got, wantCreds) {
		t.Fatalf("Generate() creds = %v, want %v", got, wantCreds)
	}
	if meta.Source.Kind != SourceDictDir || meta.Source.Name != "redis" {
		t.Fatalf("Generate() source = %+v", meta.Source)
	}
	if builtinCalled {
		t.Fatal("expected builtin loader to stay unused when dict_dir hit exists")
	}
}

func TestGeneratorTreatsWhitespaceDictDirAsExplicitDirectoryInput(t *testing.T) {
	builtinCalled := false
	restore := stubBuiltinLoader(func(string) ([]strategy.Credential, error) {
		builtinCalled = true
		return []strategy.Credential{{Username: "builtin", Password: "builtin"}}, nil
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:         "redis",
			DefaultSources:   []string{"redis"},
			DefaultTiers:     []Tier{TierTop, TierCommon},
			ScanProfile:      ScanProfileDefault,
			ExpansionProfile: "none",
		},
		DictDir: "   ",
	})
	if err == nil {
		t.Fatal("expected Generate() error when whitespace dict_dir is explicitly provided")
	}
	if !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
	if builtinCalled {
		t.Fatal("expected builtin loader to stay unused when whitespace dict_dir is explicit")
	}
}

func TestGeneratorFiltersTierTaggedEntriesByScanProfile(t *testing.T) {
	dir := t.TempDir()
	data := "[top] root : root\n[common] admin : admin\n[extended] guest : guest\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh.txt"), []byte(data), 0o600); err != nil {
		t.Fatalf("write dict: %v", err)
	}

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:         "ssh",
			DefaultSources:   []string{"ssh"},
			DefaultTiers:     []Tier{TierTop, TierCommon, TierExtended},
			ScanProfile:      ScanProfileDefault,
			ExpansionProfile: "none",
		},
		DictDir: dir,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wantCreds := []strategy.Credential{
		{Username: "root", Password: "root"},
		{Username: "admin", Password: "admin"},
	}
	if !reflect.DeepEqual(got, wantCreds) {
		t.Fatalf("Generate() creds = %v, want %v", got, wantCreds)
	}
	if !reflect.DeepEqual(meta.SelectedTiers, []Tier{TierTop, TierCommon}) {
		t.Fatalf("Generate() selected tiers = %v, want [top common]", meta.SelectedTiers)
	}
}

func TestGeneratorFallsBackToBuiltinAndExpands(t *testing.T) {
	restore := stubBuiltinLoader(func(protocol string) ([]strategy.Credential, error) {
		if protocol != "redis" {
			t.Fatalf("protocol = %q, want %q", protocol, "redis")
		}
		return []strategy.Credential{
			{Username: "redis", Password: "redis"},
			{Username: "admin", Password: "admin"},
		}, nil
	})
	defer restore()

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultSources:     []string{"redis"},
			DefaultTiers:       []Tier{TierTop, TierCommon, TierExtended},
			ScanProfile:        ScanProfileFast,
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	wantCreds := []strategy.Credential{
		{Username: "redis", Password: "redis"},
		{Username: "admin", Password: "admin"},
		{Username: "redis", Password: "redis123"},
		{Username: "redis", Password: "redis@123"},
		{Username: "", Password: "redis"},
		{Username: "redis", Password: ""},
		{Username: "admin", Password: "admin123"},
		{Username: "admin", Password: "admin@123"},
		{Username: "", Password: "admin"},
		{Username: "admin", Password: ""},
	}
	if !reflect.DeepEqual(got, wantCreds) {
		t.Fatalf("Generate() creds = %v, want %v", got, wantCreds)
	}
	if meta.Source.Kind != SourceBuiltin {
		t.Fatalf("Generate() source = %+v, want builtin", meta.Source)
	}
	if !reflect.DeepEqual(meta.SelectedTiers, []Tier{TierTop}) {
		t.Fatalf("Generate() selected tiers = %v, want [top]", meta.SelectedTiers)
	}
}

func TestGeneratorReturnsSourceErrorWhenBuiltinFallbackFails(t *testing.T) {
	restore := stubBuiltinLoader(func(string) ([]strategy.Credential, error) {
		return nil, os.ErrNotExist
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:         "missing",
			DefaultSources:   []string{"missing"},
			DefaultTiers:     []Tier{TierTop},
			ExpansionProfile: "none",
		},
	})
	if err == nil {
		t.Fatal("expected Generate() error")
	}
}

func TestGeneratorReturnsMissingDictDirErrorWithoutBuiltinFallback(t *testing.T) {
	builtinCalled := false
	restore := stubBuiltinLoader(func(string) ([]strategy.Credential, error) {
		builtinCalled = true
		return []strategy.Credential{{Username: "builtin", Password: "builtin"}}, nil
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:         "redis",
			DefaultSources:   []string{"redis"},
			DefaultTiers:     []Tier{TierTop, TierCommon},
			ScanProfile:      ScanProfileDefault,
			ExpansionProfile: "none",
		},
		DictDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected Generate() error when explicit dict_dir has no matching dictionary")
	}
	if !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
	if builtinCalled {
		t.Fatal("expected builtin loader to stay unused when explicit dict_dir misses")
	}
}
