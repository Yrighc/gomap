package credentials

import (
	"os"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestGeneratorKeepsInlineCredentialsLiteralWithoutExpansion(t *testing.T) {
	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultUsers:       []string{""},
			PasswordSource:     "builtin:passwords/global",
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
		Inline: []strategy.Credential{
			{Username: "admin", Password: "admin"},
			{Username: "admin", Password: "admin"},
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{{Username: "admin", Password: "admin"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %v, want %v", got, want)
	}
	if meta.Source.Kind != SourceInline {
		t.Fatalf("Generate() source = %+v, want inline", meta.Source)
	}
}

func TestGeneratorBuildsCredentialsFromSharedPasswordsExtraPasswordsAndPairs(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(source string) ([]credentialEntry, error) {
		if source != "builtin:passwords/global" {
			t.Fatalf("source = %q, want builtin:passwords/global", source)
		}
		return []credentialEntry{
			{Tier: TierTop, Credential: strategy.Credential{Password: "123456"}},
			{Tier: TierCommon, Credential: strategy.Credential{Password: "{user}123"}},
			{Tier: TierExtended, Credential: strategy.Credential{Password: "Passw0rd"}},
		}, nil
	})
	defer restore()

	gen := Generator{}
	got, meta, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:           "redis",
			DefaultUsers:       []string{""},
			PasswordSource:     "builtin:passwords/global",
			ExtraPasswords:     []string{"redis"},
			DefaultPairs:       []CredentialPair{{Username: "default", Password: "default"}},
			DefaultTiers:       []Tier{TierTop, TierCommon},
			ScanProfile:        ScanProfileDefault,
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{
		{Username: "", Password: "123456"},
		{Username: "", Password: "123"},
		{Username: "", Password: "redis"},
		{Username: "", Password: ""},
		{Username: "default", Password: "default"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %#v, want %#v", got, want)
	}
	if meta.Source.Kind != SourceBuiltin || meta.Source.Name != "builtin:passwords/global" {
		t.Fatalf("Generate() source = %+v", meta.Source)
	}
	if !reflect.DeepEqual(meta.SelectedTiers, []Tier{TierTop, TierCommon}) {
		t.Fatalf("Generate() selected tiers = %v, want [top common]", meta.SelectedTiers)
	}
}

func TestGeneratorAppliesUsernamePasswordTemplates(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{
			{Tier: TierTop, Credential: strategy.Credential{Password: "{user}"}},
			{Tier: TierTop, Credential: strategy.Credential{Password: "{user}@123"}},
		}, nil
	})
	defer restore()

	gen := Generator{}
	got, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:       "ssh",
			DefaultUsers:   []string{"root", "admin"},
			PasswordSource: "builtin:passwords/global",
			DefaultTiers:   []Tier{TierTop},
			ScanProfile:    ScanProfileFast,
		},
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root@123"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "admin@123"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %v, want %v", got, want)
	}
}

func TestGeneratorReturnsMissingWhenPasswordSourceFiltersToEmpty(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{{Tier: TierExtended, Credential: strategy.Credential{Password: "extended"}}}, nil
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:       "ssh",
			DefaultUsers:   []string{"root"},
			PasswordSource: "builtin:passwords/global",
			DefaultTiers:   []Tier{TierTop},
			ScanProfile:    ScanProfileFast,
		},
	})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestGeneratorReturnsSourceErrorWhenBuiltinFails(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return nil, os.ErrNotExist
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:       "missing",
			DefaultUsers:   []string{"root"},
			PasswordSource: "builtin:passwords/missing",
			DefaultTiers:   []Tier{TierTop},
		},
	})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestGeneratorRequiresExplicitPasswordSource(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{{Tier: TierTop, Credential: strategy.Credential{Password: "should-not-load"}}}, nil
	})
	defer restore()

	gen := Generator{}
	_, _, err := gen.Generate(GenerateInput{
		Profile: CredentialProfile{
			Protocol:     "ssh",
			DefaultUsers: []string{"root"},
			DefaultTiers: []Tier{TierTop},
		},
	})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestGeneratorKeepsExplicitEmptyDefaultPairs(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{{Tier: TierTop, Credential: strategy.Credential{Password: "redis"}}}, nil
	})
	defer restore()

	gen := Generator{}
	got, _, err := gen.Generate(GenerateInput{
		Profile: ProfileFromDictionary("redis", DictionaryProfileInput{
			DefaultUsers:       []string{""},
			PasswordSource:     "builtin:passwords/global",
			DefaultPairs:       []CredentialPair{{Username: "", Password: "default"}, {Username: "root", Password: ""}},
			DefaultTiers:       []string{"top"},
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		}),
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	want := []strategy.Credential{
		{Username: "", Password: "redis"},
		{Username: "", Password: ""},
		{Username: "", Password: "default"},
		{Username: "root", Password: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Generate() creds = %#v, want %#v", got, want)
	}
}
