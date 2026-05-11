package credentials

import (
	"os"
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestParsePasswordEntriesSupportsTierTags(t *testing.T) {
	got, err := parsePasswordEntries("123456\n[common] {user}@123\n[extended] Passw0rd\n")
	if err != nil {
		t.Fatalf("parsePasswordEntries() error = %v", err)
	}
	want := []credentialEntry{
		{Tier: TierTop, Credential: strategy.Credential{Password: "123456"}},
		{Tier: TierCommon, Credential: strategy.Credential{Password: "{user}@123"}},
		{Tier: TierExtended, Credential: strategy.Credential{Password: "Passw0rd"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsePasswordEntries() = %#v, want %#v", got, want)
	}
}

func TestLoadBuiltinSourceNameByTiersFiltersPasswordEntries(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(source string) ([]credentialEntry, error) {
		if source != "builtin:passwords/global" {
			t.Fatalf("source = %q, want builtin:passwords/global", source)
		}
		return []credentialEntry{
			{Tier: TierTop, Credential: strategy.Credential{Password: "123456"}},
			{Tier: TierCommon, Credential: strategy.Credential{Password: "admin"}},
			{Tier: TierExtended, Credential: strategy.Credential{Password: "Passw0rd"}},
		}, nil
	})
	defer restore()

	got, desc, err := loadBuiltinSourceNameByTiers(" builtin:passwords/global ", []Tier{TierTop, TierCommon})
	if err != nil {
		t.Fatalf("loadBuiltinSourceNameByTiers() error = %v", err)
	}
	want := []strategy.Credential{
		{Password: "123456"},
		{Password: "admin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadBuiltinSourceNameByTiers() = %#v, want %#v", got, want)
	}
	if desc.Kind != SourceBuiltin || desc.Name != "builtin:passwords/global" {
		t.Fatalf("loadBuiltinSourceNameByTiers() desc = %+v", desc)
	}
}

func TestLoadBuiltinSourceNameByTiersReturnsMissingWhenFilteredOut(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return []credentialEntry{{Tier: TierExtended, Credential: strategy.Credential{Password: "extended"}}}, nil
	})
	defer restore()

	_, _, err := loadBuiltinSourceNameByTiers("builtin:passwords/global", []Tier{TierTop})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestLoadBuiltinSourceNameByTiersWrapsLoaderError(t *testing.T) {
	restore := stubBuiltinPasswordEntryLoader(func(string) ([]credentialEntry, error) {
		return nil, os.ErrNotExist
	})
	defer restore()

	_, _, err := loadBuiltinSourceNameByTiers("builtin:passwords/missing", []Tier{TierTop})
	if err == nil || !IsMissingSource(err) {
		t.Fatalf("expected missing source error, got %v", err)
	}
}
