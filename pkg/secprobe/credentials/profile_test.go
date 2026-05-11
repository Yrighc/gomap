package credentials

import (
	"reflect"
	"testing"
)

func TestProfileFromDictionaryUsesExplicitDefaultTiers(t *testing.T) {
	dict := DictionaryProfileInput{
		PasswordSource:     "ssh",
		DefaultTiers:       []string{" Top ", "COMMON", "top", "extended", ""},
		AllowEmptyUsername: false,
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	}

	got := ProfileFromDictionary("ssh", dict)
	want := CredentialProfile{
		Protocol:           "ssh",
		PasswordSource:     "ssh",
		DefaultTiers:       []Tier{TierTop, TierCommon, TierExtended},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: false,
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromDictionary() = %#v, want %#v", got, want)
	}
}

func TestProfileFromDictionaryFallsBackToTopCommonDefaultTiers(t *testing.T) {
	dict := DictionaryProfileInput{
		PasswordSource:     "redis",
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	got := ProfileFromDictionary("redis", dict)
	want := CredentialProfile{
		Protocol:           "redis",
		PasswordSource:     "redis",
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromDictionary() = %#v, want %#v", got, want)
	}
}

func TestProfileFromDictionaryFallsBackWhenDefaultTiersNormalizeToEmpty(t *testing.T) {
	dict := DictionaryProfileInput{
		PasswordSource:     "mqtt",
		DefaultTiers:       []string{" ", "\t", ""},
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "static_basic",
	}

	got := ProfileFromDictionary(" MQTT ", dict)
	want := CredentialProfile{
		Protocol:           "mqtt",
		PasswordSource:     "mqtt",
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "static_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromDictionary() = %#v, want %#v", got, want)
	}
}

func TestProfileWithScanProfileOverridesDefault(t *testing.T) {
	base := CredentialProfile{
		Protocol:           "redis",
		PasswordSource:     "redis",
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	got := base.WithScanProfile(" full ")
	want := CredentialProfile{
		Protocol:           "redis",
		PasswordSource:     "redis",
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileFull,
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WithScanProfile() = %#v, want %#v", got, want)
	}
}

func TestProfileWithScanProfileIgnoresUnknownValue(t *testing.T) {
	base := CredentialProfile{ScanProfile: ScanProfileFast}

	got := base.WithScanProfile("unexpected")
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("WithScanProfile() = %#v, want %#v", got, base)
	}
}
