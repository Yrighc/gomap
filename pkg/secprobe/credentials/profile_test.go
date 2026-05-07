package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestProfileFromMetadataUsesExplicitDefaultTiers(t *testing.T) {
	dict := metadata.Dictionary{
		DefaultSources:     []string{"ssh"},
		DefaultTiers:       []string{" Top ", "COMMON", "top", "extended", ""},
		AllowEmptyUsername: false,
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	}

	got := ProfileFromMetadata("ssh", dict)
	want := CredentialProfile{
		Protocol:           "ssh",
		DefaultSources:     []string{"ssh"},
		DefaultTiers:       []Tier{TierTop, TierCommon, TierExtended},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: false,
		AllowEmptyPassword: true,
		ExpansionProfile:   "user_password_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromMetadata() = %#v, want %#v", got, want)
	}
}

func TestProfileFromMetadataFallsBackToTopCommonDefaultTiers(t *testing.T) {
	dict := metadata.Dictionary{
		DefaultSources:     []string{"redis"},
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	got := ProfileFromMetadata("redis", dict)
	want := CredentialProfile{
		Protocol:           "redis",
		DefaultSources:     []string{"redis"},
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: true,
		AllowEmptyPassword: true,
		ExpansionProfile:   "static_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromMetadata() = %#v, want %#v", got, want)
	}
}

func TestProfileFromMetadataFallsBackWhenDefaultTiersNormalizeToEmpty(t *testing.T) {
	dict := metadata.Dictionary{
		DefaultSources:     []string{"mqtt"},
		DefaultTiers:       []string{" ", "\t", ""},
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "static_basic",
	}

	got := ProfileFromMetadata(" MQTT ", dict)
	want := CredentialProfile{
		Protocol:           "mqtt",
		DefaultSources:     []string{"mqtt"},
		DefaultTiers:       []Tier{TierTop, TierCommon},
		ScanProfile:        ScanProfileDefault,
		AllowEmptyUsername: false,
		AllowEmptyPassword: false,
		ExpansionProfile:   "static_basic",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromMetadata() = %#v, want %#v", got, want)
	}
}
