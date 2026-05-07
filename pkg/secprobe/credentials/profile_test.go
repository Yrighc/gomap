package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/metadata"
)

func TestProfileFromMetadataUsesExplicitDefaultTiers(t *testing.T) {
	spec := metadata.Spec{
		Name: "ssh",
		Dictionary: metadata.Dictionary{
			DefaultSources:     []string{"ssh"},
			DefaultTiers:       []string{" Top ", "COMMON", "top", ""},
			AllowEmptyUsername: false,
			AllowEmptyPassword: true,
			ExpansionProfile:   "user_password_basic",
		},
	}

	got := ProfileFromMetadata(spec)
	want := CredentialProfile{
		Protocol: "ssh",
		Scan: ScanProfile{
			Sources:        []string{"ssh"},
			Tiers:          []Tier{TierTop, TierCommon},
			Expansion:      "user_password_basic",
			AllowEmptyUser: false,
			AllowEmptyPass: true,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ProfileFromMetadata() = %#v, want %#v", got, want)
	}
}

func TestProfileFromMetadataFallsBackToTopCommonDefaultTiers(t *testing.T) {
	spec := metadata.Spec{
		Name: "redis",
		Dictionary: metadata.Dictionary{
			DefaultSources:     []string{"redis"},
			AllowEmptyUsername: true,
			AllowEmptyPassword: true,
			ExpansionProfile:   "static_basic",
		},
	}

	got := ProfileFromMetadata(spec)
	wantTiers := []Tier{TierTop, TierCommon}
	if !reflect.DeepEqual(got.Scan.Tiers, wantTiers) {
		t.Fatalf("ProfileFromMetadata() tiers = %v, want %v", got.Scan.Tiers, wantTiers)
	}
}
