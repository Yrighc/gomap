package credentials

import (
	"reflect"
	"testing"
)

func TestResolveTiersUsesProfileIntersection(t *testing.T) {
	got := ResolveTiers(CredentialProfile{
		DefaultTiers: []Tier{TierTop, TierCommon, TierExtended},
		ScanProfile:  ScanProfileFast,
	})
	want := []Tier{TierTop}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveTiers() = %v, want %v", got, want)
	}
}

func TestResolveTiersKeepsDefaultOrderWithinIntersection(t *testing.T) {
	got := ResolveTiers(CredentialProfile{
		DefaultTiers: []Tier{TierExtended, TierTop, TierCommon},
		ScanProfile:  ScanProfileDefault,
	})
	want := []Tier{TierTop, TierCommon}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveTiers() = %v, want %v", got, want)
	}
}

func TestResolveTiersReturnsEmptyWhenFastAndExtendedOnlyDoNotIntersect(t *testing.T) {
	got := ResolveTiers(CredentialProfile{
		DefaultTiers: []Tier{TierExtended},
		ScanProfile:  ScanProfileFast,
	})
	want := []Tier{}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveTiers() = %v, want %v", got, want)
	}
}

func TestResolveTiersReturnsEmptyWhenDefaultAndExtendedOnlyDoNotIntersect(t *testing.T) {
	got := ResolveTiers(CredentialProfile{
		DefaultTiers: []Tier{TierExtended},
		ScanProfile:  ScanProfileDefault,
	})
	want := []Tier{}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveTiers() = %v, want %v", got, want)
	}
}

func TestNormalizeScanProfileDefaultsToDefault(t *testing.T) {
	if got := normalizeScanProfile(" "); got != ScanProfileDefault {
		t.Fatalf("normalizeScanProfile() = %q, want %q", got, ScanProfileDefault)
	}
}
