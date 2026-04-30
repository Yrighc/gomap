package result

import "testing"

func TestParseFindingType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		want   FindingType
		wantOK bool
	}{
		{name: "snake case credential", raw: "credential_valid", want: FindingTypeCredentialValid, wantOK: true},
		{name: "hyphen case credential", raw: "credential-valid", want: FindingTypeCredentialValid, wantOK: true},
		{name: "snake case unauthorized", raw: "unauthorized_access", want: FindingTypeUnauthorizedAccess, wantOK: true},
		{name: "hyphen case unauthorized", raw: "unauthorized-access", want: FindingTypeUnauthorizedAccess, wantOK: true},
		{name: "unknown finding type", raw: "maybe", wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := ParseFindingType(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseErrorCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		want   ErrorCode
		wantOK bool
	}{
		{name: "timeout is stable across formats", raw: "timeout", want: ErrorCodeTimeout, wantOK: true},
		{name: "snake case insufficient confirmation", raw: "insufficient_confirmation", want: ErrorCodeInsufficientConfirmation, wantOK: true},
		{name: "hyphen case insufficient confirmation", raw: "insufficient-confirmation", want: ErrorCodeInsufficientConfirmation, wantOK: true},
		{name: "unknown error code", raw: "mystery", wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := ParseErrorCode(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLegacyFindingType(t *testing.T) {
	t.Parallel()

	if got := LegacyFindingType(FindingTypeCredentialValid); got != "credential-valid" {
		t.Fatalf("credential legacy = %q, want %q", got, "credential-valid")
	}
	if got := LegacyFindingType(FindingTypeUnauthorizedAccess); got != "unauthorized-access" {
		t.Fatalf("unauthorized legacy = %q, want %q", got, "unauthorized-access")
	}
}

func TestLegacyErrorCode(t *testing.T) {
	t.Parallel()

	if got := LegacyErrorCode(ErrorCodeInsufficientConfirmation); got != "insufficient-confirmation" {
		t.Fatalf("insufficient confirmation legacy = %q, want %q", got, "insufficient-confirmation")
	}
	if got := LegacyErrorCode(ErrorCodeTimeout); got != "timeout" {
		t.Fatalf("timeout legacy = %q, want %q", got, "timeout")
	}
}
