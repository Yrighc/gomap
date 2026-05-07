package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

func TestExpandStaticBasic(t *testing.T) {
	base := []strategy.Credential{
		{Username: "admin", Password: "secret"},
		{Username: "guest", Password: "guest"},
	}

	got := Expand(base, Options{Profile: "static_basic"})
	want := []strategy.Credential{
		{Username: "admin", Password: "secret"},
		{Username: "guest", Password: "guest"},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "admin123"},
		{Username: "admin", Password: "admin@123"},
		{Username: "guest", Password: "guest123"},
		{Username: "guest", Password: "guest@123"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}

func TestExpandAllowsEmptyUserAndPassword(t *testing.T) {
	base := []strategy.Credential{
		{Username: "redis", Password: "redis"},
	}

	got := Expand(base, Options{
		Profile:        "static_basic",
		AllowEmptyUser: true,
		AllowEmptyPass: true,
	})
	want := []strategy.Credential{
		{Username: "redis", Password: "redis"},
		{Username: "redis", Password: "redis123"},
		{Username: "redis", Password: "redis@123"},
		{Username: "", Password: "redis"},
		{Username: "redis", Password: ""},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}

func TestExpandDedupesStably(t *testing.T) {
	base := []strategy.Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root123"},
		{Username: "root", Password: ""},
	}

	got := Expand(base, Options{
		Profile:        "static_basic",
		AllowEmptyPass: true,
	})
	want := []strategy.Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root123"},
		{Username: "root", Password: ""},
		{Username: "root", Password: "root@123"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}

func TestExpandWithoutStaticBasicOnlyDedupes(t *testing.T) {
	base := []strategy.Credential{
		{Username: "snmp", Password: "public"},
		{Username: "snmp", Password: "public"},
	}

	got := Expand(base, Options{
		Profile:        "none",
		AllowEmptyUser: true,
		AllowEmptyPass: true,
	})
	want := []strategy.Credential{
		{Username: "snmp", Password: "public"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}

func TestExpandEmptyBaseReturnsNil(t *testing.T) {
	got := Expand(nil, Options{Profile: "static_basic"})
	if got != nil {
		t.Fatalf("Expand() = %+v, want nil", got)
	}
}

func TestExpandStaticBasicSkipsUsernameDerivedVariantsForEmptyUsername(t *testing.T) {
	base := []strategy.Credential{
		{Username: "", Password: "nopass"},
		{Username: "admin", Password: "secret"},
	}

	got := Expand(base, Options{
		Profile:        " static_basic ",
		AllowEmptyUser: true,
		AllowEmptyPass: true,
	})
	want := []strategy.Credential{
		{Username: "", Password: "nopass"},
		{Username: "admin", Password: "secret"},
		{Username: "", Password: ""},
		{Username: "admin", Password: "admin"},
		{Username: "admin", Password: "admin123"},
		{Username: "admin", Password: "admin@123"},
		{Username: "", Password: "secret"},
		{Username: "admin", Password: ""},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}
