package credentials

import (
	"reflect"
	"testing"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func TestExpandStaticBasic(t *testing.T) {
	base := []core.Credential{
		{Username: "admin", Password: "secret"},
		{Username: "guest", Password: "guest"},
	}

	got := Expand(base, Options{Profile: "static_basic"})
	want := []core.Credential{
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
	base := []core.Credential{
		{Username: "redis", Password: "redis"},
	}

	got := Expand(base, Options{
		Profile:        "static_basic",
		AllowEmptyUser: true,
		AllowEmptyPass: true,
	})
	want := []core.Credential{
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
	base := []core.Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root123"},
		{Username: "root", Password: ""},
	}

	got := Expand(base, Options{
		Profile:        "static_basic",
		AllowEmptyPass: true,
	})
	want := []core.Credential{
		{Username: "root", Password: "root"},
		{Username: "root", Password: "root123"},
		{Username: "root", Password: ""},
		{Username: "root", Password: "root@123"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}

func TestExpandWithoutProfileOnlyDedupesAndAppliesEmptyVariants(t *testing.T) {
	base := []core.Credential{
		{Username: "snmp", Password: "public"},
		{Username: "snmp", Password: "public"},
	}

	got := Expand(base, Options{AllowEmptyUser: true})
	want := []core.Credential{
		{Username: "snmp", Password: "public"},
		{Username: "", Password: "public"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Expand() = %+v, want %+v", got, want)
	}
}
