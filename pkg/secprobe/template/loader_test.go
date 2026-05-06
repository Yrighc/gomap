package template

import (
	"maps"
	"slices"
	"testing"
)

func TestLoadBuiltinUnauthorizedTemplates(t *testing.T) {
	templates, err := LoadBuiltinUnauthorized()
	if err != nil {
		t.Fatalf("LoadBuiltinUnauthorized() error = %v", err)
	}

	tpl, ok := templates["memcached"]
	if !ok {
		t.Fatalf("expected memcached template, got keys %v", slices.Sorted(maps.Keys(templates)))
	}
	if tpl.Transport != "tcp" || tpl.Request != "stats\r\n" {
		t.Fatalf("unexpected template: %+v", tpl)
	}
}
