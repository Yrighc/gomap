package metadata

import (
	"maps"
	"slices"
	"testing"
)

func TestLoadSpecsIncludesRedisAndSSHAliases(t *testing.T) {
	specs, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin() error = %v", err)
	}

	redis, ok := specs["redis"]
	if !ok {
		keys := slices.Sorted(maps.Keys(specs))
		t.Fatalf("expected redis spec, got keys %v", keys)
	}
	if redis.PolicyTags.LockoutRisk != "low" {
		t.Fatalf("expected redis lockout risk low, got %+v", redis.PolicyTags)
	}
	if !slices.Equal(redis.Aliases, []string{"redis/ssl", "redis/tls"}) {
		t.Fatalf("expected redis aliases %v, got %v", []string{"redis/ssl", "redis/tls"}, redis.Aliases)
	}
	if !slices.Equal(redis.Ports, []int{6379}) {
		t.Fatalf("expected redis port 6379, got %v", redis.Ports)
	}

	ssh, ok := specs["ssh"]
	if !ok {
		keys := slices.Sorted(maps.Keys(specs))
		t.Fatalf("expected ssh spec, got keys %v", keys)
	}
	if len(ssh.Ports) != 1 || ssh.Ports[0] != 22 {
		t.Fatalf("expected ssh port 22, got %+v", ssh.Ports)
	}
	if len(ssh.Aliases) != 0 {
		t.Fatalf("expected ssh aliases empty, got %+v", ssh.Aliases)
	}
}
