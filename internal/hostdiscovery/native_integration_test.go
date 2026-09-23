//go:build linux || darwin

package hostdiscovery

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNativeICMPIntegration(t *testing.T) {
	requireNativeIntegration(t)
	for _, test := range []struct {
		name string
		env  string
	}{
		{name: "ipv4", env: "GOMAP_HOSTDISCOVERY_ICMP4_TARGET"},
		{name: "ipv6", env: "GOMAP_HOSTDISCOVERY_ICMP6_TARGET"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := requiredIntegrationEnv(t, test.env)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, target, Options{Modes: []string{"icmp-echo"}, Timeout: 2 * time.Second, Retries: 1})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Matched || result.Method != "icmp-echo" {
				t.Fatalf("native ICMP did not match: %#v", result)
			}
		})
	}
}

func requireNativeIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("GOMAP_HOSTDISCOVERY_INTEGRATION") != "1" {
		t.Skip("set GOMAP_HOSTDISCOVERY_INTEGRATION=1 with explicit isolated-network targets")
	}
}

func requiredIntegrationEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when GOMAP_HOSTDISCOVERY_INTEGRATION=1", name)
	}
	return value
}
