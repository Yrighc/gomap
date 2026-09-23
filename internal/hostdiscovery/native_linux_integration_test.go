//go:build linux

package hostdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNoRouteIntegrationRejectsActiveExternalInterfaces(t *testing.T) {
	for _, test := range []struct {
		name   string
		ifaces []net.Interface
		want   bool
	}{
		{name: "empty", want: false},
		{name: "loopback only", ifaces: []net.Interface{{Name: "lo", Flags: net.FlagLoopback}}, want: true},
		{name: "down kernel tunnel", ifaces: []net.Interface{{Name: "lo", Flags: net.FlagLoopback | net.FlagUp}, {Name: "tunl0"}}, want: true},
		{name: "no loopback", ifaces: []net.Interface{{Name: "tunl0"}}, want: false},
		{name: "host or container interface", ifaces: []net.Interface{{Name: "lo", Flags: net.FlagLoopback}, {Name: "eth0", Flags: net.FlagUp}}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := noRouteIntegrationHasOnlyActiveLoopback(test.ifaces); got != test.want {
				t.Fatalf("only active loopback=%v, want %v", got, test.want)
			}
		})
	}
}

// noRouteIntegrationHasOnlyActiveLoopback prevents opt-in no-route tests from
// probing through an active external interface, including one reached through
// policy routing not shown in /proc/net/route. Linux may add a DOWN tunl0 to
// otherwise isolated namespaces; an inactive interface cannot carry packets.
func noRouteIntegrationHasOnlyActiveLoopback(ifaces []net.Interface) bool {
	hasLoopback := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			hasLoopback = true
			continue
		}
		if iface.Flags&(net.FlagUp|net.FlagRunning) != 0 {
			return false
		}
	}
	return hasLoopback
}

// TestNativeLinuxNoRouteIntegration requires a no-route namespace with no
// active external interfaces. It must not probe through host adapters.
func TestNativeLinuxNoRouteIntegration(t *testing.T) {
	if os.Getenv("GOMAP_HOSTDISCOVERY_NO_ROUTE_INTEGRATION") != "1" {
		t.Skip("requires an explicitly isolated no-route namespace")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("cannot verify namespace interfaces: %v", err)
	}
	if !noRouteIntegrationHasOnlyActiveLoopback(ifaces) {
		t.Fatalf("not isolated: active non-loopback interface or no loopback: %v", ifaces)
	}
	table, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(table)), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "lo" {
			t.Fatalf("not isolated: non-loopback route in /proc/net/route: %s", line)
		}
	}
	for _, mode := range []string{"auto", "icmp-echo", "tcp-syn", "tcp-connect"} {
		t.Run(mode, func(t *testing.T) {
			options := Options{Ports: []int{65000}, Timeout: 200 * time.Millisecond, Retries: 1}
			if mode != "auto" {
				options.Modes = []string{mode}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := Run(ctx, "198.51.100.1", options)
			if result.Matched || !errors.Is(err, ErrProbeFailed) || !errors.Is(err, unix.ENETUNREACH) {
				t.Fatalf("local no-route must be reported via error: result=%#v err=%v", result, err)
			}
		})
	}
}

func TestNativeLinuxTCPIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_TCP_TARGET")
	for _, test := range []struct {
		mode string
		env  string
	}{
		{mode: "tcp-syn", env: "GOMAP_HOSTDISCOVERY_SYN_PORT"},
		{mode: "tcp-ack", env: "GOMAP_HOSTDISCOVERY_ACK_PORT"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			port := requiredIntegrationPort(t, test.env)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, target, Options{Modes: []string{test.mode}, Ports: []int{port}, Timeout: 2 * time.Second, Retries: 1})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Matched || result.Method != test.mode {
				t.Fatalf("native %s did not match: %#v", test.mode, result)
			}
		})
	}
}

func TestNativeLinuxARPIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_ARP_TARGET")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Run(ctx, target, Options{Modes: []string{"arp"}, Timeout: 2 * time.Second, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched || result.Method != "arp" {
		t.Fatalf("native ARP did not match: %#v", result)
	}
}

func TestNativeLinuxSYNMatchesOpenAndClosedPortIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_TCP_TARGET")
	for _, env := range []string{"GOMAP_HOSTDISCOVERY_SYN_PORT", "GOMAP_HOSTDISCOVERY_TCP_CLOSED_PORT"} {
		t.Run(env, func(t *testing.T) {
			port := requiredIntegrationPort(t, env)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, target, Options{Modes: []string{"tcp-syn"}, Ports: []int{port}, Timeout: 2 * time.Second, Retries: 1})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Matched || result.Method != "tcp-syn" {
				t.Fatalf("native SYN did not match %s: %#v", env, result)
			}
		})
	}
}

func TestNativeLinuxNoReplyIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_NO_REPLY_TARGET")
	port := requiredIntegrationPort(t, "GOMAP_HOSTDISCOVERY_SYN_PORT")
	for _, mode := range []string{"icmp-echo", "tcp-syn"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result, err := Run(ctx, target, Options{Modes: []string{mode}, Ports: []int{port}, Timeout: 2 * time.Second, Retries: 1})
			if err != nil {
				t.Fatal(err)
			}
			if result.Matched {
				t.Fatalf("native %s unexpectedly matched no-reply target: %#v", mode, result)
			}
		})
	}
}

func TestNativeLinuxAutomaticARPIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_ARP_TARGET")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Run(ctx, target, Options{Ports: []int{80}, Timeout: 2 * time.Second, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched || result.Method != "arp" {
		t.Fatalf("automatic discovery did not use ARP for direct target: %#v", result)
	}
}

func TestNativeLinuxAutomaticRemoteIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_TCP_TARGET")
	port := requiredIntegrationPort(t, "GOMAP_HOSTDISCOVERY_SYN_PORT")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Run(ctx, target, Options{Ports: []int{port}, Timeout: 2 * time.Second, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatalf("automatic discovery did not match remote target: %#v", result)
	}
	switch result.Method {
	case "icmp-echo", "tcp-syn", "tcp-connect":
	default:
		t.Fatalf("unexpected automatic remote winner: %#v", result)
	}
}

// This scenario intentionally runs separately from raw-socket integration:
// the enabled environment must deny raw probes and make ICMP silent while the
// configured TCP port remains reachable by Connect.
func TestNativeLinuxAutomaticConnectFallbackIntegration(t *testing.T) {
	requireNativeIntegration(t)
	target := requiredIntegrationEnv(t, "GOMAP_HOSTDISCOVERY_CONNECT_FALLBACK_TARGET")
	port := requiredIntegrationPort(t, "GOMAP_HOSTDISCOVERY_CONNECT_FALLBACK_PORT")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := Run(ctx, target, Options{Ports: []int{port}, Timeout: 2 * time.Second, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched || result.Method != "tcp-connect" {
		t.Fatalf("automatic discovery did not fall back to Connect: %#v", result)
	}
}

func requiredIntegrationPort(t *testing.T, name string) int {
	t.Helper()
	value := requiredIntegrationEnv(t, name)
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("%s must be a port in 1..65535, got %q", name, value)
	}
	return port
}
