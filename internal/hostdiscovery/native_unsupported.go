//go:build !linux && !darwin

package hostdiscovery

import (
	"context"
	"fmt"
	"net"
)

func newICMPEchoRunner(Options) Runner {
	return unavailableRunner("icmp-echo", "native ICMP is not implemented on this platform")
}

func newTCPSYNRunner(Options) Runner { return unsupportedNativeRunner("tcp-syn") }

func newTCPACKRunner(Options) Runner { return unsupportedNativeRunner("tcp-ack") }

func newARPRunner(Options) Runner { return unsupportedNativeRunner("arp") }

func unsupportedNativeRunner(mode string) Runner {
	return RunnerFunc(func(_ context.Context, ip string) (Result, error) {
		family := "IPv4"
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
			family = "IPv6"
		}
		return Result{}, fmt.Errorf("%w: mode %s: %s is not implemented on this platform", ErrModeUnavailable, mode, family)
	})
}
