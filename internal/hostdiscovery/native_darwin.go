//go:build darwin

package hostdiscovery

import (
	"context"
	"fmt"
	"net"
)

func newTCPSYNRunner(Options) Runner { return darwinUnsupportedRunner("tcp-syn") }

func newTCPACKRunner(Options) Runner { return darwinUnsupportedRunner("tcp-ack") }

func newARPRunner(Options) Runner { return darwinUnsupportedRunner("arp") }

func darwinUnsupportedRunner(mode string) Runner {
	return RunnerFunc(func(_ context.Context, ip string) (Result, error) {
		family := "IPv4"
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
			family = "IPv6"
		}
		return Result{}, fmt.Errorf("%w: mode %s: %s is not implemented on darwin", ErrModeUnavailable, mode, family)
	})
}
