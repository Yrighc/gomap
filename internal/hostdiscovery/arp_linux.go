//go:build linux

package hostdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type linuxARPTransport interface {
	Send(context.Context, time.Time, []byte) error
	Receive(context.Context, time.Time) ([]byte, *unix.SockaddrLinklayer, error)
	Close() error
}

var (
	linuxARPRouteLookup     = lookupLinuxARPRoute
	linuxARPInterfaceLookup = validateLinuxARPInterface
	openLinuxARP            = openLinuxARPTransport
)

type linuxARPRunner struct {
	opts Options
}

func newLinuxARPRunner(opts Options) Runner { return &linuxARPRunner{opts: opts} }

// Run resolves only a kernel-confirmed on-link IPv4 target and accepts one
// fully associated ARP reply from the selected Ethernet interface.
func (r *linuxARPRunner) Run(ctx context.Context, target string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return Result{}, fmt.Errorf("%w: invalid ARP target %q", ErrInvalidOptions, target)
	}
	if targetIP.To4() == nil {
		return Result{}, fmt.Errorf("%w: mode arp supports IPv4 only", ErrModeUnavailable)
	}
	timeout := r.opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	route, err := linuxARPRouteLookup(ctx, targetIP.To4(), deadline)
	if err != nil {
		return Result{}, err
	}
	if !time.Now().Before(deadline) {
		return Result{}, fmt.Errorf("%w: ARP route preparation exceeded timeout", ErrProbeFailed)
	}
	iface, localIP, err := linuxARPInterfaceLookup(route)
	if err != nil {
		return Result{}, err
	}
	if !time.Now().Before(deadline) {
		return Result{}, fmt.Errorf("%w: ARP interface preparation exceeded timeout", ErrProbeFailed)
	}
	transport, err := openLinuxARP(iface)
	if err != nil {
		return Result{}, err
	}
	defer transport.Close()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !time.Now().Before(deadline) {
		return Result{}, fmt.Errorf("%w: ARP socket preparation exceeded timeout", ErrProbeFailed)
	}
	request := buildARPRequest(iface.HardwareAddr, localIP, targetIP)
	if err := transport.Send(ctx, deadline, request); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		return Result{}, classifyLinuxARPSystemError("send request", err)
	}

	for {
		packet, source, err := transport.Receive(ctx, deadline)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if err != nil {
			if errors.Is(err, errNativeNoSignal) || isNetworkTimeout(err) {
				return Result{}, nil
			}
			return Result{}, classifyLinuxARPSystemError("receive reply", err)
		}
		if source == nil || source.Ifindex != iface.Index || source.Hatype != unix.ARPHRD_ETHER || source.Pkttype != unix.PACKET_HOST || source.Halen != 6 || source.Protocol != htons(unix.ETH_P_ARP) {
			continue
		}
		linkSource := net.HardwareAddr(source.Addr[:6])
		if matchARPReply(packet, linkSource, iface.HardwareAddr, targetIP, localIP) {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			return Result{Matched: true, Method: "arp"}, nil
		}
	}
}

func validateLinuxARPInterface(route linuxRouteInfo) (*net.Interface, net.IP, error) {
	iface, err := net.InterfaceByIndex(route.ifIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ARP resolve interface %d: %w", ErrProbeFailed, route.ifIndex, err)
	}
	if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || len(iface.HardwareAddr) != 6 || !validUnicastHardwareAddr(iface.HardwareAddr) {
		return nil, nil, fmt.Errorf("%w: interface %s is not ARP-capable Ethernet", ErrModeUnavailable, iface.Name)
	}
	flags, err := linuxInterfaceFlags(iface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ARP inspect interface %s: %w", ErrProbeFailed, iface.Name, err)
	}
	if flags&unix.IFF_NOARP != 0 {
		return nil, nil, fmt.Errorf("%w: interface %s disables ARP", ErrModeUnavailable, iface.Name)
	}
	assigned := false
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: ARP inspect interface addresses: %w", ErrProbeFailed, err)
	}
	for _, address := range addresses {
		ip, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil && ip.Equal(route.source) {
			assigned = true
			break
		}
	}
	if !assigned {
		return nil, nil, fmt.Errorf("%w: route preferred source is not assigned to interface %s", ErrModeUnavailable, iface.Name)
	}
	return iface, append(net.IP(nil), route.source.To4()...), nil
}

func linuxInterfaceFlags(name string) (uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		return 0, err
	}
	return request.Uint16(), nil
}

type linuxARPFD struct {
	fd      int
	ifIndex int
}

func openLinuxARPTransport(iface *net.Interface) (linuxARPTransport, error) {
	protocol := htons(unix.ETH_P_ARP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(protocol))
	if err != nil {
		return nil, classifyLinuxARPSystemError("open packet socket", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: iface.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, classifyLinuxARPSystemError("bind packet socket", err)
	}
	return &linuxARPFD{fd: fd, ifIndex: iface.Index}, nil
}

func (t *linuxARPFD) Send(ctx context.Context, deadline time.Time, packet []byte) error {
	address := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: t.ifIndex, Halen: 6}
	for index := 0; index < 6; index++ {
		address.Addr[index] = 0xff
	}
	return sendLinuxDatagram(ctx, deadline, t.fd, packet, 0, address)
}

func (t *linuxARPFD) Receive(ctx context.Context, deadline time.Time) ([]byte, *unix.SockaddrLinklayer, error) {
	buffer := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !time.Now().Before(deadline) {
			return nil, nil, errNativeNoSignal
		}
		ready, err := pollLinuxFD(ctx, t.fd, deadline)
		if err != nil {
			return nil, nil, err
		}
		if !ready {
			continue
		}
		n, from, err := unix.Recvfrom(t.fd, buffer, 0)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		source, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		return append([]byte(nil), buffer[:n]...), source, nil
	}
}

func (t *linuxARPFD) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := unix.Close(t.fd)
	t.fd = -1
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
