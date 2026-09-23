//go:build linux || darwin

package hostdiscovery

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const icmpNonceSize = 16

type icmpPacketConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	Close() error
}

var (
	listenICMPPacket = func(network, address string) (icmpPacketConn, error) {
		return icmp.ListenPacket(network, address)
	}
	readICMPRandom = rand.Read
	icmpGOOS       = runtime.GOOS
)

type nativeICMPRunner struct {
	opts Options
}

func newICMPEchoRunner(opts Options) Runner {
	return &nativeICMPRunner{opts: opts}
}

// Run sends exactly one native Echo Request. It falls back from a ping socket
// to a raw socket only when opening the first backend proves it unavailable.
func (r *nativeICMPRunner) Run(ctx context.Context, target string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return Result{}, fmt.Errorf("%w: invalid ICMP target %q", ErrInvalidOptions, target)
	}
	if ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return Result{}, fmt.Errorf("%w: icmp-echo: link-local IPv6 target requires an interface zone", ErrModeUnavailable)
	}

	timeout := r.opts.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	deadline := time.Now().Add(timeout)
	conn, backend, err := openNativeICMP(ip)
	if err != nil {
		return Result{}, err
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !time.Now().Before(deadline) {
		return Result{}, fmt.Errorf("%w: icmp-echo preparation exceeded timeout", ErrProbeFailed)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("%w: icmp-echo set deadline: %w", ErrProbeFailed, err)
	}
	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(ctx, func() {
		defer close(closeDone)
		_ = conn.Close()
	})
	defer func() {
		if !stopClose() {
			<-closeDone
		}
	}()

	probe, message, destination, err := buildICMPRequest(ip, backend, conn.LocalAddr())
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	written, err := conn.WriteTo(message, destination)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		return Result{}, classifyNativeICMPIOError("write", err)
	}
	if written != len(message) {
		return Result{}, fmt.Errorf("%w: icmp-echo short write: wrote %d of %d bytes", ErrProbeFailed, written, len(message))
	}

	buffer := make([]byte, 64*1024)
	for {
		n, source, readErr := conn.ReadFrom(buffer)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if readErr != nil {
			if isNetworkTimeout(readErr) || errors.Is(readErr, os.ErrDeadlineExceeded) {
				return Result{}, nil
			}
			return Result{}, classifyNativeICMPIOError("read", readErr)
		}
		if n <= 0 || n > len(buffer) {
			continue
		}
		sourceIP := addrIP(source)
		if sourceIP == nil {
			continue
		}
		if matchICMPEchoReply(icmpReply{source: sourceIP, target: ip, proto: probe.proto, packet: buffer[:n]}, probe) {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			return Result{Matched: true, Method: "icmp-echo"}, nil
		}
	}
}

type icmpBackend struct {
	raw bool
}

// openNativeICMP prefers an unprivileged ping socket and falls back to a raw
// socket only for capability errors encountered before any packet is sent.
func openNativeICMP(ip net.IP) (icmpPacketConn, icmpBackend, error) {
	ipv6Target := ip.To4() == nil
	wildcard := "0.0.0.0"
	datagramNetwork := "udp4"
	rawNetwork := "ip4:icmp"
	if ipv6Target {
		wildcard = "::"
		datagramNetwork = "udp6"
		rawNetwork = "ip6:ipv6-icmp"
	}
	conn, err := listenICMPPacket(datagramNetwork, wildcard)
	if err == nil {
		return conn, icmpBackend{}, nil
	}
	if !isNativeCapabilityError(err) {
		return nil, icmpBackend{}, fmt.Errorf("%w: icmp-echo open %s: %w", ErrProbeFailed, datagramNetwork, err)
	}

	rawConn, rawErr := listenICMPPacket(rawNetwork, wildcard)
	if rawErr == nil {
		return rawConn, icmpBackend{raw: true}, nil
	}
	if isNativeCapabilityError(rawErr) {
		return nil, icmpBackend{}, fmt.Errorf("%w: icmp-echo unavailable (%s: %v; %s: %v)", ErrModeUnavailable, datagramNetwork, err, rawNetwork, rawErr)
	}
	return nil, icmpBackend{}, fmt.Errorf("%w: icmp-echo open %s after %s unavailable: %w", ErrProbeFailed, rawNetwork, datagramNetwork, rawErr)
}

func buildICMPRequest(ip net.IP, backend icmpBackend, local net.Addr) (icmpProbe, []byte, net.Addr, error) {
	random := make([]byte, icmpNonceSize+4)
	if _, err := readICMPRandom(random); err != nil {
		return icmpProbe{}, nil, nil, fmt.Errorf("%w: icmp-echo random token: %w", ErrProbeFailed, err)
	}
	id := int(uint16(random[16])<<8 | uint16(random[17]))
	seq := int(uint16(random[18])<<8 | uint16(random[19]))
	if id == 0 {
		id = 1
	}
	if icmpGOOS == "linux" && !backend.raw {
		udpAddr, ok := local.(*net.UDPAddr)
		if !ok || udpAddr.Port < 1 || udpAddr.Port > 65535 {
			return icmpProbe{}, nil, nil, fmt.Errorf("%w: icmp-echo cannot determine ping socket identifier", ErrProbeFailed)
		}
		id = udpAddr.Port
	}

	proto := 1
	requestType := icmp.Type(ipv4.ICMPTypeEcho)
	var destination net.Addr = &net.IPAddr{IP: ip}
	if ip.To4() == nil {
		proto = 58
		requestType = ipv6.ICMPTypeEchoRequest
	}
	if !backend.raw {
		destination = &net.UDPAddr{IP: ip}
	}
	probe := icmpProbe{id: id, seq: seq, nonce: append([]byte(nil), random[:icmpNonceSize]...), proto: proto}
	message, err := (&icmp.Message{
		Type: requestType,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: probe.nonce},
	}).Marshal(nil)
	if err != nil {
		return icmpProbe{}, nil, nil, fmt.Errorf("%w: icmp-echo encode request: %w", ErrProbeFailed, err)
	}
	return probe, message, destination, nil
}

func addrIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP
	case *net.UDPAddr:
		return value.IP
	default:
		return nil
	}
}

func classifyNativeICMPIOError(operation string, err error) error {
	if isNativeCapabilityError(err) {
		return fmt.Errorf("%w: icmp-echo %s unavailable: %w", ErrModeUnavailable, operation, err)
	}
	// A write-side unreachable means no request was transmitted. A read-side
	// unreachable may instead report a response after a successful send.
	if operation == "write" && (errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)) {
		return fmt.Errorf("%w: icmp-echo %s: %w", ErrProbeFailed, operation, err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return nil
	}
	return fmt.Errorf("%w: icmp-echo %s: %w", ErrProbeFailed, operation, err)
}
