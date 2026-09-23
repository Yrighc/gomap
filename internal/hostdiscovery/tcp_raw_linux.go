//go:build linux

package hostdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

var dialLinuxNativeTCP = func(ctx context.Context, target string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "ip4:tcp", target)
}

type linuxNativeTCPSession struct {
	conn       net.Conn
	raw        *ipv4.RawConn
	sourceIP   net.IP
	targetIP   net.IP
	sourcePort uint16
	reserveFD  int
	timeout    time.Duration
	closeOnce  sync.Once
}

// openLinuxNativeTCPSession owns one raw IP socket and a bind-only TCP socket
// whose ephemeral port remains reserved for the entire discovery round.
func openLinuxNativeTCPSession(ctx context.Context, targetIP net.IP, timeout time.Duration) (nativeTCPSession, error) {
	prepareCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := dialLinuxNativeTCP(prepareCtx, targetIP.String())
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if prepareErr := prepareCtx.Err(); prepareErr != nil {
			return nil, fmt.Errorf("%w: native TCP preparation exceeded timeout: %v", ErrProbeFailed, prepareErr)
		}
		return nil, classifyLinuxNativeTCPOpenError("open raw socket", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = connection.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packetConnection, ok := connection.(net.PacketConn)
	if !ok {
		return nil, fmt.Errorf("%w: native TCP raw socket does not implement net.PacketConn", ErrProbeFailed)
	}
	localAddress, ok := connection.LocalAddr().(*net.IPAddr)
	if !ok || localAddress.IP.To4() == nil {
		return nil, fmt.Errorf("%w: native TCP cannot determine local IPv4 address", ErrProbeFailed)
	}
	sourceIP := append(net.IP(nil), localAddress.IP.To4()...)
	raw, err := ipv4.NewRawConn(packetConnection)
	if err != nil {
		return nil, fmt.Errorf("%w: native TCP wrap raw socket: %w", ErrProbeFailed, err)
	}
	reserveFD, sourcePort, err := reserveLinuxTCPPort(sourceIP)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Close(reserveFD)
		return nil, err
	}
	if err := prepareCtx.Err(); err != nil {
		_ = unix.Close(reserveFD)
		return nil, fmt.Errorf("%w: native TCP preparation exceeded timeout: %v", ErrProbeFailed, err)
	}
	cleanup = false
	return &linuxNativeTCPSession{
		conn: connection, raw: raw, sourceIP: sourceIP, targetIP: append(net.IP(nil), targetIP.To4()...),
		sourcePort: sourcePort, reserveFD: reserveFD, timeout: timeout,
	}, nil
}

func reserveLinuxTCPPort(sourceIP net.IP) (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, 0, classifyLinuxNativeTCPOpenError("reserve TCP source port", err)
	}
	address := &unix.SockaddrInet4{}
	copy(address.Addr[:], sourceIP.To4())
	if err := unix.Bind(fd, address); err != nil {
		_ = unix.Close(fd)
		return -1, 0, classifyLinuxNativeTCPOpenError("bind TCP source port", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("%w: native TCP read reserved source port: %w", ErrProbeFailed, err)
	}
	inet, ok := bound.(*unix.SockaddrInet4)
	if !ok || inet.Port < 1 || inet.Port > 65535 {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("%w: native TCP received invalid reserved source port", ErrProbeFailed)
	}
	return fd, uint16(inet.Port), nil
}

func (s *linuxNativeTCPSession) LocalIP() net.IP   { return s.sourceIP }
func (s *linuxNativeTCPSession) LocalPort() uint16 { return s.sourcePort }

func (s *linuxNativeTCPSession) Send(probe tcpProbe) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	flags := tcpFlagSYN
	if probe.mode == "tcp-ack" {
		flags = tcpFlagACK
	}
	packet := buildTCPPacket(s.sourceIP, s.targetIP, s.sourcePort, probe.remotePort, probe.seq, probe.ack, flags)
	header := &ipv4.Header{
		Version: ipv4.Version, Len: ipv4.HeaderLen, TotalLen: ipv4.HeaderLen + len(packet),
		TTL: 64, Protocol: unix.IPPROTO_TCP, Src: s.sourceIP, Dst: s.targetIP,
	}
	if err := s.raw.WriteTo(header, packet, nil); err != nil {
		return err
	}
	return nil
}

func (s *linuxNativeTCPSession) Receive(deadline time.Time) (nativeTCPInbound, error) {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nativeTCPInbound{}, err
	}
	buffer := make([]byte, 64*1024)
	header, payload, _, err := s.raw.ReadFrom(buffer)
	if err != nil {
		return nativeTCPInbound{}, err
	}
	if header == nil || header.Protocol != unix.IPPROTO_TCP || header.Src.To4() == nil || header.Dst.To4() == nil {
		return nativeTCPInbound{}, errNativeNoSignal
	}
	response, ok := parseTCPResponse(header.Src, header.Dst, payload)
	if !ok {
		return nativeTCPInbound{}, errNativeNoSignal
	}
	fragment := header.FragOff != 0 || header.Flags&ipv4.MoreFragments != 0
	return nativeTCPInbound{sourceIP: header.Src, targetIP: header.Dst, fragment: fragment, response: response}, nil
}

func (s *linuxNativeTCPSession) SendReset(probe tcpProbe, response tcpResponse, deadline time.Time) error {
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	reset := tcpProbe{remotePort: probe.remotePort, seq: response.ack}
	packet := buildTCPPacket(s.sourceIP, s.targetIP, s.sourcePort, reset.remotePort, reset.seq, 0, tcpFlagRST)
	header := &ipv4.Header{
		Version: ipv4.Version, Len: ipv4.HeaderLen, TotalLen: ipv4.HeaderLen + len(packet),
		TTL: 64, Protocol: unix.IPPROTO_TCP, Src: s.sourceIP, Dst: s.targetIP,
	}
	return s.raw.WriteTo(header, packet, nil)
}

func (s *linuxNativeTCPSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if s.reserveFD >= 0 {
			if err := unix.Close(s.reserveFD); err != nil && !errors.Is(err, unix.EBADF) {
				closeErr = err
			}
			s.reserveFD = -1
		}
		if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func classifyLinuxNativeTCPOpenError(operation string, err error) error {
	if isNativeCapabilityError(err) {
		return fmt.Errorf("%w: native TCP %s: %w", ErrModeUnavailable, operation, err)
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return fmt.Errorf("%w: native TCP %s: %w", ErrProbeFailed, operation, err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%w: %s: %v", errNativeNoSignal, operation, err)
	}
	return fmt.Errorf("%w: native TCP %s: %w", ErrProbeFailed, operation, err)
}
