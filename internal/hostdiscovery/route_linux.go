//go:build linux

package hostdiscovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const netlinkAlignment = 4

var (
	routeSequence  atomic.Uint32
	linuxSendto    = unix.Sendto
	linuxPoll      = unix.Poll
	linuxTimeNow   = time.Now
	linuxTimeUntil = time.Until
)

// linuxRTANHID is RTA_NH_ID from linux/uapi/linux/rtnetlink.h. The pinned
// x/sys version does not expose it.
const linuxRTANHID = 30

type linuxRouteInfo struct {
	ifIndex int
	source  net.IP
}

// lookupLinuxARPRoute asks the kernel for one target-specific route and accepts
// only a single, simple, on-link IPv4 unicast result suitable for ARP.
func lookupLinuxARPRoute(ctx context.Context, target net.IP, deadline time.Time) (linuxRouteInfo, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return linuxRouteInfo{}, classifyLinuxARPSystemError("open route socket", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return linuxRouteInfo{}, classifyLinuxARPSystemError("bind route socket", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return linuxRouteInfo{}, fmt.Errorf("%w: ARP read netlink port: %w", ErrProbeFailed, err)
	}
	local, ok := bound.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		return linuxRouteInfo{}, fmt.Errorf("%w: ARP received invalid netlink port", ErrProbeFailed)
	}
	sequence := routeSequence.Add(1)
	request := buildRouteRequest(target.To4(), sequence, local.Pid)
	if err := sendLinuxDatagram(ctx, deadline, fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return linuxRouteInfo{}, ctxErr
		}
		return linuxRouteInfo{}, classifyLinuxARPSystemError("send route query", err)
	}

	buffer := make([]byte, 64*1024)
	var routes []linuxRouteInfo
	multipart := false
	for {
		if err := ctx.Err(); err != nil {
			return linuxRouteInfo{}, err
		}
		if !time.Now().Before(deadline) {
			return linuxRouteInfo{}, fmt.Errorf("%w: ARP route query timed out", ErrProbeFailed)
		}
		ready, err := pollLinuxFD(ctx, fd, deadline)
		if err != nil {
			return linuxRouteInfo{}, fmt.Errorf("%w: ARP poll route socket: %w", ErrProbeFailed, err)
		}
		if !ready {
			continue
		}
		n, from, err := unix.Recvfrom(fd, buffer, 0)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return linuxRouteInfo{}, classifyLinuxARPSystemError("receive route query", err)
		}
		netlinkFrom, ok := from.(*unix.SockaddrNetlink)
		if !ok || netlinkFrom.Pid != 0 {
			return linuxRouteInfo{}, fmt.Errorf("%w: ARP route response not sent by kernel", ErrProbeFailed)
		}
		parsed, done, responseMultipart, err := parseRouteMessages(buffer[:n], sequence, local.Pid)
		if err != nil {
			return linuxRouteInfo{}, err
		}
		routes = append(routes, parsed...)
		multipart = multipart || responseMultipart
		if done || (!multipart && len(routes) > 0) {
			if len(routes) != 1 {
				return linuxRouteInfo{}, fmt.Errorf("%w: ARP route is ambiguous", ErrModeUnavailable)
			}
			return routes[0], nil
		}
	}
}

func buildRouteRequest(target net.IP, sequence, pid uint32) []byte {
	message := make([]byte, 16+12+8)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(message[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	binary.NativeEndian.PutUint32(message[12:16], pid)
	message[16] = unix.AF_INET
	message[17] = 32
	binary.NativeEndian.PutUint32(message[24:28], unix.RTM_F_LOOKUP_TABLE)
	binary.NativeEndian.PutUint16(message[28:30], 8)
	binary.NativeEndian.PutUint16(message[30:32], unix.RTA_DST)
	copy(message[32:36], target.To4())
	return message
}

// parseRouteMessages validates netlink ownership and framing before exposing
// route attributes; multipart replies remain incomplete until NLMSG_DONE.
func parseRouteMessages(buffer []byte, sequence, pid uint32) ([]linuxRouteInfo, bool, bool, error) {
	var routes []linuxRouteInfo
	multipart := false
	for len(buffer) > 0 {
		if len(buffer) < 16 {
			return nil, false, false, fmt.Errorf("%w: truncated netlink header", ErrProbeFailed)
		}
		length := int(binary.NativeEndian.Uint32(buffer[0:4]))
		if length < 16 || length > len(buffer) {
			return nil, false, false, fmt.Errorf("%w: invalid netlink message length", ErrProbeFailed)
		}
		if binary.NativeEndian.Uint32(buffer[8:12]) != sequence || binary.NativeEndian.Uint32(buffer[12:16]) != pid {
			return nil, false, false, fmt.Errorf("%w: mismatched netlink route response", ErrProbeFailed)
		}
		typeValue := binary.NativeEndian.Uint16(buffer[4:6])
		flags := binary.NativeEndian.Uint16(buffer[6:8])
		multipart = multipart || flags&unix.NLM_F_MULTI != 0
		payload := buffer[16:length]
		switch typeValue {
		case unix.NLMSG_ERROR:
			if len(payload) < 4 {
				return nil, false, false, fmt.Errorf("%w: truncated netlink error", ErrProbeFailed)
			}
			errno := int32(binary.NativeEndian.Uint32(payload[:4]))
			if errno != 0 {
				return nil, false, false, classifyLinuxARPRouteError(unix.Errno(-errno))
			}
		case unix.NLMSG_DONE:
			return routes, true, multipart, nil
		case unix.RTM_NEWROUTE:
			route, err := parseRouteMessage(payload)
			if err != nil {
				return nil, false, false, err
			}
			routes = append(routes, route)
		}
		aligned := alignNetlink(length)
		if aligned > len(buffer) {
			return nil, false, false, fmt.Errorf("%w: truncated aligned netlink message", ErrProbeFailed)
		}
		buffer = buffer[aligned:]
	}
	return routes, false, multipart, nil
}

func parseRouteMessage(payload []byte) (linuxRouteInfo, error) {
	if len(payload) < 12 {
		return linuxRouteInfo{}, fmt.Errorf("%w: truncated route message", ErrProbeFailed)
	}
	if payload[0] != unix.AF_INET || payload[7] != unix.RTN_UNICAST {
		return linuxRouteInfo{}, fmt.Errorf("%w: route is not IPv4 unicast", ErrModeUnavailable)
	}
	attributes := payload[12:]
	var route linuxRouteInfo
	for len(attributes) > 0 {
		if len(attributes) < 4 {
			return linuxRouteInfo{}, fmt.Errorf("%w: truncated route attribute", ErrProbeFailed)
		}
		length := int(binary.NativeEndian.Uint16(attributes[0:2]))
		typeValue := binary.NativeEndian.Uint16(attributes[2:4])
		if length < 4 || length > len(attributes) {
			return linuxRouteInfo{}, fmt.Errorf("%w: invalid route attribute length", ErrProbeFailed)
		}
		value := attributes[4:length]
		switch typeValue {
		case unix.RTA_OIF:
			if len(value) != 4 {
				return linuxRouteInfo{}, fmt.Errorf("%w: invalid route interface attribute", ErrProbeFailed)
			}
			route.ifIndex = int(binary.NativeEndian.Uint32(value))
		case unix.RTA_PREFSRC:
			if len(value) != 4 {
				return linuxRouteInfo{}, fmt.Errorf("%w: invalid preferred source attribute", ErrProbeFailed)
			}
			route.source = net.IPv4(value[0], value[1], value[2], value[3]).To4()
		case unix.RTA_GATEWAY, unix.RTA_VIA, unix.RTA_MULTIPATH, unix.RTA_NEWDST, unix.RTA_ENCAP, unix.RTA_ENCAP_TYPE, linuxRTANHID:
			return linuxRouteInfo{}, fmt.Errorf("%w: route is not a simple on-link route", ErrModeUnavailable)
		}
		aligned := alignNetlink(length)
		if aligned > len(attributes) {
			return linuxRouteInfo{}, fmt.Errorf("%w: truncated aligned route attribute", ErrProbeFailed)
		}
		attributes = attributes[aligned:]
	}
	if route.ifIndex <= 0 || route.source.To4() == nil {
		return linuxRouteInfo{}, fmt.Errorf("%w: route lacks interface or preferred source", ErrModeUnavailable)
	}
	return route, nil
}

func alignNetlink(length int) int {
	return (length + netlinkAlignment - 1) & ^(netlinkAlignment - 1)
}

func sendLinuxDatagram(ctx context.Context, deadline time.Time, fd int, packet []byte, flags int, address unix.Sockaddr) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !linuxTimeNow().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		err := linuxSendto(fd, packet, flags, address)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func pollLinuxFD(ctx context.Context, fd int, deadline time.Time) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		remaining := linuxTimeUntil(deadline)
		if remaining <= 0 {
			return false, nil
		}
		wait := minDuration(remaining, 50*time.Millisecond)
		milliseconds := int((wait + time.Millisecond - 1) / time.Millisecond)
		fds[0].Revents = 0
		count, err := linuxPoll(fds, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		if count == 0 {
			return false, nil
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("unexpected poll events %#x", fds[0].Revents)
		}
		return fds[0].Revents&unix.POLLIN != 0, nil
	}
}

func classifyLinuxARPRouteError(err error) error {
	if isNativeCapabilityError(err) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("%w: ARP has no usable direct route: %w", ErrModeUnavailable, err)
	}
	return fmt.Errorf("%w: ARP route query: %w", ErrProbeFailed, err)
}

func classifyLinuxARPSystemError(operation string, err error) error {
	if isNativeCapabilityError(err) {
		return fmt.Errorf("%w: ARP %s: %w", ErrModeUnavailable, operation, err)
	}
	return fmt.Errorf("%w: ARP %s: %w", ErrProbeFailed, operation, err)
}
