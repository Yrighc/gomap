//go:build linux

package hostdiscovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSendLinuxDatagramRetriesEINTRWithinDeadline(t *testing.T) {
	originalSendto := linuxSendto
	originalNow := linuxTimeNow
	t.Cleanup(func() { linuxSendto = originalSendto; linuxTimeNow = originalNow })
	deadline := time.Now().Add(time.Second)
	linuxTimeNow = func() time.Time { return deadline.Add(-time.Millisecond) }
	calls := 0
	linuxSendto = func(int, []byte, int, unix.Sockaddr) error {
		calls++
		if calls == 1 {
			return unix.EINTR
		}
		return nil
	}
	if err := sendLinuxDatagram(context.Background(), deadline, 1, []byte{1}, 0, &unix.SockaddrNetlink{}); err != nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestSendLinuxDatagramEINTRCannotExtendDeadline(t *testing.T) {
	originalSendto := linuxSendto
	originalNow := linuxTimeNow
	t.Cleanup(func() { linuxSendto = originalSendto; linuxTimeNow = originalNow })
	deadline := time.Now().Add(time.Second)
	nowCalls := 0
	linuxTimeNow = func() time.Time {
		nowCalls++
		if nowCalls == 1 {
			return deadline.Add(-time.Millisecond)
		}
		return deadline
	}
	sendCalls := 0
	linuxSendto = func(int, []byte, int, unix.Sockaddr) error { sendCalls++; return unix.EINTR }
	err := sendLinuxDatagram(context.Background(), deadline, 1, []byte{1}, 0, &unix.SockaddrNetlink{})
	if !errors.Is(err, os.ErrDeadlineExceeded) || sendCalls != 1 {
		t.Fatalf("calls=%d err=%v", sendCalls, err)
	}
}

func TestPollLinuxFDEINTRCannotExtendDeadline(t *testing.T) {
	originalPoll := linuxPoll
	originalUntil := linuxTimeUntil
	t.Cleanup(func() { linuxPoll = originalPoll; linuxTimeUntil = originalUntil })
	untilCalls := 0
	linuxTimeUntil = func(time.Time) time.Duration {
		untilCalls++
		if untilCalls == 1 {
			return 20 * time.Millisecond
		}
		return 0
	}
	pollCalls := 0
	linuxPoll = func([]unix.PollFd, int) (int, error) { pollCalls++; return 0, unix.EINTR }
	ready, err := pollLinuxFD(context.Background(), 1, time.Now().Add(time.Second))
	if err != nil || ready || pollCalls != 1 {
		t.Fatalf("ready=%v pollCalls=%d err=%v", ready, pollCalls, err)
	}
}

func TestParseRouteMessagesAcceptsOnlySimpleOnLinkRoute(t *testing.T) {
	payload := make([]byte, 12)
	payload[0] = unix.AF_INET
	payload[7] = unix.RTN_UNICAST
	payload = append(payload, routeAttribute(unix.RTA_OIF, uint32Bytes(3))...)
	payload = append(payload, routeAttribute(unix.RTA_PREFSRC, []byte{192, 0, 2, 1})...)
	message := netlinkMessage(unix.RTM_NEWROUTE, 9, 77, payload)
	routes, _, _, err := parseRouteMessages(message, 9, 77)
	if err != nil || len(routes) != 1 || routes[0].ifIndex != 3 || !routes[0].source.Equal(net.IPv4(192, 0, 2, 1)) {
		t.Fatalf("routes=%#v err=%v", routes, err)
	}

	for _, attribute := range []struct {
		name string
		kind uint16
		data []byte
	}{
		{name: "gateway", kind: unix.RTA_GATEWAY, data: []byte{192, 0, 2, 254}},
		{name: "nexthop id", kind: linuxRTANHID, data: uint32Bytes(7)},
	} {
		t.Run(attribute.name, func(t *testing.T) {
			complexRoute := append([]byte(nil), payload...)
			complexRoute = append(complexRoute, routeAttribute(attribute.kind, attribute.data)...)
			_, _, _, routeErr := parseRouteMessages(netlinkMessage(unix.RTM_NEWROUTE, 9, 77, complexRoute), 9, 77)
			if !errors.Is(routeErr, ErrModeUnavailable) {
				t.Fatalf("expected complex route unavailable, got %v", routeErr)
			}
		})
	}
}

func TestParseRouteMessagesPreservesMultipartUntilDone(t *testing.T) {
	payload := make([]byte, 12)
	payload[0] = unix.AF_INET
	payload[7] = unix.RTN_UNICAST
	payload = append(payload, routeAttribute(unix.RTA_OIF, uint32Bytes(3))...)
	payload = append(payload, routeAttribute(unix.RTA_PREFSRC, []byte{192, 0, 2, 1})...)
	routes, done, multipart, err := parseRouteMessages(netlinkMessageWithFlags(unix.RTM_NEWROUTE, unix.NLM_F_MULTI, 9, 77, payload), 9, 77)
	if err != nil || done || !multipart || len(routes) != 1 {
		t.Fatalf("routes=%d done=%v multipart=%v err=%v", len(routes), done, multipart, err)
	}
	_, done, _, err = parseRouteMessages(netlinkMessage(unix.NLMSG_DONE, 9, 77, nil), 9, 77)
	if err != nil || !done {
		t.Fatalf("DONE not recognized: done=%v err=%v", done, err)
	}
}

func TestParseRouteMessagesClassifiesNoRouteAsUnavailable(t *testing.T) {
	payload := make([]byte, 4)
	errno := -int32(unix.ENETUNREACH)
	binary.NativeEndian.PutUint32(payload, uint32(errno))
	_, _, _, err := parseRouteMessages(netlinkMessage(unix.NLMSG_ERROR, 9, 77, payload), 9, 77)
	if !errors.Is(err, ErrModeUnavailable) || errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected route unavailable, got %v", err)
	}
}

func TestParseRouteMessagesRejectsMismatchedAndTruncatedData(t *testing.T) {
	payload := make([]byte, 12)
	payload[0] = unix.AF_INET
	payload[7] = unix.RTN_UNICAST
	message := netlinkMessage(unix.RTM_NEWROUTE, 10, 77, payload)
	if _, _, _, err := parseRouteMessages(message, 9, 77); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected sequence failure, got %v", err)
	}
	if _, _, _, err := parseRouteMessages(message[:15], 10, 77); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("expected truncation failure, got %v", err)
	}
}

func routeAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	attribute := make([]byte, alignNetlink(length))
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], kind)
	copy(attribute[4:], value)
	return attribute
}

func uint32Bytes(value uint32) []byte {
	buffer := make([]byte, 4)
	binary.NativeEndian.PutUint32(buffer, value)
	return buffer
}

func netlinkMessage(kind uint16, sequence, pid uint32, payload []byte) []byte {
	return netlinkMessageWithFlags(kind, 0, sequence, pid, payload)
}

func netlinkMessageWithFlags(kind, flags uint16, sequence, pid uint32, payload []byte) []byte {
	message := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	binary.NativeEndian.PutUint32(message[12:16], pid)
	copy(message[16:], payload)
	return message
}

type fakeLinuxARPTransport struct {
	packet    []byte
	source    *unix.SockaddrLinklayer
	receiveFn func(context.Context, time.Time) ([]byte, *unix.SockaddrLinklayer, error)
	sent      []byte
	closed    bool
}

func (t *fakeLinuxARPTransport) Send(_ context.Context, _ time.Time, packet []byte) error {
	t.sent = append([]byte(nil), packet...)
	return nil
}
func (t *fakeLinuxARPTransport) Receive(ctx context.Context, deadline time.Time) ([]byte, *unix.SockaddrLinklayer, error) {
	if t.receiveFn != nil {
		return t.receiveFn(ctx, deadline)
	}
	return t.packet, t.source, nil
}
func (t *fakeLinuxARPTransport) Close() error { t.closed = true; return nil }

func TestLinuxARPRunnerRouteUnavailableDoesNotOpenTransport(t *testing.T) {
	originalRoute := linuxARPRouteLookup
	originalOpen := openLinuxARP
	t.Cleanup(func() { linuxARPRouteLookup = originalRoute; openLinuxARP = originalOpen })
	linuxARPRouteLookup = func(context.Context, net.IP, time.Time) (linuxRouteInfo, error) {
		return linuxRouteInfo{}, fmt.Errorf("%w: gateway route", ErrModeUnavailable)
	}
	opened := false
	openLinuxARP = func(*net.Interface) (linuxARPTransport, error) { opened = true; return nil, nil }
	_, err := newLinuxARPRunner(Options{Timeout: time.Second}).Run(context.Background(), "192.0.2.10")
	if !errors.Is(err, ErrModeUnavailable) || opened {
		t.Fatalf("opened=%v err=%v", opened, err)
	}
}

func TestLinuxARPRunnerCancellationInterruptsReceive(t *testing.T) {
	originalRoute := linuxARPRouteLookup
	originalInterface := linuxARPInterfaceLookup
	originalOpen := openLinuxARP
	t.Cleanup(func() {
		linuxARPRouteLookup = originalRoute
		linuxARPInterfaceLookup = originalInterface
		openLinuxARP = originalOpen
	})
	localMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	localIP := net.IPv4(192, 0, 2, 1)
	iface := &net.Interface{Index: 3, Name: "eth-test", HardwareAddr: localMAC, Flags: net.FlagUp}
	started := make(chan struct{})
	transport := &fakeLinuxARPTransport{receiveFn: func(ctx context.Context, _ time.Time) ([]byte, *unix.SockaddrLinklayer, error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}}
	linuxARPRouteLookup = func(context.Context, net.IP, time.Time) (linuxRouteInfo, error) {
		return linuxRouteInfo{ifIndex: 3, source: localIP}, nil
	}
	linuxARPInterfaceLookup = func(linuxRouteInfo) (*net.Interface, net.IP, error) { return iface, localIP, nil }
	openLinuxARP = func(*net.Interface) (linuxARPTransport, error) { return transport, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := newLinuxARPRunner(Options{Timeout: time.Second}).Run(ctx, "192.0.2.10"); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ARP receive did not stop after cancellation")
	}
}

func TestLinuxNativePermissionErrorsAreModeUnavailable(t *testing.T) {
	for _, err := range []error{
		classifyLinuxARPSystemError("open packet socket", unix.EPERM),
		classifyLinuxNativeTCPOpenError("open raw socket", unix.EACCES),
	} {
		if !errors.Is(err, ErrModeUnavailable) {
			t.Fatalf("expected unavailable, got %v", err)
		}
	}
}

func TestLinuxARPRunnerMatchesAssociatedReply(t *testing.T) {
	originalRoute := linuxARPRouteLookup
	originalInterface := linuxARPInterfaceLookup
	originalOpen := openLinuxARP
	t.Cleanup(func() {
		linuxARPRouteLookup = originalRoute
		linuxARPInterfaceLookup = originalInterface
		openLinuxARP = originalOpen
	})
	localMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	targetMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	localIP := net.IPv4(192, 0, 2, 1)
	targetIP := net.IPv4(192, 0, 2, 10)
	iface := &net.Interface{Index: 3, Name: "eth-test", HardwareAddr: localMAC, Flags: net.FlagUp}
	transport := &fakeLinuxARPTransport{
		packet: buildARPPacket(arpOperationReply, targetMAC, targetIP, localMAC, localIP),
		source: &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: 3, Hatype: unix.ARPHRD_ETHER, Pkttype: unix.PACKET_HOST, Halen: 6},
	}
	copy(transport.source.Addr[:6], targetMAC)
	linuxARPRouteLookup = func(context.Context, net.IP, time.Time) (linuxRouteInfo, error) {
		return linuxRouteInfo{ifIndex: 3, source: localIP}, nil
	}
	linuxARPInterfaceLookup = func(linuxRouteInfo) (*net.Interface, net.IP, error) { return iface, localIP, nil }
	openLinuxARP = func(*net.Interface) (linuxARPTransport, error) { return transport, nil }

	result, err := newLinuxARPRunner(Options{Timeout: time.Second}).Run(context.Background(), targetIP.String())
	if err != nil || !result.Matched || result.Method != "arp" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(transport.sent) != arpPacketLength || !transport.closed {
		t.Fatalf("sent=%x closed=%v", transport.sent, transport.closed)
	}
}
