package hostdiscovery

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestMatchICMPEchoReplyRequiresEveryField(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	nonce := bytes.Repeat([]byte{0x5a}, 16)
	reply := mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 0, 7, 3, nonce)

	if !matchICMPEchoReply(icmpReply{
		source: target,
		target: target,
		proto:  1,
		packet: reply,
	}, icmpProbe{id: 7, seq: 3, nonce: nonce}) {
		t.Fatal("expected exact echo reply to match")
	}

	mutations := []struct {
		name  string
		reply icmpReply
	}{
		{name: "wrong source", reply: icmpReply{source: net.ParseIP("192.0.2.11"), target: target, proto: 1, packet: reply}},
		{name: "request type", reply: icmpReply{source: target, target: target, proto: 1, packet: mustICMPEcho(t, ipv4.ICMPTypeEcho, 0, 7, 3, nonce)}},
		{name: "nonzero code", reply: icmpReply{source: target, target: target, proto: 1, packet: mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 1, 7, 3, nonce)}},
		{name: "wrong id", reply: icmpReply{source: target, target: target, proto: 1, packet: mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 0, 8, 3, nonce)}},
		{name: "wrong sequence", reply: icmpReply{source: target, target: target, proto: 1, packet: mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 0, 7, 4, nonce)}},
		{name: "wrong nonce", reply: icmpReply{source: target, target: target, proto: 1, packet: mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 0, 7, 3, bytes.Repeat([]byte{0xa5}, 16))}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			if matchICMPEchoReply(tt.reply, icmpProbe{id: 7, seq: 3, nonce: nonce}) {
				t.Fatal("mutated reply matched")
			}
		})
	}
}

func TestMatchICMPEchoReplyAcceptsIPv6AndStripsValidIPv4Header(t *testing.T) {
	target := net.ParseIP("2001:db8::10")
	nonce := bytes.Repeat([]byte{0x11}, 16)
	packet, err := (&icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 9, Seq: 2, Data: nonce},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !matchICMPEchoReply(icmpReply{source: target, target: target, proto: 58, packet: packet}, icmpProbe{id: 9, seq: 2, nonce: nonce}) {
		t.Fatal("expected IPv6 echo reply to match")
	}

	ipv4Target := net.ParseIP("192.0.2.10").To4()
	body := mustICMPEcho(t, ipv4.ICMPTypeEchoReply, 0, 4, 1, nonce)
	header := &ipv4.Header{Version: 4, Len: ipv4.HeaderLen, TotalLen: ipv4.HeaderLen + len(body), Protocol: 1, Src: ipv4Target, Dst: net.IPv4(192, 0, 2, 1)}
	rawHeader, err := header.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	wrapped := append(rawHeader, body...)
	if !matchICMPEchoReply(icmpReply{source: ipv4Target, target: ipv4Target, proto: 1, packet: wrapped}, icmpProbe{id: 4, seq: 1, nonce: nonce}) {
		t.Fatal("expected reply behind a valid IPv4 header to match")
	}
	wrongHeaderSource := append([]byte(nil), wrapped...)
	copy(wrongHeaderSource[12:16], net.IPv4(192, 0, 2, 11).To4())
	if matchICMPEchoReply(icmpReply{source: ipv4Target, target: ipv4Target, proto: 1, packet: wrongHeaderSource}, icmpProbe{id: 4, seq: 1, nonce: nonce}) {
		t.Fatal("IPv4 header with wrong source matched")
	}
	shortHeader := append([]byte{0x46, 0, 0, 20}, body...)
	if matchICMPEchoReply(icmpReply{source: ipv4Target, target: ipv4Target, proto: 1, packet: shortHeader}, icmpProbe{id: 4, seq: 1, nonce: nonce}) {
		t.Fatal("short claimed IPv4 header matched")
	}
}

func mustICMPEcho(t *testing.T, typ ipv4.ICMPType, code, id, seq int, nonce []byte) []byte {
	t.Helper()
	packet, err := (&icmp.Message{
		Type: typ,
		Code: code,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: nonce},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
