package hostdiscovery

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildTCPProbeProducesValidChecksum(t *testing.T) {
	source := net.IPv4(192, 0, 2, 1)
	target := net.IPv4(192, 0, 2, 10)
	packet := buildTCPPacket(source, target, 41000, 443, 0x10203040, 0, tcpFlagSYN)
	if len(packet) != 20 {
		t.Fatalf("unexpected TCP header length: %d", len(packet))
	}
	if packet[12]>>4 != 5 || packet[13] != tcpFlagSYN {
		t.Fatalf("unexpected TCP header: %x", packet)
	}
	if checksumTCPIPv4(source, target, packet) != 0 {
		t.Fatalf("invalid checksum: %x", packet)
	}
}

func TestMatchTCPProbeResponseUsesStrictTokensAndFlags(t *testing.T) {
	local := net.IPv4(192, 0, 2, 1)
	target := net.IPv4(192, 0, 2, 10)

	tests := []struct {
		name  string
		probe tcpProbe
		seq   uint32
		ack   uint32
		flags uint8
		match bool
	}{
		{name: "syn ack", probe: tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 0xffffffff}, seq: 8, ack: 0, flags: tcpFlagSYN | tcpFlagACK, match: true},
		{name: "syn rst ack", probe: tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 9}, seq: 8, ack: 10, flags: tcpFlagRST | tcpFlagACK, match: true},
		{name: "syn bare rst rejected", probe: tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 9}, seq: 8, ack: 0, flags: tcpFlagRST},
		{name: "syn wrong ack", probe: tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 9}, seq: 8, ack: 9, flags: tcpFlagSYN | tcpFlagACK},
		{name: "syn conflicting fin", probe: tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 9}, seq: 8, ack: 10, flags: tcpFlagSYN | tcpFlagACK | tcpFlagFIN},
		{name: "ack rst", probe: tcpProbe{mode: "tcp-ack", remotePort: 443, seq: 9, ack: 0xaabbccdd}, seq: 0xaabbccdd, ack: 0, flags: tcpFlagRST, match: true},
		{name: "ack rst ack rejected", probe: tcpProbe{mode: "tcp-ack", remotePort: 443, seq: 9, ack: 0xaabbccdd}, seq: 0xaabbccdd, ack: 10, flags: tcpFlagRST | tcpFlagACK},
		{name: "ack wrong seq", probe: tcpProbe{mode: "tcp-ack", remotePort: 443, ack: 10}, seq: 11, flags: tcpFlagRST},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildTCPPacket(target, local, 443, 41000, tt.seq, tt.ack, tt.flags)
			response, ok := parseTCPResponse(target, local, packet)
			if !ok {
				t.Fatal("valid TCP packet did not parse")
			}
			if got := matchTCPProbeResponse(tt.probe, response, 41000); got != tt.match {
				t.Fatalf("match=%v want %v response=%#v", got, tt.match, response)
			}
		})
	}
}

func TestParseTCPResponseRejectsMalformedHeaders(t *testing.T) {
	local := net.IPv4(192, 0, 2, 1)
	target := net.IPv4(192, 0, 2, 10)
	valid := buildTCPPacket(target, local, 443, 41000, 1, 2, tcpFlagRST|tcpFlagACK)
	cases := [][]byte{
		valid[:19],
		append([]byte(nil), valid...),
		append([]byte(nil), valid...),
	}
	cases[1][12] = 4 << 4
	cases[2][12] = 15 << 4
	for index, packet := range cases {
		if _, ok := parseTCPResponse(target, local, packet); ok {
			t.Fatalf("case %d parsed malformed packet", index)
		}
	}

	wrongPort := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(wrongPort[2:4], 41001)
	response, ok := parseTCPResponse(target, local, wrongPort)
	if !ok || matchTCPProbeResponse(tcpProbe{mode: "tcp-syn", remotePort: 443, seq: 1}, response, 41000) {
		t.Fatal("wrong local port matched")
	}
}
