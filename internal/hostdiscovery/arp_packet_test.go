package hostdiscovery

import (
	"net"
	"testing"
)

func TestMatchARPReplyRequiresCompleteAssociation(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	targetMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	localIP := net.IPv4(192, 0, 2, 1)
	targetIP := net.IPv4(192, 0, 2, 10)
	packet := buildARPPacket(arpOperationReply, targetMAC, targetIP, localMAC, localIP)

	if !matchARPReply(packet, targetMAC, localMAC, targetIP, localIP) {
		t.Fatal("expected exact ARP reply to match")
	}
	mutations := []struct {
		name      string
		packet    []byte
		linkLayer net.HardwareAddr
	}{
		{name: "request operation", packet: buildARPPacket(arpOperationRequest, targetMAC, targetIP, localMAC, localIP), linkLayer: targetMAC},
		{name: "wrong sender ip", packet: buildARPPacket(arpOperationReply, targetMAC, net.IPv4(192, 0, 2, 11), localMAC, localIP), linkLayer: targetMAC},
		{name: "wrong target ip", packet: buildARPPacket(arpOperationReply, targetMAC, targetIP, localMAC, net.IPv4(192, 0, 2, 9)), linkLayer: targetMAC},
		{name: "wrong target mac", packet: buildARPPacket(arpOperationReply, targetMAC, targetIP, net.HardwareAddr{0x02, 0, 0, 0, 0, 3}, localIP), linkLayer: targetMAC},
		{name: "link source mismatch", packet: packet, linkLayer: net.HardwareAddr{0x02, 0, 0, 0, 0, 4}},
		{name: "multicast sender", packet: buildARPPacket(arpOperationReply, net.HardwareAddr{0x01, 0, 0, 0, 0, 2}, targetIP, localMAC, localIP), linkLayer: net.HardwareAddr{0x01, 0, 0, 0, 0, 2}},
		{name: "short packet", packet: packet[:27], linkLayer: targetMAC},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			if matchARPReply(tt.packet, tt.linkLayer, localMAC, targetIP, localIP) {
				t.Fatal("mutated ARP reply matched")
			}
		})
	}
}

func TestBuildARPRequestUsesBroadcastTarget(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	packet := buildARPRequest(localMAC, net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 10))
	if len(packet) != arpPacketLength || packet[7] != arpOperationRequest {
		t.Fatalf("unexpected request: %x", packet)
	}
	for _, value := range packet[18:24] {
		if value != 0 {
			t.Fatalf("target hardware address must be zero: %x", packet[18:24])
		}
	}
}
