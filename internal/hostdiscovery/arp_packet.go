package hostdiscovery

import (
	"bytes"
	"encoding/binary"
	"net"
)

const (
	arpPacketLength     = 28
	arpOperationRequest = 1
	arpOperationReply   = 2
)

func buildARPRequest(localMAC net.HardwareAddr, localIP, targetIP net.IP) []byte {
	return buildARPPacket(arpOperationRequest, localMAC, localIP, make(net.HardwareAddr, 6), targetIP)
}

func buildARPPacket(operation uint16, senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) []byte {
	packet := make([]byte, arpPacketLength)
	binary.BigEndian.PutUint16(packet[0:2], 1)
	binary.BigEndian.PutUint16(packet[2:4], 0x0800)
	packet[4] = 6
	packet[5] = 4
	binary.BigEndian.PutUint16(packet[6:8], operation)
	copy(packet[8:14], senderMAC)
	copy(packet[14:18], senderIP.To4())
	copy(packet[18:24], targetMAC)
	copy(packet[24:28], targetIP.To4())
	return packet
}

func matchARPReply(packet []byte, linkSource, localMAC net.HardwareAddr, targetIP, localIP net.IP) bool {
	if len(packet) != arpPacketLength || len(linkSource) < 6 || len(localMAC) != 6 {
		return false
	}
	if binary.BigEndian.Uint16(packet[0:2]) != 1 || binary.BigEndian.Uint16(packet[2:4]) != 0x0800 || packet[4] != 6 || packet[5] != 4 || binary.BigEndian.Uint16(packet[6:8]) != arpOperationReply {
		return false
	}
	senderMAC := net.HardwareAddr(packet[8:14])
	if !validUnicastHardwareAddr(senderMAC) || !bytes.Equal(senderMAC, linkSource[:6]) {
		return false
	}
	return bytes.Equal(packet[14:18], targetIP.To4()) &&
		bytes.Equal(packet[18:24], localMAC) &&
		bytes.Equal(packet[24:28], localIP.To4())
}

func validUnicastHardwareAddr(address net.HardwareAddr) bool {
	if len(address) != 6 || address[0]&1 != 0 {
		return false
	}
	for _, value := range address {
		if value != 0 {
			return true
		}
	}
	return false
}
