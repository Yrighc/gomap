package hostdiscovery

import (
	"encoding/binary"
	"net"
	"time"
)

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagSYN uint8 = 0x02
	tcpFlagRST uint8 = 0x04
	tcpFlagACK uint8 = 0x10
)

type tcpProbe struct {
	mode       string
	remotePort uint16
	seq        uint32
	ack        uint32
	deadline   time.Time
}

type tcpResponse struct {
	sourcePort      uint16
	destinationPort uint16
	seq             uint32
	ack             uint32
	flags           uint8
}

func buildTCPPacket(sourceIP, targetIP net.IP, sourcePort, targetPort uint16, seq, ack uint32, flags uint8) []byte {
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet[0:2], sourcePort)
	binary.BigEndian.PutUint16(packet[2:4], targetPort)
	binary.BigEndian.PutUint32(packet[4:8], seq)
	binary.BigEndian.PutUint32(packet[8:12], ack)
	packet[12] = 5 << 4
	packet[13] = flags
	binary.BigEndian.PutUint16(packet[14:16], 1024)
	binary.BigEndian.PutUint16(packet[16:18], checksumTCPIPv4(sourceIP, targetIP, packet))
	return packet
}

func checksumTCPIPv4(sourceIP, targetIP net.IP, packet []byte) uint16 {
	source := sourceIP.To4()
	target := targetIP.To4()
	if source == nil || target == nil {
		return 0xffff
	}
	sum := uint32(0)
	add := func(buffer []byte) {
		for len(buffer) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(buffer[:2]))
			buffer = buffer[2:]
		}
		if len(buffer) == 1 {
			sum += uint32(buffer[0]) << 8
		}
	}
	add(source)
	add(target)
	sum += 6
	sum += uint32(len(packet))
	add(packet)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseTCPResponse(sourceIP, targetIP net.IP, packet []byte) (tcpResponse, bool) {
	if sourceIP.To4() == nil || targetIP.To4() == nil || len(packet) < 20 {
		return tcpResponse{}, false
	}
	headerLength := int(packet[12]>>4) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return tcpResponse{}, false
	}
	return tcpResponse{
		sourcePort:      binary.BigEndian.Uint16(packet[0:2]),
		destinationPort: binary.BigEndian.Uint16(packet[2:4]),
		seq:             binary.BigEndian.Uint32(packet[4:8]),
		ack:             binary.BigEndian.Uint32(packet[8:12]),
		flags:           packet[13],
	}, true
}

func matchTCPProbeResponse(probe tcpProbe, response tcpResponse, localPort uint16) bool {
	if response.sourcePort != probe.remotePort || response.destinationPort != localPort {
		return false
	}
	switch probe.mode {
	case "tcp-syn":
		if response.flags&(tcpFlagFIN|tcpFlagRST) == 0 && response.flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK {
			return response.ack == probe.seq+1
		}
		if response.flags&(tcpFlagSYN|tcpFlagFIN) == 0 && response.flags&(tcpFlagRST|tcpFlagACK) == tcpFlagRST|tcpFlagACK {
			return response.ack == probe.seq+1
		}
	case "tcp-ack":
		if response.flags&(tcpFlagSYN|tcpFlagFIN|tcpFlagACK) == 0 && response.flags&tcpFlagRST != 0 {
			return response.seq == probe.ack
		}
	}
	return false
}
