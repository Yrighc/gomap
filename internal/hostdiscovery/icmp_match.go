package hostdiscovery

import (
	"bytes"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpProbe struct {
	id    int
	seq   int
	proto int
	nonce []byte
}

type icmpReply struct {
	source net.IP
	target net.IP
	proto  int
	packet []byte
}

func matchICMPEchoReply(reply icmpReply, probe icmpProbe) bool {
	if !reply.source.Equal(reply.target) {
		return false
	}
	packet := icmpPayload(reply)
	message, err := icmp.ParseMessage(reply.proto, packet)
	if err != nil || message.Code != 0 {
		return false
	}
	switch reply.proto {
	case 1:
		if message.Type != ipv4.ICMPTypeEchoReply {
			return false
		}
	case 58:
		if message.Type != ipv6.ICMPTypeEchoReply {
			return false
		}
	default:
		return false
	}

	echo, ok := message.Body.(*icmp.Echo)
	if !ok {
		return false
	}
	return echo.ID == probe.id && echo.Seq == probe.seq && bytes.Equal(echo.Data, probe.nonce)
}

func icmpPayload(reply icmpReply) []byte {
	if reply.proto != 1 || len(reply.packet) < ipv4.HeaderLen || reply.packet[0]>>4 != 4 {
		return reply.packet
	}
	headerLen := int(reply.packet[0]&0x0f) << 2
	if headerLen < ipv4.HeaderLen || headerLen > len(reply.packet) || reply.packet[9] != 1 || !net.IP(reply.packet[12:16]).Equal(reply.target) {
		return nil
	}
	return reply.packet[headerLen:]
}
