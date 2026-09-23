package updservices

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/probes"
	"github.com/yrighc/gomap/internal/achieve"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// ProbeResult keeps UDP response evidence separate from service identification.
// Responded is true for every received datagram, including a legal zero-length
// datagram. Service metadata never implies that a response was received.
type ProbeResult struct {
	Responded bool
	Banner    string
	Subject   string
	DNS       string
	Service   string
	Version   string
}

var dialUDPContext = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// UcpPortServer runs the configured UDP probes for one port. Each probe owns
// its connection and buffer so a timed-out read cannot consume a later probe's
// response. timeout covers dial, write, and read for that one probe.
func UcpPortServer(ctx context.Context, ip string, port int, timeout time.Duration) ProbeResult {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	result := ProbeResult{}
	for _, rule := range probes.QueryProbes(common.NmapData, port) {
		if err := ctx.Err(); err != nil {
			return result
		}
		if rule.Protocol != "UDP" {
			continue
		}

		probeBytes := probePayload(rule.ProbeBytes)
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		probeResult := runUDPProbe(probeCtx, ip, port, probeBytes, rule.Msg)
		cancel()
		if probeResult.Responded {
			result.Responded = true
			if result.Banner == "" || probeResult.Banner != "" {
				result.Banner = probeResult.Banner
				result.Subject = probeResult.Subject
				result.DNS = probeResult.DNS
			}
			if probeResult.Service != "" {
				result.Service = probeResult.Service
				result.Version = probeResult.Version
				return result
			}
		}
		if err := ctx.Err(); err != nil {
			return result
		}
	}

	if result.Responded && result.Service == "" {
		result.Service = udpServiceGuess(port)
	}
	return result
}

func probePayload(encoded string) []byte {
	var payload []byte
	if strings.Contains(encoded, "\\x") {
		payload, _ = achieve.HexStringToBytes(encoded)
	} else {
		decoded := strings.NewReplacer("\\r", "\r", "\\n", "\n").Replace(encoded)
		payload = []byte(decoded)
	}
	if len(payload) == 0 {
		payload, _ = achieve.SpecialStringToBytes(encoded)
	}
	return payload
}

func runUDPProbe(ctx context.Context, ip string, port int, payload []byte, rules []common.MatchRule) ProbeResult {
	if err := ctx.Err(); err != nil {
		return ProbeResult{}
	}

	conn, err := dialUDPContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ProbeResult{}
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			return ProbeResult{}
		}
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{}
	}
	if _, err := conn.Write(payload); err != nil {
		return ProbeResult{}
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return ProbeResult{}
	}

	result := ProbeResult{Responded: true}
	if n == 0 {
		return result
	}
	result.Banner = decodeBanner(buf[:n])
	for _, rule := range rules {
		if rule.Regex == nil {
			continue
		}
		if match, _ := rule.Regex.FindStringMatch(result.Banner); match != nil {
			result.Service = rule.Name
			result.Version = rule.Service
			return result
		}
	}
	for _, rule := range common.NmapData.NullProbeMatchRules {
		if rule.Regex == nil {
			continue
		}
		if match, _ := rule.Regex.FindStringMatch(result.Banner); match != nil {
			result.Service = rule.Name
			result.Version = rule.Service
			return result
		}
	}
	return result
}

func decodeBanner(raw []byte) string {
	decoder := charmap.ISO8859_1.NewDecoder()
	converted, _, err := transform.Bytes(decoder, raw)
	if err != nil {
		return string(raw)
	}
	return string(converted)
}

func udpServiceGuess(port int) string {
	if protocols, ok := common.ServiceMap[port]; ok && protocols["udp"] != "" {
		return protocols["udp"] + "?"
	}
	return ""
}
