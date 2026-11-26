package tcpservices

// TCP 服务探测
import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/probes"
	"github.com/yrighc/gomap/internal/connect"
	"github.com/yrighc/gomap/internal/separate"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

// TLSReadWithProbe 封装 TLS 连接 + probeBytes 发送 + 读取 + 解码逻辑。
// 当 targetHost 是域名时会自动携带 SNI，避免站点因为缺少 ServerName 而拒绝返回证书或 HTTP 响应。
func TLSReadWithProbe(ip string, targetHost string, port int, buf []byte, timeout time.Duration, compatibleTLS bool, probe []byte) (string, error) {
	return tlsReadWithProbe(ip, targetHost, port, buf, timeout, compatibleTLS, probe, nil)
}

// onTLS runs immediately after a successful handshake, before application I/O.
// A subsequent read timeout must not erase the confirmed transport.
func tlsReadWithProbe(ip string, targetHost string, port int, buf []byte, timeout time.Duration, compatibleTLS bool, probe []byte, onTLS func(string, string)) (string, error) {
	var tlsConf *tls.Config
	if !compatibleTLS {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
		}
	} else {
		tlsConf = &tls.Config{InsecureSkipVerify: true}
	}
	if targetHost != "" && net.ParseIP(targetHost) == nil {
		tlsConf.ServerName = targetHost
	}

	dialer := &net.Dialer{Timeout: timeout}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), tlsConf)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()
	if onTLS != nil {
		onTLS(tlsCertificateInfo(tlsConn))
	}

	tlsConn.SetWriteDeadline(time.Now().Add(timeout))
	if probe != nil {
		_, err = tlsConn.Write(probe)
		if err != nil {
			return "", err
		}
	}
	tlsConn.SetReadDeadline(time.Now().Add(timeout))
	n, err := tlsConn.Read(buf)
	if err == io.EOF {
		err = nil
	}
	if n == 0 {
		return "", err
	}

	decoder := charmap.ISO8859_1.NewDecoder()
	reader := transform.NewReader(bytes.NewReader(buf[:n]), decoder)
	converted, _ := ioutil.ReadAll(reader)
	return string(converted), err
}

func tlsCertificateInfo(conn *tls.Conn) (string, string) {
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", ""
	}
	return fmt.Sprint(certs[0].Subject), strings.Join(certs[0].DNSNames, ", ")
}

// TcpPortServer 对指定 IP 与端口进行 TCP 探测，返回 banner、subject、dns、service、version 以及 weak（弱口令）信息。
func TcpPortServer(ip string, targetHost string, port int, buf []byte, conn net.Conn, unweak bool) (string, string, string, string, string, common.UsePwd) {
	return TcpPortServerWithTLSObserver(ip, targetHost, port, buf, conn, unweak, nil)
}

// TcpPortServerWithTLSObserver lets budgeted callers retain confirmed TLS even
// if application detection outlives their budget. The observer is synchronous
// and must not block; it reports transport evidence, not an application match.
func TcpPortServerWithTLSObserver(ip string, targetHost string, port int, buf []byte, conn net.Conn, unweak bool, onTLS func(string, string)) (string, string, string, string, string, common.UsePwd) {
	var banner, subject, dns, service, version string
	tlsConfirmed := false
	recordTLS := func(certSubject, certDNS string) {
		tlsConfirmed = true
		subject, dns = certSubject, certDNS
		if onTLS != nil {
			onTLS(certSubject, certDNS)
		}
	}
	var weak = common.UsePwd{
		Username: "null",
		Password: "null",
	}
	timeout := 3 * time.Second
	tlstimeout := 4 * time.Second
	result := probes.QueryProbes(common.NmapData, port)

	// 常见 Web 端口优先走一次快速协议确认。
	// 这类端口往往不会主动回 banner，先等被动读取很容易白白消耗 2~3 秒，
	// 直接发送原始 GET 请求更符合 Web 服务的真实交互方式，也能更稳定识别 80/443。
	if banner, subject, dns, svc, ver, ok := detectPreferredWebServiceWithHost(ip, targetHost, port, timeout, buf, recordTLS); ok {
		return banner, subject, dns, svc, ver, weak
	}

	conn.SetDeadline(time.Now().Add(timeout))
	// 如果没有匹配规则，尝试读取数据并检查 NullProbeMatchRules
	n, err := conn.Read(buf)
	if err == nil {
		banner = string(buf[:n])
		// fmt.Println("detect 直接 banner", banner)
		if banner != "" {
			httpFallback, hasHTTPFallback := detectHTTPServiceByPrefix(banner, false)
			for _, rule := range common.NmapData.NullProbeMatchRules {
				if match, _ := rule.Regex.FindStringMatch(banner); match != nil {
					service = rule.Name
					version = rule.Service
					if ok, response := connect.CheckStartTLSUpgrade(conn, service); ok {
						service += "/ssl"
						subject, dns = separate.ParseHTTPS(ip, port)
						return SanitizeBanner(banner) + "\n" + response, subject, dns, service, version, weak
					}
					return SanitizeBanner(banner), subject, dns, service, version, weak
				}
			}
			if hasHTTPFallback {
				return SanitizeBanner(banner), subject, dns, httpFallback, "", weak
			}
		}
	}

	// 检查特殊服务
	if banner, subject, dns, svc, ver, weak, ok := connect.CheckSpecialService(ip, port, unweak); ok {
		return banner, subject, dns, svc, ver, weak
	}

	// Probe TLS on any port, rather than treating sslports as proof of TLS or
	// using a port whitelist as an admission gate. A failed handshake falls
	// through to the plaintext probes below, including GetRequest.
	readTLS := func(probe []byte, wait time.Duration) string {
		response, err := tlsReadWithProbe(ip, targetHost, port, buf, wait, false, probe, recordTLS)
		if err != nil && (strings.Contains(err.Error(), "handshake failure") || strings.Contains(err.Error(), "protocol version")) {
			response, _ = tlsReadWithProbe(ip, targetHost, port, buf, wait, true, probe, recordTLS)
		}
		return response
	}
	initialResponse := readTLS(nil, timeout)
	if tlsConfirmed {
		matchTLS := func(response string, rules []common.MatchRule) (string, string, common.UsePwd, bool) {
			if response == "" {
				return "", "", weak, false
			}
			if svc, ver, w, ok := connect.MatchRules(response, rules, true, unweak, ip, port); ok {
				return svc, ver, w, true
			}
			if svc, ver, w, ok := connect.MatchRules(response, common.NmapData.NullProbeMatchRules, true, unweak, ip, port); ok {
				return svc, ver, w, true
			}
			svc, ok := detectHTTPServiceByPrefix(response, true)
			return svc, "", weak, ok
		}
		// Keep decrypted evidence separate from any earlier plaintext banner.
		banner = initialResponse
		for _, probeRule := range result {
			if probeRule.Protocol != "TCP" {
				continue
			}
			if svc, ver, w, ok := matchTLS(initialResponse, probeRule.Msg); ok {
				return SanitizeBanner(initialResponse), subject, dns, svc, ver, w
			}
			response := readTLS(connect.GetProbeBytes(probeRule.ProbeBytes), tlstimeout)
			if response != "" {
				banner = response
			}
			if svc, ver, w, ok := matchTLS(response, probeRule.Msg); ok {
				return SanitizeBanner(response), subject, dns, svc, ver, w
			}
		}
		if svc, ver, w, ok := matchTLS(initialResponse, nil); ok {
			return SanitizeBanner(initialResponse), subject, dns, svc, ver, w
		}
		// TLS is confirmed, but no application is. Do not turn a service-table
		// guess into an apparently verified product name such as ultraseek-http.
		return SanitizeBanner(banner), subject, dns, "unknown/ssl", "", weak
	}

	// 非 SSL 处理
	for _, probeRule := range result {
		if probeRule.Protocol != "TCP" {
			continue
		}
		probeBytes := connect.GetProbeBytes(probeRule.ProbeBytes)
		tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
		if err != nil {
			continue
		}
		defer tcpConn.Close()

		tcpConn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = tcpConn.Write(probeBytes)
		if err != nil {
			continue
		}
		tcpConn.SetReadDeadline(time.Now().Add(timeout))
		response := connect.ReadWithTimeout(tcpConn, buf, timeout)
		if response != "" {
			httpFallback, hasHTTPFallback := detectHTTPServiceByPrefix(response, false)
			if svc, ver, w, ok := connect.MatchRules(response, probeRule.Msg, false, unweak, ip, port); ok {
				return SanitizeBanner(response), subject, dns, svc, ver, w
			}
			if svc, ver, w, ok := connect.MatchRules(response, common.NmapData.NullProbeMatchRules, false, unweak, ip, port); ok {
				return SanitizeBanner(response), subject, dns, svc, ver, w
			}
			if hasHTTPFallback {
				return SanitizeBanner(response), subject, dns, httpFallback, "", weak
			}
		}
	}

	if service == "" && common.ServiceMap[port]["tcp"] != "" {
		service = common.ServiceMap[port]["tcp"] + "?"
		if service == "" {
			service = "unknown"
		}
	}
	if isUnknownService(service) {
		if banner, subject, dns, svc, ver, ok := detectWebServiceWithHost(ip, targetHost, port, timeout, buf, recordTLS); ok {
			return banner, subject, dns, svc, ver, weak
		}
	}
	if tlsConfirmed {
		// The final Web fallback may have completed a handshake without an
		// application response, even if the earlier handshake attempt failed.
		return "", subject, dns, "unknown/ssl", "", weak
	}
	return banner, subject, dns, service, version, weak
}

// detectHTTPServiceByPrefix 负责在规则精确匹配之前，先做协议级粗识别。
// 只要响应已经明确以 HTTP 状态行开头，就优先认定为 HTTP/HTTPS，
// 避免因为未命中某条细粒度 nmap 指纹而退化成 unknown。
func detectHTTPServiceByPrefix(response string, isTLS bool) (string, bool) {
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "HTTP/") {
		return "", false
	}
	if isTLS {
		return "https", true
	}
	return "http", true
}

func isLikelyTLSPort(port int) bool {
	// Port hints only select the preferred Web probe order. They never prove
	// TLS and never exclude other ports from handshake-based detection.
	switch port {
	case 80, 81, 591, 593, 8000, 8008, 8080, 8081, 8088, 8888:
		return false
	}

	serviceName := strings.ToLower(strings.TrimSpace(common.ServiceMap[port]["tcp"]))
	if strings.Contains(serviceName, "https") || strings.Contains(serviceName, "ssl") {
		return true
	}

	if common.SslPortsMap[port] {
		return true
	}

	switch port {
	case 9093:
		// Kafka 常见 TLS 端口，仅作顺序提示，仍需实际握手确认。
		return true
	default:
		return false
	}
}

func isUnknownService(service string) bool {
	service = strings.TrimSpace(strings.ToLower(service))
	return service == "" || service == "unknown" || service == "unknown?" || service == "unknown/ssl" || service == "unknown/ssl?"
}

func shouldTryWebFallback(port int) bool {
	switch port {
	case 80, 81, 443, 444, 591, 593, 8000, 8008, 8080, 8081, 8088, 8443, 8843, 8888:
		return true
	default:
		return false
	}
}

func detectWebServiceWithHost(ip, targetHost string, port int, timeout time.Duration, buf []byte, onTLS func(string, string)) (string, string, string, string, string, bool) {
	if !shouldTryWebFallback(port) {
		return "", "", "", "", "", false
	}

	if preferTLSFirst(port) {
		if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, true, onTLS); service != "" {
			return banner, subject, dns, service, version, true
		}
		if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, false, onTLS); service != "" {
			return banner, subject, dns, service, version, true
		}
		return "", "", "", "", "", false
	}

	if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, false, onTLS); service != "" {
		return banner, subject, dns, service, version, true
	}
	if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, true, onTLS); service != "" {
		return banner, subject, dns, service, version, true
	}
	return "", "", "", "", "", false
}

// detectPreferredWebServiceWithHost 是常见 Web 端口的快速识别入口。
// 与底部的未知服务回退不同，这里会在通用探针前优先执行，从而减少 443 等端口因为等待 banner 或遍历大量探针导致的超时。
func detectPreferredWebServiceWithHost(ip, targetHost string, port int, timeout time.Duration, buf []byte, onTLS func(string, string)) (string, string, string, string, string, bool) {
	return detectWebServiceWithHost(ip, targetHost, port, timeout, buf, onTLS)
}

func preferTLSFirst(port int) bool {
	switch port {
	case 443, 444, 465, 563, 585, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 8843, 9443, 10443, 14443:
		return true
	default:
		return isLikelyTLSPort(port)
	}
}

func httpRequestFallback(ip, targetHost string, port int, timeout time.Duration, buf []byte, isTLS bool, onTLS func(string, string)) (string, string, string, string, string) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	hostHeader := targetHost
	if hostHeader == "" {
		hostHeader = ip
	}
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: gomap\r\nAccept: */*\r\nConnection: close\r\n\r\n", hostHeader)

	var (
		conn net.Conn
		err  error
	)
	if isTLS {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
		}
		if targetHost != "" && net.ParseIP(targetHost) == nil {
			cfg.ServerName = targetHost
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return "", "", "", "", ""
	}
	defer conn.Close()
	subject, dns := "", ""
	if tlsConn, ok := conn.(*tls.Conn); ok {
		subject, dns = tlsCertificateInfo(tlsConn)
		if onTLS != nil {
			onTLS(subject, dns)
		}
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", "", "", "", ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := connect.ReadWithTimeout(conn, buf, timeout)
	if response == "" {
		return "", "", "", "", ""
	}

	service := "http"
	if isTLS {
		service = "https"
	}

	for _, rule := range common.AllHTTPRules {
		if rule.Regex == nil {
			continue
		}
		if match, _ := rule.Regex.FindStringMatch(response); match != nil {
			name := rule.Name
			if isTLS {
				if strings.HasPrefix(strings.ToLower(name), "http") {
					name = "https"
				} else {
					name = name + "/ssl"
				}
			}
			return SanitizeBanner(response), subject, dns, name, rule.Service
		}
	}

	if strings.HasPrefix(response, "HTTP/") {
		return SanitizeBanner(response), subject, dns, service, ""
	}
	return "", "", "", "", ""
}

func HttpOnlyPortServer(ip string, port int, buf []byte) (string, string, string, string, string) {
	var subject, dns, service, version string
	timeout := 3 * time.Second

	// ------------------------
	// 1. 先尝试 TLS 连接（判断是否 HTTPS）
	// ------------------------
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	dialer := &net.Dialer{Timeout: timeout}

	tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err == nil {

		defer tlsConn.Close()
		// 发送 GET 请求
		tlsConn.SetWriteDeadline(time.Now().Add(timeout))
		_, err = tlsConn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		if err == nil {
			// 读取响应

			tlsConn.SetReadDeadline(time.Now().Add(timeout))
			response := connect.ReadWithTimeout(tlsConn, buf, timeout)

			// 匹配规则（只取 Name 为 http 的规则）
			for _, rule := range common.AllHTTPRules {
				if rule.Regex == nil {
					continue
				}
				if match, _ := rule.Regex.FindStringMatch(response); match != nil {
					service = rule.Name + "/ssl"
					version = rule.Service
					subject, dns = separate.ParseHTTPS(ip, port)
					return response, subject, dns, service, version
				}
			}

		}
	}

	// ------------------------
	// 2. 明文 HTTP 探测（普通 HTTP）
	// ------------------------
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", "", "", ""
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	if err != nil {
		return "", "", "", "", ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := connect.ReadWithTimeout(conn, buf, timeout)

	for _, rule := range common.AllHTTPRules {
		if rule.Regex == nil {
			continue
		}
		if match, _ := rule.Regex.FindStringMatch(response); match != nil {
			service = rule.Name
			version = rule.Service
			return response, subject, dns, service, version
		}
	}

	return "", "", "", "", ""
}

func SanitizeBanner(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		switch b {
		case '\r', '\n': // 保留换行符
			buf.WriteByte(b)
		default:
			if b >= 32 && b <= 126 {
				// 可打印字符
				buf.WriteByte(b)
			} else {
				// 其它不可打印字符转义
				buf.WriteString(fmt.Sprintf("\\x%02x", b))
			}
		}
	}
	return buf.String()
}
