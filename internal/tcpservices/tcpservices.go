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

// TLSReadWithProbe 封装 TLS 连接 + probeBytes 发送 + 读取 + 解码逻辑
func TLSReadWithProbe(ip string, port int, buf []byte, timeout time.Duration, compatibleTLS bool, probe []byte) (string, error) {
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

	dialer := &net.Dialer{Timeout: timeout}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), tlsConf)
	if err != nil {
		return "", err
	}
	defer tlsConn.Close()

	tlsConn.SetWriteDeadline(time.Now().Add(timeout))
	if probe != nil {
		_, err = tlsConn.Write(probe)
		if err != nil {
			return "", err
		}
	}
	tlsConn.SetReadDeadline(time.Now().Add(timeout))
	n, err := tlsConn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	if n == 0 {
		return "", nil
	}

	decoder := charmap.ISO8859_1.NewDecoder()
	reader := transform.NewReader(bytes.NewReader(buf[:n]), decoder)
	converted, _ := ioutil.ReadAll(reader)
	return string(converted), nil
}

// TcpPortServer 对指定 IP 与端口进行 TCP 探测，返回 banner、subject、dns、service、version 以及 weak（弱口令）信息。
func TcpPortServer(ip string, targetHost string, port int, buf []byte, conn net.Conn, unweak bool) (string, string, string, string, string, common.UsePwd) {
	var banner, subject, dns, service, version string
	var count = 0
	var weak = common.UsePwd{
		Username: "null",
		Password: "null",
	}
	timeout := 3 * time.Second
	tlstimeout := 4 * time.Second
	result := probes.QueryProbes(common.NmapData, port)

	conn.SetDeadline(time.Now().Add(timeout))
	// 如果没有匹配规则，尝试读取数据并检查 NullProbeMatchRules
	n, err := conn.Read(buf)
	if err == nil {
		banner = string(buf[:n])
		// fmt.Println("detect 直接 banner", banner)
		if banner != "" {
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
		}
	}

	// 检查特殊服务
	if banner, subject, dns, svc, ver, weak, ok := connect.CheckSpecialService(ip, port, unweak); ok {
		return banner, subject, dns, svc, ver, weak
	}

	// 判断是否是 SSL 端口
	// fmt.Println("SSL length", len(common.SslPortsMap))

	if shouldTreatAsSSLPort(port) {
		for _, probeRule := range result {
			if probeRule.Protocol != "TCP" {
				continue
			}

			if count == 0 {
				// 第一次尝试直接读取 TLS 初始响应（普通 TLS）
				count++
				initialResponse, err := TLSReadWithProbe(ip, port, buf, timeout, false, nil)
				if err != nil {
					// 如果 TLS 握手失败，切换兼容套件重试
					if strings.Contains(err.Error(), "handshake failure") || strings.Contains(err.Error(), "protocol version") {
						initialResponse, err = TLSReadWithProbe(ip, port, buf, timeout, true, nil)
					}
				}
				if err == nil && initialResponse != "" {
					if svc, ver, w, ok := connect.MatchRules(initialResponse, probeRule.Msg, true, unweak, ip, port); ok {
						service, version, weak = svc, ver, w
						subject, dns = parseTLSCertificate(ip, targetHost, port)
						return SanitizeBanner(initialResponse), subject, dns, service, version, weak
					}
					if svc, ver, w, ok := connect.MatchRules(initialResponse, common.NmapData.NullProbeMatchRules, true, unweak, ip, port); ok {
						service, version, weak = svc, ver, w
						subject, dns = parseTLSCertificate(ip, targetHost, port)
						return SanitizeBanner(initialResponse), subject, dns, service, version, weak
					}
				}
			}

			// TLS 探测：发送 probeBytes
			probeBytes := connect.GetProbeBytes(probeRule.ProbeBytes)
			response, err := TLSReadWithProbe(ip, port, buf, tlstimeout, false, probeBytes)
			if err != nil {
				// 遇到 handshake failure 切换兼容套件
				if strings.Contains(err.Error(), "handshake failure") || strings.Contains(err.Error(), "protocol version") {
					response, _ = TLSReadWithProbe(ip, port, buf, tlstimeout, true, probeBytes)
				} else {
					continue
				}
			}
			if response != "" {
				if svc, ver, w, ok := connect.MatchRules(response, probeRule.Msg, true, unweak, ip, port); ok {
					subject, dns = parseTLSCertificate(ip, targetHost, port)
					return SanitizeBanner(response), subject, dns, svc, ver, w
				}
				if svc, ver, w, ok := connect.MatchRules(response, common.NmapData.NullProbeMatchRules, true, unweak, ip, port); ok {
					subject, dns = parseTLSCertificate(ip, targetHost, port)
					return SanitizeBanner(response), subject, dns, svc, ver, w
				}
				if service == "" && common.ServiceMap[port]["tcp"] != "" {
					service = common.ServiceMap[port]["tcp"] + "/ssl?"
					if service == "" {
						service = "unknown/ssl"
					}
				}
			}
		}
		if service == "" && common.ServiceMap[port]["tcp"] != "" {
			subject, dns = parseTLSCertificate(ip, targetHost, port)
			service = common.ServiceMap[port]["tcp"] + "/ssl?"
			return banner, subject, dns, service, version, weak
		}
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
			if svc, ver, w, ok := connect.MatchRules(response, probeRule.Msg, false, unweak, ip, port); ok {
				return SanitizeBanner(response), subject, dns, svc, ver, w
			}
			if svc, ver, w, ok := connect.MatchRules(response, common.NmapData.NullProbeMatchRules, false, unweak, ip, port); ok {
				return SanitizeBanner(response), subject, dns, svc, ver, w
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
		if banner, subject, dns, svc, ver, ok := detectWebServiceWithHost(ip, targetHost, port, timeout, buf); ok {
			return banner, subject, dns, svc, ver, weak
		}
	}
	return banner, subject, dns, service, version, weak
}

func shouldTreatAsSSLPort(port int) bool {
	if common.SslPortsMap[port] {
		return true
	}

	switch port {
	case 9093:
		// Kafka 常见的 TLS 端口；很多场景不会主动返回可匹配 banner，
		// 但 TLS 握手本身是可成立的，因此这里强制走 TLS 识别分支。
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

func parseTLSCertificate(ip, targetHost string, port int) (string, string) {
	if targetHost != "" && net.ParseIP(targetHost) == nil {
		return separate.ParseHTTPSWithServerName(ip, port, targetHost)
	}
	return separate.ParseHTTPS(ip, port)
}

func detectWebServiceWithHost(ip, targetHost string, port int, timeout time.Duration, buf []byte) (string, string, string, string, string, bool) {
	if !shouldTryWebFallback(port) {
		return "", "", "", "", "", false
	}
	if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, true); service != "" {
		return banner, subject, dns, service, version, true
	}
	if banner, subject, dns, service, version := httpRequestFallback(ip, targetHost, port, timeout, buf, false); service != "" {
		return banner, subject, dns, service, version, true
	}
	return "", "", "", "", "", false
}

func httpRequestFallback(ip, targetHost string, port int, timeout time.Duration, buf []byte, isTLS bool) (string, string, string, string, string) {
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

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", "", "", "", ""
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := connect.ReadWithTimeout(conn, buf, timeout)
	if response == "" {
		return "", "", "", "", ""
	}

	subject, dns := "", ""
	service := "http"
	if isTLS {
		service = "https"
		subject, dns = parseTLSCertificate(ip, targetHost, port)
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
