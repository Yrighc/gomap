package connect

// 连接与服务识别模块
import (
	"bytes"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/internal/achieve"
	"github.com/yrighc/gomap/internal/separate"
	"net"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func CheckStartTLSUpgrade(conn net.Conn, protocol string) (bool, string) {
	var cmd string

	switch protocol {
	// case "smtp":
	// 	cmd = "EHLO test.com\r\n"
	// case "imap":
	// 	cmd = "a1 CAPABILITY\r\n"
	// case "pop3":
	// 	cmd = "STLS\r\n"
	case "ftp":
		cmd = "AUTH TLS\r\n"
	default:
		return false, ""
	}

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return false, ""
	}

	reply := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(reply)
	if err != nil || n == 0 {
		return false, ""
	}
	response := string(reply[:n])

	switch protocol {
	case "ftp":
		if strings.HasPrefix(response, "234") {
			return true, response
		}
	}

	return false, response
}

// checkSpecialService 处理特定端口的服务识别逻辑
func CheckSpecialService(ip string, port int, unweak bool) (banner, subject, dns, service, version string, weak common.UsePwd, ok bool) {
	weak = common.UsePwd{Username: "null", Password: "null"}

	var handle = func(svc, ver, b string) (string, string, string, string, string, common.UsePwd, bool) {
		if unweak {
			if handler, exists := achieve.ServiceBlasts[svc]; exists {
				weak = handler(ip, port, false)
			}
		}
		return b, "", "", svc, ver, weak, true
	}

	switch port {
	case 53:
		banner = separate.ParseDNS(ip, port)
		if banner != "" {
			return handle("dns-tcp", "", banner)
		}
	case 23:
		banner = separate.ParseTelnet(ip, port)
		if banner != "" {
			service = "telnet"
			for _, rule := range common.NmapData.NullProbeMatchRules {
				if match, _ := rule.Regex.FindStringMatch(banner); match != nil {
					return handle(rule.Name, rule.Service, banner)
				}
			}
			return handle("telnet", "", banner)
		}
	case 1723:
		banner, _ = separate.SendPPTPRequest(ip, port)
		if banner != "" {
			return handle("pptp", "MikroTik PPTP VPN", banner)
		}
	case 3389, 3388:
		banner = separate.RdpSSLParse(ip, port)
		if banner != "" {
			return handle("rdp/ssl", "Microsoft RDP", banner)
		}

	case 587:
		banner = separate.ParseSMTPStartTLS(ip, port)
		if banner != "" {
			service = "smtp/ssl"
			return handle("smtp/ssl", "SMTP TLS", banner)
		}
	case 993:
		banner = separate.ParseIMapStartTLS(ip, port)
		if banner != "" {
			service = "imap/ssl"
			return handle("imap/ssl", "IMAP TLS", banner)
		}
	case 995:
		banner = separate.ParsePop3StartTLS(ip, port)
		if banner != "" {
			service = "pop3/ssl"
			return handle("pop3/ssl", "POP3 TLS", banner)
		}
	}
	return "", "", "", "", "", weak, false
}

// getProbeBytes 根据 probe 字符串生成对应的字节数组
func GetProbeBytes(probeStr string) []byte {
	var probeBytes []byte
	if strings.Contains(probeStr, "\\x") {
		probeBytes, _ = achieve.HexStringToBytes(probeStr)
	} else {
		probeStr = strings.ReplaceAll(probeStr, "\\r", "\r")
		probeStr = strings.ReplaceAll(probeStr, "\\n", "\n")
		probeBytes = []byte(probeStr)
	}
	if len(probeBytes) == 0 {
		probeBytes, _ = achieve.SpecialStringToBytes(probeStr)
	}
	return probeBytes
}

// readWithTimeout 从连接中读取数据（带超时），并对读取到的内容进行字符集转换
func ReadWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) string {
	readCh := make(chan string, 1)

	go func() {
		conn.SetReadDeadline(time.Now().Add(timeout)) // 确保 conn 自身也设置超时

		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			readCh <- ""
			return
		}

		decoder := charmap.ISO8859_1.NewDecoder()
		reader := transform.NewReader(bytes.NewReader(buf[:n]), decoder)

		// 用小缓冲读 transform.Reader（不用 ReadAll）
		tmp := make([]byte, 1024)
		var output bytes.Buffer
		for {
			sn, err := reader.Read(tmp)
			if sn > 0 {
				output.Write(tmp[:sn])
			}
			if err != nil {
				break
			}
		}
		readCh <- output.String()
	}()

	select {
	case res := <-readCh:
		return res
	case <-time.After(timeout + 1*time.Second): // 稍微宽一点点，防 goroutine 漏读
		return ""
	}
}

func MatchRules(response string, rules []common.MatchRule, isSSL bool, unweak bool, ip string, port int) (string, string, common.UsePwd, bool) {
	for _, r := range rules {
		match, err := r.Regex.FindStringMatch(response)
		if err != nil {
			continue // 正则匹配出错，跳过
		} else if match != nil {
			var svc string
			if isSSL {
				if strings.Contains(r.Name, "ssl/") {
					svc = strings.Replace(r.Name, "ssl/", "", 1) + "/ssl"
				} else {
					svc = r.Name + "/ssl"
				}
			} else {
				svc = r.Name
			}
			ver := r.Service
			var w = common.UsePwd{
				Username: "null",
				Password: "null",
			}
			if unweak {
				if handler, exists := achieve.ServiceBlasts[svc]; exists {
					w = handler(ip, port, isSSL)
				} else {
					for key, handler := range achieve.ServiceBlasts {
						if strings.Contains(ver, key) {
							w = handler(ip, port, isSSL)
							break
						}
					}
				}
			}
			return svc, ver, w, true

		}
	}
	return "", "", common.UsePwd{Username: "null", Password: "null"}, false
}
