package separate

// 各种协议的单独解析函数
import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func ParseHTTPS(ip string, port int) (string, string) {

	subject, dns := getCertificate(ip, port)
	return subject, dns
}

func ParseDNS(ip string, port int) string {

	if isDNS, respData, err := checkDNSTCPService(ip, port, "github.com", 1); err == nil {
		if isDNS {
			str := fmt.Sprint(prettyFormatDNSResponse(respData))
			return str
		} else {
			return ""
		}
	} else {
		return ""
	}
}

func ParseTelnet(ip string, port int) string {

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 使用一个 buffer 累积有效数据
	var buffer bytes.Buffer
	tempBuf := make([]byte, 4096)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))

	for {
		n, err := conn.Read(tempBuf)
		if n > 0 {
			cleaned := handleTelnetNegotiation(conn, tempBuf[:n])
			buffer.Write(cleaned)
			if bytes.Contains(buffer.Bytes(), []byte("login:")) {
				break
			}
			// 每次成功读取后重置超时
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		if err != nil {
			// 超时错误时退出循环
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			} else {
				return ""
			}
		}
	}

	data := buffer.Bytes()

	var read string
	decoder := charmap.ISO8859_1.NewDecoder()
	reader := transform.NewReader(bytes.NewReader(data), decoder)
	var out bytes.Buffer
	tmp := make([]byte, 1024)
	for {
		n, err := reader.Read(tmp)
		if n > 0 {
			out.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	read = out.String()

	return read
}

// 获取 HTTPS 服务的证书
func getCertificate(ip string, port int) (string, string) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 获取服务器证书链
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		// 打印证书相关信息
		// fmt.Printf("Certificate for %s:\n", ip)
		// fmt.Printf("  SerialNumber: %s\n", cert.SerialNumber)
		// fmt.Printf("  Signature: %s\n", cert.Signature)
		// fmt.Printf("  Subject: %s\n", cert.Subject)
		// fmt.Printf("  Issuer: %s\n", cert.Issuer)
		// fmt.Printf("  Not Before: %s\n", cert.NotBefore)
		// fmt.Printf("  Not After: %s\n", cert.NotAfter)
		// fmt.Printf("  Serial Number: %s\n", cert.SerialNumber)
		// fmt.Printf("PublicKey: %+v\n", cert.PublicKey)
		// fmt.Printf("  DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))

		return fmt.Sprint(cert.Subject), strings.Join(cert.DNSNames, ", ")

	} else {
		// fmt.Println("No certificate found for port 443")
	}
	return "", ""
}

func GetHTTPSBanner(ip string, port int) (string, error) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 创建带超时的拨号器
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	// 建立TLS连接
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return "", fmt.Errorf("failed to establish TLS connection: %v", err)
	}
	defer conn.Close()

	// 设置超时时间
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 发送一个 HTTP 请求
	request := "GET / HTTP/1.0\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// 读取响应
	var buf bytes.Buffer
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break // 不再继续读（包括EOF或超时）
		}
	}
	return buf.String(), nil

}

// 核心检测函数
func checkDNSTCPService(ip string, port int, domain string, qtype uint16) (bool, []byte, error) {

	dialer := &net.Dialer{
		Timeout: 3 * time.Second, // 设置连接超时
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, nil, fmt.Errorf("TCP连接失败: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	fullQuery, transID := buildDNSTCPQuery(domain, qtype)
	if _, err = conn.Write(fullQuery); err != nil {
		return false, nil, fmt.Errorf("查询发送失败: %v", err)
	}

	lenBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, lenBuf); err != nil {
		return false, nil, fmt.Errorf("长度头读取失败: %v", err)
	}

	respLen := int(binary.BigEndian.Uint16(lenBuf))
	if respLen < 12 || respLen > 65535 {
		return false, nil, fmt.Errorf("非法DNS长度: %d", respLen)
	}

	respData := make([]byte, respLen)
	if _, err = io.ReadFull(conn, respData); err != nil {
		return false, nil, fmt.Errorf("响应体读取失败: %v", err)
	}

	if binary.BigEndian.Uint16(respData[0:2]) != transID {
		return false, append(lenBuf, respData...), fmt.Errorf("事务ID不匹配")
	}

	return true, append(lenBuf, respData...), nil
}

// 构造带事务ID的TCP查询
func buildDNSTCPQuery(domain string, qtype uint16) ([]byte, uint16) {
	transID := uint16(time.Now().UnixNano() % 0xFFFF)
	query := make([]byte, 12)

	// 头部设置
	binary.BigEndian.PutUint16(query[0:2], transID) // 事务ID
	query[2] = 0x01                                 // 标准查询
	query[3] = 0x00                                 // 标志位
	binary.BigEndian.PutUint16(query[4:6], 1)       // QDCOUNT=1

	// 构造问题部分
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0x00) // 结束符
	query = append(query, []byte{0x00, byte(qtype), 0x00, 0x01}...)

	// 添加TCP长度前缀
	tcpQuery := make([]byte, 2)
	binary.BigEndian.PutUint16(tcpQuery, uint16(len(query)))
	return append(tcpQuery, query...), transID
}

// 响应格式化输出
func prettyFormatDNSResponse(data []byte) string {
	if len(data) < 2 {
		return "响应数据不完整"
	}

	respLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(2+respLen) {
		return fmt.Sprintf("数据截断 (声明长度:%d 实际:%d)", respLen, len(data)-2)
	}

	payload := data[2 : 2+respLen]
	header := payload[0:12]

	return fmt.Sprintf(`DNS-TCP响应分析：
 Transaction ID: 0x%04X 
 Flags: 0x%04X (QR=%d OPCODE=%d RCODE=%d)
 Questions: %d 
 Answer RRs: %d 
 Data length: %d bytes 
 TXT: % X...
`,
		binary.BigEndian.Uint16(header[0:2]),
		binary.BigEndian.Uint16(header[2:4]),
		(binary.BigEndian.Uint16(header[2:4])&0x8000)>>15,
		(binary.BigEndian.Uint16(header[2:4])&0x7800)>>11,
		binary.BigEndian.Uint16(header[2:4])&0x000F,
		binary.BigEndian.Uint16(header[4:6]),
		binary.BigEndian.Uint16(header[6:8]),
		respLen,
		first6Bytes(payload),
	)
}

func first6Bytes(data []byte) string {
	if len(data) > 6 {
		return fmt.Sprintf("% X", data[:6])
	}
	return fmt.Sprintf("% X", data)
}

func handleTelnetNegotiation(conn net.Conn, data []byte) []byte {
	var result []byte
	for i := 0; i < len(data); {
		if data[i] == 0xff && i+2 < len(data) {

			cmd, opt := data[i+1], data[i+2]
			result = append(result, data[i], cmd, opt)

			switch cmd {
			case 251: // WILL
				if opt == 0x01 {
					conn.Write([]byte{0xff, 0xfd, opt}) // DO
				} else {
					conn.Write([]byte{0xff, 0xfe, opt}) // DONT
				}
			case 253: // DO
				conn.Write([]byte{0xff, 0xfc, opt}) // WONT
			}
			i += 3
		} else {
			result = append(result, data[i])
			i++
		}
	}
	return result
}

// PPTP 客户端模拟
func SendPPTPRequest(ip string, port int) (string, error) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	// 建立 TCP 连接
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	defer conn.Close()

	// 模拟 PPTP 握手请求
	handshakeData := []byte{
		0x00, 0x9c, 0x00, 0x01, 0x1a, 0x2b, 0x3c, 0x4d, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	// 设置读取超时
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// 发送握手请求
	_, err = conn.Write(handshakeData)
	if err != nil {
		return "", fmt.Errorf("error sending handshake request: %v", err)
	}

	// 读取响应
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	// 解析控制响应消息
	response, err := parsePPTPControlResponse(buf[:n])
	if err != nil {
		return "", fmt.Errorf("error parsePPTPControlResponse: %v", err)
	}

	// 返回接收到的数据
	return printPPTPControlResponse(response), nil
}

// 解析 PPTP 控制响应消息
func parsePPTPControlResponse(data []byte) (*common.PPTPControlResponse, error) {
	response := &common.PPTPControlResponse{}
	buf := bytes.NewReader(data)

	// 解析 Magic Cookie (4 字节)
	err := binary.Read(buf, binary.BigEndian, &response.Length)
	if err != nil {
		return nil, err
	}
	// 解析 Magic Cookie (4 字节)
	err = binary.Read(buf, binary.BigEndian, &response.MessageType)
	if err != nil {
		return nil, err
	}
	// 解析 Magic Cookie (4 字节)
	err = binary.Read(buf, binary.BigEndian, &response.MagicCookie)
	if err != nil {
		return nil, err
	}

	// 解析控制消息类型 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.ControlMessageType)
	if err != nil {
		return nil, err
	}

	// 解析保留字段 (2 字节)
	err = binary.Read(buf, binary.BigEndian, &response.Reserved)
	if err != nil {
		return nil, err
	}

	// 解析协议版本 (2 字节)
	err = binary.Read(buf, binary.BigEndian, &response.ProtocolVersion)
	if err != nil {
		return nil, err
	}

	// 解析结果码 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.ResultCode)
	if err != nil {
		return nil, err
	}

	// 解析错误码 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.ErrorCode)
	if err != nil {
		return nil, err
	}

	// 解析帧能力 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.FramingCapabilities)
	if err != nil {
		return nil, err
	}

	// 解析承载能力 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.BearerCapabilities)
	if err != nil {
		return nil, err
	}

	// 解析最大通道数 (2 字节)
	err = binary.Read(buf, binary.BigEndian, &response.MaximumChannels)
	if err != nil {
		return nil, err
	}

	// 解析固件修订 (1 字节)
	err = binary.Read(buf, binary.BigEndian, &response.FirmwareRevision)
	if err != nil {
		return nil, err
	}

	// 解析主机名 (直到遇到 0 字节)
	response.HostName, err = readHostName(buf)
	if err != nil {
		return nil, err
	}

	response.VendorName, _, err = readVendorName(buf)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// 读取 Null 终止字符串并返回读取到的位置
func readHostName(buf *bytes.Reader) (string, error) {
	var str []byte

	// 循环读取字节直到遇到 0 字节
	for {
		b, err := buf.ReadByte()
		if err != nil {
			if err == io.EOF && len(str) > 0 {
				break
			}
			return "", err
		}
		if b == 0 {
			break
		}
		str = append(str, b)
	}

	// 计算读取的字节数
	return string(str), nil
}
func readVendorName(buf *bytes.Reader) (string, int, error) {
	var str []byte
	buf.Seek(92, 0)

	// 循环读取字节直到遇到 0 字节
	for {
		b, err := buf.ReadByte()
		if err != nil {
			if err == io.EOF && len(str) > 0 {
				break
			}
			return "", 0, err
		}
		if b == 0 {
			continue
		}
		str = append(str, b)
	}

	// 计算读取的字节数
	return string(str), buf.Len(), nil
}

// 打印 PPTP 控制响应的详细信息
func printPPTPControlResponse(response *common.PPTPControlResponse) string {
	var builder strings.Builder

	// 使用 fmt.Fprintf 将格式化的输出写入 builder
	fmt.Fprintf(&builder, "Length %d\n", response.Length)
	fmt.Fprintf(&builder, "Magic Cookie: 0x%x\n", response.MagicCookie)
	fmt.Fprintf(&builder, "Message Type: Control Message (%d) \n", response.MessageType)
	fmt.Fprintf(&builder, "Control Message Type: Start-Control-Connection-Reply (%d) \n", response.ControlMessageType)
	fmt.Fprintf(&builder, "Reserved: 0x%x\n", response.Reserved)
	fmt.Fprintf(&builder, "Protocol Version: %d.0\n", response.ProtocolVersion)
	fmt.Fprintf(&builder, "Result Code: Successful channel establishment (%d) \n", response.ResultCode)
	fmt.Fprintf(&builder, "Error Code: None (%d) \n", response.ErrorCode)
	fmt.Fprintf(&builder, "Framing Capabilities: Synchronous Framing supported (%d)\n", response.FramingCapabilities)
	fmt.Fprintf(&builder, "Bearer Capabilities: Unknown (%d)\n", response.BearerCapabilities)
	fmt.Fprintf(&builder, "Maximum Channels: %d\n", response.MaximumChannels)
	fmt.Fprintf(&builder, "Firmware Revision: %d\n", response.FirmwareRevision)
	fmt.Fprintf(&builder, "Host Name: %s\n", response.HostName)
	fmt.Fprintf(&builder, "Vendor Name: %s\n", response.VendorName)

	// 返回 builder.String()，以获取最终的字符串输出
	return builder.String()
}

// 判断响应是否符合 RDP 特征
func isRDPResponse(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	// RDP协议一般前2字节是 0x03 0x00
	return data[0] == 0x03 && data[1] == 0x00
}

// 先裸 TCP 握手，确认 RDP 后升级 TLS
func detectRDPOverSSL(ip string, port int) (string, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("TCP dial error: %w", err)
	}
	// 如果最后升级 TLS 出错，conn 需要手动关闭
	// 这里先不defer，下面根据情况决定
	// defer conn.Close()

	// 1. 先发 RDP 协议的握手包（你抓包里拿到的）
	rdpNegotiationRequest := []byte{
		0x03, 0x00, 0x00, 0x2f,
		0x2a, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43,
		0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d,
		0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d,
		0x32, 0x34, 0x32, 0x33, 0x34, 0x39, 0x34, 0x30,
		0x38, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(rdpNegotiationRequest)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("write RDP negotiation error: %w", err)
	}

	resp := make([]byte, 1024)

	n, err := conn.Read(resp)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("read RDP negotiation response error: %w", err)
	}

	if !isRDPResponse(resp[:n]) {
		conn.Close()
		return "", errors.New("response does not match RDP pattern")
	}

	// 2. 升级为 TLS 连接，继续用 utls 在同一个连接上握手
	tlsConfig := &utls.Config{
		ServerName:         ip,
		InsecureSkipVerify: true,
		OmitEmptyPsk:       true, // 解决之前你遇到的 empty psk 问题
	}

	uconn := utls.UClient(conn, tlsConfig, utls.HelloChrome_120)
	uconn.SetDeadline(time.Now().Add(3 * time.Second))
	err = uconn.Handshake()
	if err != nil {
		uconn.Close()
		return "", fmt.Errorf("TLS handshake error: %w", err)
	}

	// 3. TLS 握手成功后，你可以继续读写 TLS 层数据，或返回成功标志
	return fmt.Sprintf("RDP over SSL detected, TLS handshake success, response prefix: %x", resp[:n]), nil
}

func RdpSSLParse(ip string, port int) string {

	info, err := detectRDPOverSSL(ip, port)
	if err != nil {
		return ""
	}
	return info

}

func ParseSMTPStartTLS(ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	// 全局超时，防止阻塞
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var buf bytes.Buffer
	tmp := make([]byte, 1024)

	// 直接发送 EHLO，不主动读取连接建立时的 banner
	_, err = conn.Write([]byte("EHLO test.com\r\n"))
	if err != nil {
		return ""
	}

	// 读取 EHLO 的响应
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			// 超时或 EOF 停止读取
			break
		}
	}

	return buf.String()
}

func ParseIMapStartTLS(ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var buf bytes.Buffer
	tmp := make([]byte, 1024)

	// 直接发送 IMAP 命令，不读取初始 banner
	_, err = conn.Write([]byte("a1 CAPABILITY\r\n"))
	if err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}

	return buf.String()
}

func ParsePop3StartTLS(ip string, port int) string {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var buf bytes.Buffer
	tmp := make([]byte, 1024)

	// 直接发送 IMAP 命令，不读取初始 banner
	_, err = conn.Write([]byte("STLS\r\n\r\n"))
	if err != nil {
		return ""
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}

	return buf.String()
}
