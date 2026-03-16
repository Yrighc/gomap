package achieve

// 工具函数
import (
	"bufio"
	"bytes"
	"fmt"
	"gomap/config/common"
	"gomap/config/logger"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// pingHost 使用操作系统的 ping 命令检查主机是否可达
func PingHost(host string) bool {
	// 判断是否为 IPv6 地址
	ip := net.ParseIP(host)
	isIPv6 := ip != nil && ip.To4() == nil

	// 动态选择 ping 命令参数
	cmd := exec.Command("ping", "-c", "1", "-W", "3", host)
	if isIPv6 {
		// Linux/macOS 使用 ping6 或 ping -6
		if _, err := exec.LookPath("ping6"); err == nil {
			cmd = exec.Command("ping6", "-c", "1", "-w", "3", host)
		} else {
			cmd = exec.Command("ping", "-6", "-c", "1", "-W", "3", host)
		}
	}

	err := cmd.Run()
	return err == nil
}

// hexStringToBytes 将类似 "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x02\x04\0\x80\0" 的字符串转换为字节数组
func HexStringToBytes(hexStr string) ([]byte, error) {

	hexStr = strings.ReplaceAll(hexStr, "\\x", "")

	hexStr = strings.ReplaceAll(hexStr, "\\0", "00")

	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}

	var bytes []byte
	for i := 0; i < len(hexStr); i += 2 {
		byteValue, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid hex character: %v", err)
		}
		bytes = append(bytes, byte(byteValue))
	}

	return bytes, nil
}

func SpecialStringToBytes(hexStr string) ([]byte, error) {
	var bytes []byte
	i := 0
	for i < len(hexStr) {
		// 处理转义字符 \x 和 \0
		if hexStr[i] == '\\' {
			// 处理 \x 转义
			if i+1 < len(hexStr) && hexStr[i+1] == 'x' && i+3 < len(hexStr) {
				// 提取并解析十六进制字节
				hexByte := hexStr[i+2 : i+4]
				byteValue, err := strconv.ParseUint(hexByte, 16, 8)
				if err != nil {
					return nil, fmt.Errorf("invalid hex character: %v", err)
				}
				bytes = append(bytes, byte(byteValue))
				i += 4
			} else if i+1 < len(hexStr) && hexStr[i+1] == '0' {
				bytes = append(bytes, 0x00)
				i += 2
			} else {
				i++
			}
		} else {
			bytes = append(bytes, hexStr[i])
			i++
		}
	}

	return bytes, nil
}

// SanitizeUTF8 检查字符串是否为有效的 UTF-8 编码
func SanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return SanitizeString(s)
}

func HostParse(ip string) string {

	// 反向解析
	names, err := net.LookupAddr(ip)
	if err != nil {
		// logger.Infof("解析失败, ip :%s, err: %v", ip, err)
		return ""
	}

	return names[0]
}

func SanitizeString(s string) string {
	v := make([]rune, 0, len(s))
	for i, r := range s {
		if r == utf8.RuneError {
			_, size := utf8.DecodeRuneInString(s[i:])
			if size == 1 {
				continue // skip invalid rune
			}
		}
		v = append(v, r)
	}
	return string(v)
}

// 检查 ss -s 输出中的 TCP 总连接数
func WaitForTCPBelowThreshold(threshold int) {
	for {
		tcpCount, err := getTCPConnectionCount()
		if err != nil {
			logger.Info("Error getting TCP count:", err)
			time.Sleep(1 * time.Second)
			break
		}

		if tcpCount < threshold {
			logger.Infof("TCP 连接数符合标准")
			break
		}

		logger.Warnf("TCP 连接数越过标准，修复中")
		time.Sleep(2 * time.Second)
	}
}

// 解析 `ss -s` 输出，提取 TCP 总连接数
func getTCPConnectionCount() (int, error) {
	cmd := exec.Command("ss", "-s")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TCP:") {
			// 例如：TCP:   507 (estab 395, closed 82, orphaned 0, timewait 52)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				count, err := strconv.Atoi(fields[1])
				if err == nil {
					return count, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("TCP line not found or invalid")
}

// GetInstanceID 获取当前实例的唯一标识符
func GetInstanceID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return "gomap-machine-" + id
		}
	}

	// fallback 使用 PID，适合单机临时唯一标识
	pid := os.Getpid()
	return "gomap-pid-" + strconv.Itoa(pid)
}

// helper：把 topics 列表拼成一个字符串键
func MakeConsumerKey(groupID string, topics []string) string {
	// 假设 topics 里只有一个元素，你也可以 strings.Join(topics, ",")
	return groupID + "-" + topics[0]
}

func ExtractTopicFromErrorLog(msg string, topicToGroup map[string]string) string {
	for topic := range topicToGroup {
		if strings.Contains(msg, topic+"/") {
			return topic
		}
	}
	return ""
}

var ServiceBlasts = map[string]func(ip string, port int, ishttps bool) common.UsePwd{}
