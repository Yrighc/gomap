package updservices

// UDP 服务探测
import (
	"bytes"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/probes"
	"github.com/yrighc/gomap/internal/achieve"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

func UcpPortServer(ip string, port int, buf []byte, conn net.Conn) (string, string, string, string, string) {

	var banner, subject, dns, service, version string

	// 设置超时时间为 3 秒
	timeout := 3 * time.Second

	// 输出解析后的结果
	result := probes.QueryProbes(common.NmapData, port)

	for _, rule := range result {

		if rule.Protocol == "UDP" {

			var probeBytes []byte
			if strings.Contains(rule.ProbeBytes, "\\x") {
				probeBytes, _ = achieve.HexStringToBytes(rule.ProbeBytes)
			} else {
				rule.ProbeBytes = strings.ReplaceAll(rule.ProbeBytes, "\\r", "\r")
				rule.ProbeBytes = strings.ReplaceAll(rule.ProbeBytes, "\\n", "\n")
				probeBytes = []byte(rule.ProbeBytes)
			}
			if len(probeBytes) == 0 {
				probeBytes, _ = achieve.SpecialStringToBytes(rule.ProbeBytes)
			}

			// 创建UDP连接
			conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
			if err != nil {
				continue
			}
			defer conn.Close()

			// 写入 ProbeBytes 数据
			_, err = conn.Write(probeBytes)
			if err != nil {
				continue
			}

			// 使用 select 实现超时机制
			readCh := make(chan string, 1) // 用于读取数据的 channel
			go func() {
				n, err := conn.Read(buf) // 在 goroutine 中读取数据
				if err != nil {
				} else {
					var read string
					decoder := charmap.ISO8859_1.NewDecoder()
					reader := transform.NewReader(bytes.NewReader(buf[:n]), decoder)

					// 读取并转换为字符串
					convertedString, err := ioutil.ReadAll(reader)
					if err != nil {
						read = string(buf[:n])
					} else {
						read = string(convertedString)
					}
					readCh <- read // 将读取到的数据发送到 channel
				}
			}()

			select {
			case response := <-readCh:
				banner = response
				// 匹配正则
				for _, rule := range rule.Msg {
					match, _ := rule.Regex.FindStringMatch(response)
					if match != nil {
						service = rule.Name
						version = rule.Service
						return banner, subject, dns, service, version
					}
				}
				for _, rule := range common.NmapData.NullProbeMatchRules {
					match, _ := rule.Regex.FindStringMatch(response)
					if match != nil {
						service = rule.Name
						version = rule.Service
						return banner, subject, dns, service, version
					}
				}

			case <-time.After(timeout):
				continue
			}
		}
	}
	if service == "" {
		if common.ServiceMap[port]["udp"] != "" {
			service = common.ServiceMap[port]["udp"] + "?"
		} else {
			service = ""
		}
	}

	return banner, subject, dns, service, version
}
