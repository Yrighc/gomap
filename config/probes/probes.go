package probes

// 解析 nmap-service-probes 文件，提取探针和匹配规则
import (
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/logger"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
)

var mu sync.Mutex

func parseServiceProbes(serviceProbes string) (common.Nmap, error) {
	var nmap common.Nmap
	nmap.PortToProbes = make(map[int][]common.MapValue)
	nmap.NullProbeMatchRules = []common.MatchRule{} // 初始化为空

	lines := strings.Split(serviceProbes, "\n")
	var currentRule *common.ProbeRule

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Probe ") {
			// 保存当前规则并开始新规则解析
			if currentRule != nil {
				// 确保每次保存 MapValue 时，Msg 中的 MatchRules 是一个新的切片
				mapValue := common.MapValue{
					Protocol:   currentRule.Protocol,
					ProbeBytes: currentRule.ProbeBytes,
					Msg:        append([]common.MatchRule(nil), currentRule.MatchRules...), // 使用新的切片，避免引用问题
				}
				mu.Lock()
				for _, port := range currentRule.Ports {
					nmap.PortToProbes[port] = append(nmap.PortToProbes[port], mapValue)
				}
				mu.Unlock()

				// 如果 ProbeName 是 NULL，将 match 规则存入 NullProbeMatchRules
				if currentRule.ProbeName == "NULL" {
					nmap.NullProbeMatchRules = append(nmap.NullProbeMatchRules, currentRule.MatchRules...)
				}
			}

			// 开始解析新规则
			currentRule = &common.ProbeRule{
				ProbeName:  parseProbeName(line),
				Protocol:   parseProtocol(line),
				ProbeBytes: parseProbeBytes(line),
			}
		} else if strings.HasPrefix(line, "ports") {
			if currentRule != nil {
				currentRule.Ports = parsePorts(line)
			}
		} else if strings.HasPrefix(line, "sslports") {
			// 解析 sslports，并将端口添加到 currentRule.Ports
			if currentRule != nil {
				sslPorts := parsePorts(line) // 使用 parsePorts 函数解析 sslports
				mu.Lock()
				currentRule.Ports = append(currentRule.Ports, sslPorts...)
				for _, port := range sslPorts {
					common.SslPortsMap[port] = true
				}
				mu.Unlock()
			}
		} else if strings.HasPrefix(line, "match") || strings.HasPrefix(line, "softmatch") {
			if currentRule != nil {
				matchRule := parseMatchRule(line)
				if matchRule.Name != "" {
					// 将 match 规则追加到当前 Probe 的 MatchRules 中
					currentRule.MatchRules = append(currentRule.MatchRules, matchRule)
				}
			}
		}
	}

	// 处理最后一个Probe规则
	if currentRule != nil {
		// 确保最后保存时，Msg 中的 MatchRules 是新的切片
		mapValue := common.MapValue{
			Protocol:   currentRule.Protocol,
			ProbeBytes: currentRule.ProbeBytes,
			Msg:        append([]common.MatchRule(nil), currentRule.MatchRules...), // 使用新的切片，避免引用问题
		}
		for _, port := range currentRule.Ports {
			nmap.PortToProbes[port] = append(nmap.PortToProbes[port], mapValue)
		}

		// 如果 ProbeName 是 NULL，将 match 规则存入 NullProbeMatchRules
		if currentRule.ProbeName == "NULL" {
			nmap.NullProbeMatchRules = append(nmap.NullProbeMatchRules, currentRule.MatchRules...)
		}
	}

	return nmap, nil
}

func parseProbeName(line string) string {
	// 修改正则表达式，确保匹配到完整的 Probe 名称
	re := regexp.MustCompile(`^Probe\s([A-Za-z0-9\-]+)\s+([A-Za-z0-9\-_]+)\s+q\|`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 2 {
		return matches[2] // 返回 Probe 名称（第一个匹配项）
	}
	return ""
}

func parseProtocol(line string) string {
	re := regexp.MustCompile(`^Probe\s([A-Za-z0-9\-]+)\s([A-Za-z]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func parseProbeBytes(line string) string {
	re := regexp.MustCompile(`^Probe\s([A-Za-z0-9\-]+)\s+([A-Za-z0-9\-_]+)\sq\|([^|]+)\|`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 3 {
		return matches[3]
	}
	return ""
}

func parsePorts(line string) []int {
	// 修改正则表达式，分别匹配 ports 和 sslports
	re := regexp.MustCompile(`(?:ports|sslports)\s*([\d, \-]+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) > 1 {
		ports := []int{}
		portRanges := strings.Split(matches[1], ",")
		for _, portRange := range portRanges {
			portRange = strings.TrimSpace(portRange)
			if strings.Contains(portRange, "-") {
				parts := strings.Split(portRange, "-")
				startPort := strToInt(parts[0])
				endPort := strToInt(parts[1])
				for i := startPort; i <= endPort; i++ {
					ports = append(ports, i)
				}
			} else {
				ports = append(ports, strToInt(portRange))
			}
		}
		return ports
	}
	return nil
}

// 解析 Match 规则
func parseMatchRule(line string) common.MatchRule {
	// 使用 regexp2 支持 Perl 兼容的正则表达式

	// re1 := regexp2.MustCompile(`^(match|softmatch)\s([A-Za-z0-9\-/]+)\s+m\|([^|]+)\|[si]\s*(?:p/([^/]+))?\s*(?:o/([^/]+))?\s*(?:cpe:/([^/]+))?`, 0)
	// re2 := regexp2.MustCompile(`^(match|softmatch)\s([A-Za-z0-9\-/]+)\s+([m|s]\|.+?\|)\s*(?:p/([^/]+))?\s*(?:o/([^/]+))?\s*(?:cpe:/([^/]+))?`, 0)
	re1 := regexp2.MustCompile(`^(match|softmatch)\s([A-Za-z0-9\-/]+)\s+m\|([^|]+)\|[si]\s*(?:p(?:/([^/]+)/|\|([^|]+)\|))?\s*(?:o/([^/]+))?\s*(?:cpe:/([^/]+))?`, 0)
	re2 := regexp2.MustCompile(`^(match|softmatch)\s([A-Za-z0-9\-/]+)\s+([m|s]\|.+?\|)\s*(?:p(?:/([^/]+)/|\|([^|]+)\|))?\s*(?:o/([^/]+))?\s*(?:cpe:/([^/]+))?`, 0)
	// 尝试匹配第一个正则表达式
	matches, _ := re1.FindStringMatch(line)
	if matches == nil {
		// 如果第一个正则表达式不匹配，则尝试第二个正则表达式
		matches, _ = re2.FindStringMatch(line)
	}
	// 只在 Match Name 非空时返回 MatchRule
	if matches != nil && matches.GroupByNumber(1).String() != "" {
		rawRegex := matches.GroupByNumber(3).String()
		cleanRegex := strings.TrimPrefix(rawRegex, "m|") // 去掉 m|
		cleanRegex = strings.TrimSuffix(cleanRegex, "|") // 去掉 |

		serviceVal := matches.GroupByNumber(4).String()
		if serviceVal == "" || serviceVal == "/" {
			serviceVal = matches.GroupByNumber(5).String()
		}

		// 如果有 \0 替换为 \\0
		return common.MatchRule{
			Name:  matches.GroupByNumber(2).String(),
			Regex: regexp2.MustCompile(cleanRegex, 0),
			// Service: matches.GroupByNumber(4).String(),
			Service: serviceVal,
			System:  matches.GroupByNumber(5).String(),
			CPE:     matches.GroupByNumber(6).String(),
		}
	}
	// 如果 Name 为空，则返回一个空的 MatchRule
	return common.MatchRule{}
}

func strToInt(s string) int {
	result, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return result
}

func QueryProbes(nmapData common.Nmap, port int) []common.MapValue {
	// 尝试通过端口查询 PortToProbes
	if probes, exists := nmapData.PortToProbes[port]; exists {
		// 找到对应的Probe，返回匹配规则
		return probes
	}
	// 如果未找到，返回 NullProbeMatchRules 中的规则
	return nil
}

func ProbesMatch() {
	if err := ProbesMatchFromFile(""); err != nil {
		logger.Info("Error loading probes:", err)
	}
}

func ExtractAllHTTPRules() {
	common.AllHTTPRules = common.AllHTTPRules[:0]
	probeList, ok := common.NmapData.PortToProbes[443]
	if !ok {
		return // 如果 443 没有配置规则，直接返回
	}
	for _, probe := range probeList {
		for _, rule := range probe.Msg {
			if strings.HasPrefix(strings.ToLower(rule.Name), "http") {
				common.AllHTTPRules = append(common.AllHTTPRules, rule)
			}
		}
	}
}

func ProbesMatchFromFile(serviceProbesPath string) error {
	path := serviceProbesPath
	if path == "" {
		path = firstExistingPath(
			"./config/gomap-service-probes",
			"./app/gomap-service-probes",
		)
	}
	if path == "" {
		return os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	common.NmapData, err = parseServiceProbes(string(data))
	if err != nil {
		return err
	}
	logger.Infof("Probes loaded successfully from %s", path)
	return nil
}

func ProbesMatchFromBytes(data []byte, source string) error {
	var err error
	common.NmapData, err = parseServiceProbes(string(data))
	if err != nil {
		return err
	}
	if source == "" {
		source = "embedded"
	}
	logger.Infof("Probes loaded successfully from %s", source)
	return nil
}

func firstExistingPath(candidates ...string) string {
	for _, p := range candidates {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if _, err := os.Stat(clean); err == nil {
			return clean
		}
	}
	return ""
}

// 端口号到正则表达式的映射
//
//	var PortToRegex = map[int][]struct {
//		Regex   *regexp.Regexp
//		Service string
//	}{
//
//		80: {
//			{nil, "HTTP"},
//		},
//		22: {
//			{regexp.MustCompile(`(?i)SSH-2.0`), "SSH"},
//		},
//		21: {
//			{regexp.MustCompile(`(?i)220 Welcome to virtual FTP service.`), "FTP"},
//			{regexp.MustCompile(`(?i)220 ftpd ready`), "FTP"},
//		},
//		53: {
//			{nil, "DNS"},
//			{nil, "DNS-TCP"},
//		},
//		443: {
//			{nil, "HTTPS"},
//		},
//		8080: {
//			{nil, "HTTPS"},
//		},
//		8443: {
//			{nil, "HTTPS"},
//		},
//	}
//
