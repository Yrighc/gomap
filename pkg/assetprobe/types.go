package assetprobe

import "time"

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Options struct {
	// Concurrency 控制端口扫描阶段的并发 worker 数量。
	Concurrency int
	// Timeout 是单次网络探测的基础超时时间。
	Timeout time.Duration
	// DisableWeakPassword 控制是否关闭弱口令探测逻辑。
	DisableWeakPassword bool
	// DetectHomepage 控制是否对 HTTP 类端口执行首页识别。
	DetectHomepage bool
	// MaxFingerprintPorts 限制最多对多少个开放端口做深度服务指纹识别。
	MaxFingerprintPorts int
	// HoneypotOpenThreshold 是疑似蜜罐判定所需的最小开放端口数量阈值。
	HoneypotOpenThreshold int
	// HoneypotOpenRatio 是疑似蜜罐判定所需的开放端口占比阈值，范围通常为 0~1。
	HoneypotOpenRatio float64
	// ConsoleLog 控制日志是否同时输出到控制台。
	ConsoleLog bool
	// ProbesFile 是自定义服务探针文件路径，留空时使用仓库内默认探针。
	ProbesFile string
	// ServicesFile 是自定义服务映射文件路径，留空时使用仓库内默认映射。
	ServicesFile string
	// DisableLogging 控制是否完全关闭日志输出。
	DisableLogging bool
}

type ScanRequest struct {
	// Target 是扫描目标，可以是 IP 或域名。
	Target string
	// Ports 是显式传入的端口列表。
	Ports []int
	// PortSpec 是形如 "80,443,1-1024" 的端口表达式。
	PortSpec string
	// Protocol 指定本次扫描使用 tcp 还是 udp。
	Protocol Protocol
	// Concurrency 用于覆盖 Scanner 默认并发配置。
	Concurrency int
	// Timeout 用于覆盖 Scanner 默认超时配置。
	Timeout time.Duration
	// MaxFingerprintPorts 用于覆盖最多参与服务识别的开放端口数量。
	MaxFingerprintPorts int
	// HoneypotOpenThreshold 用于覆盖疑似蜜罐判定的开放端口数量阈值。
	HoneypotOpenThreshold int
	// HoneypotOpenRatio 用于覆盖疑似蜜罐判定的开放占比阈值。
	HoneypotOpenRatio float64
}

type ScanResult struct {
	// Target 是请求中的原始目标。
	Target string
	// ResolvedIP 是最终用于连接的解析后 IP。
	ResolvedIP string
	// Protocol 是本次扫描实际使用的协议。
	Protocol Protocol
	// Meta 是本次扫描的统计与诊断信息。
	Meta ScanMeta
	// Ports 是最终返回的开放端口结果列表。
	Ports []PortResult
}

type ScanMeta struct {
	// OpenPorts 是扫描范围内被判定为开放的端口总数。
	OpenPorts int
	// FingerprintedOpenPorts 是开放端口中实际完成深度服务识别的数量。
	FingerprintedOpenPorts int
	// SkippedFingerprintPorts 是因达到指纹识别上限而被跳过深度识别的开放端口数量。
	SkippedFingerprintPorts int
	// SuspectedHoneypot 表示该目标是否命中疑似蜜罐/伪全开判定规则。
	SuspectedHoneypot bool
	// HoneypotReason 是疑似蜜罐判定命中的具体原因文本。
	HoneypotReason string
}

type PortResult struct {
	// Port 是当前结果对应的端口号。
	Port int
	// Open 表示该端口是否开放。
	Open bool
	// Service 是识别出的服务名，如 ssh、http、mysql。
	Service string
	// Version 是识别出的服务版本信息。
	Version string
	// Banner 是服务返回的原始特征文本。
	Banner string
	// Subject 是 TLS 证书主题等扩展识别信息。
	Subject string
	// DNSNames 是 TLS 证书 SAN 中提取出的域名列表。
	DNSNames []string
}

type HomepageResult struct {
	// URL 是首页识别最终访问成功的地址。
	URL string
	// Title 是页面标题。
	Title string
	// StatusCode 是首页 HTTP 状态码。
	StatusCode int
	// ContentLength 是首页响应体长度。
	ContentLength int64
	// Server 是响应头中的服务端标识。
	Server string
	// HTMLHash 是首页 HTML 内容指纹。
	HTMLHash string
	// FaviconHash 是站点 favicon 指纹。
	FaviconHash string
	// ICP 是首页提取出的备案信息。
	ICP string
}

type DirResult struct {
	// Target 是目录爆破目标的原始 host。
	Target string
	// ResolvedIP 是目标 host 解析后的 IP。
	ResolvedIP string
	// Port 是本次目录爆破实际访问的端口。
	Port int
	// Homepage 是目录爆破之前探测到的首页信息。
	Homepage *HomepageResult
	// Paths 是目录爆破识别出的有效路径列表。
	Paths []PathResult
}

type DirBruteLevel string

const (
	DirBruteSimple DirBruteLevel = "simple"
	DirBruteNormal DirBruteLevel = "normal"
	DirBruteDiff   DirBruteLevel = "diff"
)

type DirBruteOptions struct {
	// Enable 控制是否启用目录爆破。
	Enable bool
	// Level 指定内置字典级别。
	Level DirBruteLevel
	// CustomDictFile 指定自定义字典文件路径。
	CustomDictFile string
	// MaxPaths 限制最多加载多少条字典路径，0 表示不限制。
	MaxPaths int
	// Concurrency 控制目录爆破阶段的并发数。
	Concurrency int
}

type PathResult struct {
	// URL 是识别出的有效路径完整地址。
	URL string
	// Title 是该路径页面的标题。
	Title string
	// StatusCode 是该路径响应的 HTTP 状态码。
	StatusCode int
	// ContentLength 是该路径响应体长度。
	ContentLength int64
	// HTMLHash 是该路径页面的 HTML 内容指纹。
	HTMLHash string
}
