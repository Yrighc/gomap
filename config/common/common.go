package common

// 公共变量
import (
	"time"

	"github.com/dlclark/regexp2"
)

var KafkaParams Config

var NmapData Nmap            // 存储 Nmap 规则数据
var AllHTTPRules []MatchRule // 存储所有 HTTP 规则
var SslPortsMap = make(map[int]bool)
var ServiceMap = make(map[int]map[string]string)

var TotalPackets int64     // 包的总数
var LastTime time.Time     // 上次打印时间
var StartTime time.Time    // 上次打印时间
var LastTotalPackets int64 // 上次记录的包总数

var TotalCompletedTasks int64 // 用于记录已完成的任务数
var TotalTasks int64          // 用于记录总任务数
var FoundPort int64           // 用于记录发现端口数

// // 定时任务全局变量
// var (
// 	DelayedSpiderTargets []DelayedSpiderTarget
// 	DelayedSpiderMutex   sync.Mutex
// )

type DelayedSpiderTarget struct {
	IP     string
	Port   int
	SSL    bool
	Target string
	ICMP   bool
}

type KafkaRevice struct {
	Target  string
	Address string
	Ports   []string
	Types   DetectType
	Output  OutputType
	Ping    bool
	MaxRate int32
	IpSize  string
}

type DetectType struct {
	IP     int
	DOMAIN int
}
type OutputType struct {
	REMOTE int
	LOCAL  int
}

type Command struct {
	Detail      bool
	Rate        int
	Agreement   string
	Port        []int
	IP          []string
	DisablePing bool
	UnWeak      bool
	Timeout     int
	Global      bool
	Distribute  bool
	ChromeUrls  []string
	SpiderUrls  []string
	Explosion   int
}

type ResultJson struct {
	IP        string
	Reachable string
	Port      int
	Service   string
	Version   string
	ICMP      bool
	Weak      UsePwd
	Banner    string
	Subject   string
	DNS       string
	Host      string
}
type GlobalJson struct {
	IP        string `json:"iP"`        // ip
	Reachable string `json:"reachable"` //解析ip
	Port      int    `json:"port"`      //端口号
	Service   string `json:"service"`   //协议类型
	Version   string `json:"version"`   //服务名
	ICMP      bool   `json:"icmp"`      //ping通情况
	Banner    string `json:"banner"`    //返回响应
	Subject   string `json:"subject"`   //证书
	DNS       string `json:"dns"`       //dns
	Http      struct {
		Server          string              `json:"server"`    //http内部server
		Path            string              `json:"path"`      //路径
		HTMLHash        string              `json:"html_hash"` //html哈希值
		ResponseHeaders map[string][]string // ✅ 改成Map格式
		ContentLength   int64
		ContentType     string `json:"content_type"` //内容类型
		StatusCode      int    `json:"status_code"`  //状态码
		Favicon         struct {
			Location string `json:"location"` //icon地址
			Data     string `json:"data"`     //icon数据
			Hash     string `json:"hash"`     //icon哈希值
		} `json:"favicon"`
		Host          string   `json:"host"`          //host ip
		Body          string   `json:"body"`          //响应体
		Title         string   `json:"title"`         //标题
		ICP           string   `json:"icp"`           //icp备案号
		RedirectChain []string `json:"redirectChain"` //重定向链
	} `json:"http"`
}

type UsePwd struct {
	Username string
	Password string
}

type WeakJson struct {
	IP        string
	Reachable string
	Port      int
	Service   string
	Version   string
	Weak      UsePwd
}

type HostInfo struct {
	Original   string // 原始输入（域名或IP）
	ResolvedIP string // 解析后的IP
}

type DockerVersion struct {
	Version       string `json:"Version"`
	ApiVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	GitCommit     string `json:"GitCommit"`
	GoVersion     string `json:"GoVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
	BuildTime     string `json:"BuildTime"`
}

// 定义 PPTP 控制消息的响应结构
type PPTPControlResponse struct {
	Length              uint16 // 长度
	MessageType         uint16 // 消息类型
	MagicCookie         uint32 // Magic Cookie
	ControlMessageType  uint16 // 控制消息类型
	Reserved            uint16 // 保留字段
	ProtocolVersion     uint16 // 协议版本
	ResultCode          uint8  // 结果码
	ErrorCode           uint8  // 错误码
	FramingCapabilities uint32 // 帧能力
	BearerCapabilities  uint32 // 承载能力
	MaximumChannels     uint16 // 最大通道数
	FirmwareRevision    uint16 // 固件修订
	HostName            string // 主机名
	VendorName          string // 供应商名
}

// Nmap 存储所有 Probe 规则
type Nmap struct {
	PortToProbes        map[int][]MapValue // 键是端口号，值是对应的Probe列表
	NullProbeMatchRules []MatchRule        // 当未查到端口号
}

// MapValue 存储每个端口对应的协议、字节内容以及匹配规则
type MapValue struct {
	Protocol   string      // 协议类型，如 TCP 或 UDP
	ProbeBytes string      // 请求的字节内容
	Msg        []MatchRule // 匹配规则
}

// MatchRule 存储每个match规则的信息
type MatchRule struct {
	Name    string          // The name of the match (e.g., 3m-sip)
	Regex   *regexp2.Regexp // 正则表达式对象
	Service string          // The service name (e.g., /pStandard Interchange Protocol 2.0)
	System  string          // Additional info (e.g., o/Integrated Library System authentication)
	CPE     string          // CPE identifier (e.g., cpe:/a:civica:spydus)
}

// ProbeRule 存储每个Probe的相关信息
type ProbeRule struct {
	ProbeName  string      // The probe type (e.g., RPCCheck)
	Protocol   string      // TCP or UDP
	ProbeBytes string      // 请求的字节内容
	Ports      []int       // List of ports this probe applies to
	MatchRules []MatchRule // List of match rules associated with the probe
}

type Config struct {
	App struct {
		Name string `yaml:"name"`
	} `yaml:"app"`
	Server struct {
		Consumer struct {
			Host          string `yaml:"host"`
			NmapTopic     string `yaml:"nmap-consumer-topic"`
			NmapGroupId   string `yaml:"nmap-group-id"`
			SpiderTopic   string `yaml:"spider-consumer-topic"`
			SpiderGroupId string `yaml:"spider-group-id"`
			KatanaTopic   string `yaml:"katana-consumer-topic"`
			KatanaGroupId string `yaml:"katana-group-id"`
		} `yaml:"consumer"`
		Producer struct {
			Host        string `yaml:"host"`
			ServerTopic string `yaml:"server-topic"`
			SpiderTopic string `yaml:"spider-topic"`
			KatanaTopic string `yaml:"katana-topic"`
		} `yaml:"producer"`
	} `yaml:"server"`
	WorkFlow struct {
		Consumer struct {
			Host          string `yaml:"host"`
			NmapTopic     string `yaml:"nmap-consumer-topic"`
			NmapGroupId   string `yaml:"nmap-group-id"`
			SpiderTopic   string `yaml:"spider-consumer-topic"`
			SpiderGroupId string `yaml:"spider-group-id"`
			KatanaTopic   string `yaml:"katana-consumer-topic"`
			KatanaGroupId string `yaml:"katana-group-id"`
		} `yaml:"consumer"`
		Producer struct {
			Host        string `yaml:"host"`
			ServerTopic string `yaml:"server-topic"`
			SpiderTopic string `yaml:"spider-topic"`
			KatanaTopic string `yaml:"katana-topic"`
		} `yaml:"producer"`
		Control struct {
			StartPauseTopic   string `yaml:"start-pause-topic"`
			StartPauseGroupId string `yaml:"start-pause-group-id"`
		} `yaml:"control"`
	} `yaml:"workflow"`
	APT struct {
		Consumer struct {
			Host        string `yaml:"host"`
			NmapTopic   string `yaml:"nmap-consumer-topic"`
			NmapGroupId string `yaml:"nmap-group-id"`
		} `yaml:"consumer"`
		Producer struct {
			Host        string `yaml:"host"`
			ServerTopic string `yaml:"server-topic"`
		} `yaml:"producer"`
	} `yaml:"apt"`
	Goclei struct {
		Consumer struct {
			Host          string `yaml:"host"`
			GocleiTopic   string `yaml:"goclei-consumer-topic"`
			GocleiGroupId string `yaml:"goclei-group-id"`
		} `yaml:"consumer"`
		Producer struct {
			Host        string `yaml:"host"`
			ServerTopic string `yaml:"server-topic"`
		} `yaml:"producer"`
	} `yaml:"goclei"`
	SSL struct {
		EnableSSL bool `yaml:"enable-ssl"`
		SASL      struct {
			Username string `yaml:"username"`
			Password string `yaml:"password"`
		} `yaml:"sasl"`
	} `yaml:"ssl"`
	Domain struct {
		NmapScan   bool `yaml:"nmap-scan"`   // 是否启用端口扫描
		SpiderScan bool `yaml:"spider-scan"` // 是否启用站点扫描
		LinkScan   bool `yaml:"link-scan"`   // 是否启用链接检测
	} `yaml:"domain"`
}

type KatanaRequest struct {
	Method    string `json:"method"`
	Endpoint  string `json:"endpoint"`
	Tag       string `json:"tag"`
	Attribute string `json:"attribute"`
	Source    string `json:"source"`
	Raw       string `json:"raw"`
}

type KatanaOutput struct {
	Timestamp string        `json:"timestamp"`
	Request   KatanaRequest `json:"request"`
	Error     string        `json:"error"`
}

var (
	CmdORkafka = false
	Cmd        = Command{}
)
