package assetprobe

import "time"

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Options struct {
	Concurrency         int
	Timeout             time.Duration
	DisableWeakPassword bool
	DetectHomepage      bool
	ProbesFile          string
	ServicesFile        string
	DisableLogging      bool
}

type ScanRequest struct {
	Target         string
	Ports          []int
	PortSpec       string
	Protocol       Protocol
	Concurrency    int
	Timeout        time.Duration
	DetectHomepage *bool
	DirBrute       *DirBruteOptions
}

type ScanResult struct {
	Target     string
	ResolvedIP string
	Protocol   Protocol
	Ports      []PortResult
}

type PortResult struct {
	Port     int
	Open     bool
	Service  string
	Version  string
	Banner   string
	Subject  string
	DNSNames []string
	WeakUser string
	WeakPass string
	Homepage *HomepageResult
	Error    string
}

type HomepageResult struct {
	URL           string
	Title         string
	StatusCode    int
	ContentLength int64
	Server        string
	HTMLHash      string
	FaviconHash   string
	ICP           string
	Paths         []PathResult
}

type DirBruteLevel string

const (
	DirBruteSimple DirBruteLevel = "simple"
	DirBruteNormal DirBruteLevel = "normal"
	DirBruteDiff   DirBruteLevel = "diff"
)

type DirBruteOptions struct {
	Enable         bool
	Level          DirBruteLevel
	CustomDictFile string
	MaxPaths       int
	Concurrency    int
}

type PathResult struct {
	URL           string
	Title         string
	StatusCode    int
	ContentLength int64
	HTMLHash      string
}
