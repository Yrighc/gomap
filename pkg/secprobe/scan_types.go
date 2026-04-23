package secprobe

import "time"

type ScanRequest struct {
	Target             string
	ResolvedIP         string
	Services           []ScanService
	Timeout            time.Duration
	Concurrency        int
	StopOnSuccess      bool
	EnableEnrichment   bool
	EnableUnauthorized bool
}

type ScanService struct {
	Port    int
	Service string
	Version string
	Banner  string
}

type ScanResult struct {
	Target     string
	ResolvedIP string
	Meta       SecurityMeta
	Results    []SecurityResult
	Error      string
}
