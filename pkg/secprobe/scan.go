package secprobe

import (
	"context"
	"strings"
)

func Scan(_ context.Context, req ScanRequest) ScanResult {
	if strings.TrimSpace(req.Target) == "" {
		return ScanResult{Error: "target is required"}
	}
	if len(req.Services) == 0 {
		return ScanResult{
			Target:     req.Target,
			ResolvedIP: req.ResolvedIP,
			Error:      "services is required",
		}
	}
	return ScanResult{
		Target:     req.Target,
		ResolvedIP: req.ResolvedIP,
	}
}
