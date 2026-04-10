package appassets

import (
	"embed"
	"fmt"
)

//go:embed gomap-service-probes gomap-services dict-simple.txt dict-normal.txt dict-diff.txt
var files embed.FS

func ServiceProbes() ([]byte, error) {
	return files.ReadFile("gomap-service-probes")
}

func Services() ([]byte, error) {
	return files.ReadFile("gomap-services")
}

func Dict(level string) ([]byte, error) {
	switch level {
	case "simple":
		return files.ReadFile("dict-simple.txt")
	case "normal":
		return files.ReadFile("dict-normal.txt")
	case "diff":
		return files.ReadFile("dict-diff.txt")
	default:
		return nil, fmt.Errorf("unsupported dict level: %s", level)
	}
}
