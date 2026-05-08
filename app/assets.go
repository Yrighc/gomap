package appassets

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/passwords/global.txt secprobe/protocols/*.yaml secprobe/templates/unauthorized/*.yaml
var files embed.FS

func ServiceProbes() ([]byte, error) {
	return files.ReadFile("assetprobe/probes/gomap-service-probes")
}

func Services() ([]byte, error) {
	return files.ReadFile("assetprobe/services/gomap-services")
}

func Dict(level string) ([]byte, error) {
	switch level {
	case "simple":
		return files.ReadFile("assetprobe/dicts/simple.txt")
	case "normal":
		return files.ReadFile("assetprobe/dicts/normal.txt")
	case "diff":
		return files.ReadFile("assetprobe/dicts/diff.txt")
	default:
		return nil, fmt.Errorf("unsupported dict level: %s", level)
	}
}

func SecprobePasswordSource(source string) ([]byte, error) {
	switch source {
	case "builtin:passwords/global":
		return files.ReadFile("secprobe/dicts/passwords/global.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe password source: %s", source)
	}
}

func SecprobeProtocolFiles() ([]string, error) {
	return fs.Glob(files, "secprobe/protocols/*.yaml")
}

func SecprobeProtocol(name string) ([]byte, error) {
	return files.ReadFile("secprobe/protocols/" + name)
}

func SecprobeUnauthorizedTemplate(name string) ([]byte, error) {
	return files.ReadFile("secprobe/templates/unauthorized/" + name)
}

func SecprobeUnauthorizedTemplateFiles() ([]string, error) {
	return fs.Glob(files, "secprobe/templates/unauthorized/*.yaml")
}
