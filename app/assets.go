package appassets

import (
	"embed"
	"fmt"
)

//go:embed gomap-service-probes gomap-services dict-simple.txt dict-normal.txt dict-diff.txt secprobe-ftp.txt secprobe-mysql.txt secprobe-postgresql.txt secprobe-redis.txt secprobe-ssh.txt secprobe-telnet.txt
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

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "ftp":
		return files.ReadFile("secprobe-ftp.txt")
	case "mysql":
		return files.ReadFile("secprobe-mysql.txt")
	case "postgresql":
		return files.ReadFile("secprobe-postgresql.txt")
	case "redis":
		return files.ReadFile("secprobe-redis.txt")
	case "ssh":
		return files.ReadFile("secprobe-ssh.txt")
	case "telnet":
		return files.ReadFile("secprobe-telnet.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", protocol)
	}
}
