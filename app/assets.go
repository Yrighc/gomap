package appassets

import (
	"embed"
	"fmt"
)

//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/ftp.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt
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

func SecprobeDict(protocol string) ([]byte, error) {
	switch protocol {
	case "ftp":
		return files.ReadFile("secprobe/dicts/ftp.txt")
	case "mssql":
		return files.ReadFile("secprobe/dicts/mssql.txt")
	case "mysql":
		return files.ReadFile("secprobe/dicts/mysql.txt")
	case "postgresql":
		return files.ReadFile("secprobe/dicts/postgresql.txt")
	case "rdp":
		return files.ReadFile("secprobe/dicts/rdp.txt")
	case "redis":
		return files.ReadFile("secprobe/dicts/redis.txt")
	case "smb":
		return files.ReadFile("secprobe/dicts/smb.txt")
	case "ssh":
		return files.ReadFile("secprobe/dicts/ssh.txt")
	case "telnet":
		return files.ReadFile("secprobe/dicts/telnet.txt")
	case "vnc":
		return files.ReadFile("secprobe/dicts/vnc.txt")
	default:
		return nil, fmt.Errorf("unsupported secprobe dict protocol: %s", protocol)
	}
}
