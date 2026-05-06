package appassets

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed assetprobe/probes/gomap-service-probes assetprobe/services/gomap-services assetprobe/dicts/simple.txt assetprobe/dicts/normal.txt assetprobe/dicts/diff.txt secprobe/dicts/amqp.txt secprobe/dicts/ftp.txt secprobe/dicts/mongodb.txt secprobe/dicts/mssql.txt secprobe/dicts/mysql.txt secprobe/dicts/oracle.txt secprobe/dicts/postgresql.txt secprobe/dicts/rdp.txt secprobe/dicts/redis.txt secprobe/dicts/smb.txt secprobe/dicts/smtp.txt secprobe/dicts/snmp.txt secprobe/dicts/ssh.txt secprobe/dicts/telnet.txt secprobe/dicts/vnc.txt secprobe/protocols/*.yaml secprobe/templates/unauthorized/*.yaml
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
	case "amqp":
		return files.ReadFile("secprobe/dicts/amqp.txt")
	case "ftp":
		return files.ReadFile("secprobe/dicts/ftp.txt")
	case "mongodb":
		return files.ReadFile("secprobe/dicts/mongodb.txt")
	case "mssql":
		return files.ReadFile("secprobe/dicts/mssql.txt")
	case "mysql":
		return files.ReadFile("secprobe/dicts/mysql.txt")
	case "oracle":
		return files.ReadFile("secprobe/dicts/oracle.txt")
	case "postgresql":
		return files.ReadFile("secprobe/dicts/postgresql.txt")
	case "rdp":
		return files.ReadFile("secprobe/dicts/rdp.txt")
	case "redis":
		return files.ReadFile("secprobe/dicts/redis.txt")
	case "smb":
		return files.ReadFile("secprobe/dicts/smb.txt")
	case "smtp":
		return files.ReadFile("secprobe/dicts/smtp.txt")
	case "snmp":
		return files.ReadFile("secprobe/dicts/snmp.txt")
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
