package secprobe

import (
	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
	elasticsearchprobe "github.com/yrighc/gomap/internal/secprobe/elasticsearch"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	imapprobe "github.com/yrighc/gomap/internal/secprobe/imap"
	mongodbprobe "github.com/yrighc/gomap/internal/secprobe/mongodb"
	mssqlprobe "github.com/yrighc/gomap/internal/secprobe/mssql"
	mysqlprobe "github.com/yrighc/gomap/internal/secprobe/mysql"
	oracledbprobe "github.com/yrighc/gomap/internal/secprobe/oracle"
	postgresqlprobe "github.com/yrighc/gomap/internal/secprobe/postgresql"
	rdpprobe "github.com/yrighc/gomap/internal/secprobe/rdp"
	redisprobe "github.com/yrighc/gomap/internal/secprobe/redis"
	smbprobe "github.com/yrighc/gomap/internal/secprobe/smb"
	smtpprobe "github.com/yrighc/gomap/internal/secprobe/smtp"
	snmpprobe "github.com/yrighc/gomap/internal/secprobe/snmp"
	sshprobe "github.com/yrighc/gomap/internal/secprobe/ssh"
	telnetprobe "github.com/yrighc/gomap/internal/secprobe/telnet"
	vncprobe "github.com/yrighc/gomap/internal/secprobe/vnc"
	zookeeperprobe "github.com/yrighc/gomap/internal/secprobe/zookeeper"
	"github.com/yrighc/gomap/pkg/secprobe/template"
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.RegisterAtomicCredential("ssh", sshprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("ftp", ftpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("imap", imapprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mssql", mssqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mysql", mysqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("postgresql", postgresqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("redis", redisprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("elasticsearch", elasticsearchprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("smtp", smtpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("telnet", telnetprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("amqp", amqpprobe.NewAuthenticator(nil))

	// Temporary builtin bridge until phase 5 cleanup.
	r.RegisterAtomicCredential("oracle", oracledbprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("rdp", rdpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("vnc", vncprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("smb", smbprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("snmp", snmpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mongodb", mongodbprobe.NewAuthenticator(nil))
	r.RegisterAtomicUnauthorized("redis", redisprobe.NewUnauthorizedChecker(nil))
	if templates, err := template.LoadBuiltinUnauthorized(); err == nil {
		if tpl, ok := templates["memcached"]; ok {
			r.RegisterAtomicUnauthorized("memcached", template.NewUnauthorizedChecker(tpl, nil))
		}
	}

	r.registerCoreProber(mongodbprobe.NewUnauthorized())
	r.registerCoreProber(zookeeperprobe.NewUnauthorized())
	r.registerCoreProber(redisprobe.NewUnauthorized())
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	RegisterDefaultProbers(r)
	return r
}
