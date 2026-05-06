package secprobe

import (
	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
	ftpprobe "github.com/yrighc/gomap/internal/secprobe/ftp"
	memcachedprobe "github.com/yrighc/gomap/internal/secprobe/memcached"
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
	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

	r.RegisterAtomicCredential("ssh", sshprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("ftp", ftpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mssql", mssqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mysql", mysqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("postgresql", postgresqlprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("redis", redisprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("smtp", smtpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("telnet", telnetprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("amqp", amqpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("oracle", registrybridge.LegacyCredentialAdapter{Prober: oracledbprobe.New()})
	r.RegisterAtomicCredential("rdp", registrybridge.LegacyCredentialAdapter{Prober: rdpprobe.New()})
	r.RegisterAtomicCredential("vnc", registrybridge.LegacyCredentialAdapter{Prober: vncprobe.New()})
	r.RegisterAtomicCredential("smb", registrybridge.LegacyCredentialAdapter{Prober: smbprobe.New()})
	r.RegisterAtomicCredential("snmp", registrybridge.LegacyCredentialAdapter{Prober: snmpprobe.New()})
	r.RegisterAtomicCredential("mongodb", registrybridge.LegacyCredentialAdapter{Prober: mongodbprobe.New()})
	r.RegisterAtomicUnauthorized("redis", redisprobe.NewUnauthorizedChecker(nil))

	r.registerCoreProber(sshprobe.New())
	r.registerCoreProber(ftpprobe.New())
	r.registerCoreProber(mssqlprobe.New())
	r.registerCoreProber(mysqlprobe.New())
	r.registerCoreProber(postgresqlprobe.New())
	r.registerCoreProber(oracledbprobe.New())
	r.registerCoreProber(mongodbprobe.New())
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
	r.registerCoreProber(zookeeperprobe.NewUnauthorized())
	r.registerCoreProber(rdpprobe.New())
	r.registerCoreProber(redisprobe.New())
	r.registerCoreProber(redisprobe.NewUnauthorized())
	r.registerCoreProber(snmpprobe.New())
	r.registerCoreProber(smbprobe.New())
	r.registerCoreProber(smtpprobe.New())
	r.registerCoreProber(amqpprobe.New())
	r.registerCoreProber(telnetprobe.New())
	r.registerCoreProber(vncprobe.New())
	r.registerCoreProber(memcachedprobe.NewUnauthorized())
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	RegisterDefaultProbers(r)
	return r
}
