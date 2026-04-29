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
)

func RegisterDefaultProbers(r *Registry) {
	if r == nil {
		return
	}

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
