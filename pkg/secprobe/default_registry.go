package secprobe

import (
	"context"

	amqpprobe "github.com/yrighc/gomap/internal/secprobe/amqp"
	"github.com/yrighc/gomap/internal/secprobe/core"
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
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
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

	// Temporary builtin bridge until phase 5 cleanup.
	r.RegisterAtomicCredential("oracle", oracledbprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("rdp", rdpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("vnc", vncprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("smb", smbprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("snmp", snmpprobe.NewAuthenticator(nil))
	r.RegisterAtomicCredential("mongodb", mongodbprobe.NewAuthenticator(nil))
	r.RegisterAtomicUnauthorized("redis", redisprobe.NewUnauthorizedChecker(nil))

	registerAtomicCredentialLookup(r, "ssh")
	registerAtomicCredentialLookup(r, "ftp")
	registerAtomicCredentialLookup(r, "mssql")
	registerAtomicCredentialLookup(r, "mysql")
	registerAtomicCredentialLookup(r, "postgresql")
	registerAtomicCredentialLookup(r, "oracle")
	registerAtomicCredentialLookup(r, "mongodb")
	r.registerCoreProber(mongodbprobe.NewUnauthorized())
	r.registerCoreProber(zookeeperprobe.NewUnauthorized())
	registerAtomicCredentialLookup(r, "rdp")
	registerAtomicCredentialLookup(r, "redis")
	r.registerCoreProber(redisprobe.NewUnauthorized())
	registerAtomicCredentialLookup(r, "snmp")
	registerAtomicCredentialLookup(r, "smb")
	registerAtomicCredentialLookup(r, "smtp")
	registerAtomicCredentialLookup(r, "amqp")
	registerAtomicCredentialLookup(r, "telnet")
	registerAtomicCredentialLookup(r, "vnc")
	r.registerCoreProber(memcachedprobe.NewUnauthorized())
}

func DefaultRegistry() *Registry {
	r := NewRegistry()
	RegisterDefaultProbers(r)
	return r
}

func registerAtomicCredentialLookup(r *Registry, protocol string) {
	if r == nil {
		return
	}

	auth, ok := r.atomicCredentials[canonicalRegistryProtocol(protocol)]
	if !ok {
		return
	}
	r.registerCoreProber(defaultAtomicCredentialLookup{
		protocol: canonicalRegistryProtocol(protocol),
		auth:     auth,
	})
}

type defaultAtomicCredentialLookup struct {
	protocol string
	auth     registrybridge.CredentialAuthenticator
}

func (p defaultAtomicCredentialLookup) Name() string {
	return p.protocol
}

func (p defaultAtomicCredentialLookup) Kind() core.ProbeKind {
	return core.ProbeKindCredential
}

func (p defaultAtomicCredentialLookup) Match(candidate core.SecurityCandidate) bool {
	return canonicalCandidateProtocol(SecurityCandidate(candidate)) == p.protocol
}

func (p defaultAtomicCredentialLookup) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	base := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	if p.auth == nil || len(creds) == 0 {
		base.FailureReason = core.FailureReasonInsufficientConfirmation
		return base
	}

	var latest core.SecurityResult
	for _, cred := range creds {
		attempt := p.auth.AuthenticateOnce(ctx, strategy.Target{
			Host:     candidate.Target,
			IP:       candidate.ResolvedIP,
			Port:     candidate.Port,
			Protocol: candidate.Service,
		}, strategy.Credential{
			Username: cred.Username,
			Password: cred.Password,
		})
		latest = normalizeDefaultCredentialResult(base, engineAttemptResult(SecurityCandidate(candidate), ProbeKindCredential, attempt), core.ProbeKindCredential)
		if latest.Success || opts.StopOnSuccess {
			return latest
		}
	}

	return latest
}

func normalizeDefaultCredentialResult(base core.SecurityResult, out core.SecurityResult, kind core.ProbeKind) core.SecurityResult {
	if out.Target == "" {
		out.Target = base.Target
	}
	if out.ResolvedIP == "" {
		out.ResolvedIP = base.ResolvedIP
	}
	if out.Port == 0 {
		out.Port = base.Port
	}
	if out.Service == "" {
		out.Service = base.Service
	}
	if out.ProbeKind == "" {
		out.ProbeKind = kind
	}
	if out.FindingType == "" {
		out.FindingType = core.FindingTypeCredentialValid
	}
	if out.FailureReason == "" && !out.Success {
		if parsed, ok := result.ParseErrorCode(out.Error); ok {
			out.FailureReason = core.FailureReason(parsed)
		} else {
			out.FailureReason = inferFailureReason(out.Error)
		}
	}
	return out
}
