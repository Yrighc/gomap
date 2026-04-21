package telnet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "telnet" }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "telnet"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		FindingType: core.FindingTypeCredentialValid,
	}

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			result.Error = err.Error()
			return result
		}

		conn, err := net.DialTimeout("tcp", addr, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		reader := bufio.NewReader(conn)

		if _, err := reader.ReadString(':'); err != nil {
			result.Error = err.Error()
			_ = conn.Close()
			return result
		}
		if _, err := fmt.Fprintf(conn, "%s\n", cred.Username); err != nil {
			result.Error = err.Error()
			_ = conn.Close()
			return result
		}

		if _, err := reader.ReadString(':'); err != nil {
			result.Error = err.Error()
			_ = conn.Close()
			return result
		}
		if _, err := fmt.Fprintf(conn, "%s\n", cred.Password); err != nil {
			result.Error = err.Error()
			_ = conn.Close()
			return result
		}

		line, err := reader.ReadString('\n')
		_ = conn.Close()
		if err == nil && strings.Contains(line, "Welcome") {
			result.Success = true
			result.Username = cred.Username
			result.Password = cred.Password
			result.Evidence = "Telnet authentication succeeded"
			return result
		}
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "authentication failed"
		}
	}

	return result
}
