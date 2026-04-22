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

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

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
	successResult := result
	successFound := false

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
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
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "Telnet authentication succeeded"
			successResult.Error = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "authentication failed"
		}
	}

	if successFound {
		return successResult
	}
	return result
}
