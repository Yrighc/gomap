package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
	gssh "golang.org/x/crypto/ssh"
)

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "ssh" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "ssh"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindCredential,
		FindingType: core.FindingTypeCredentialValid,
	}
	successResult := result
	successFound := false
	attempted := false

	addr := net.JoinHostPort(candidate.ResolvedIP, strconv.Itoa(candidate.Port))
	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifySSHFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		config := &gssh.ClientConfig{
			User:            cred.Username,
			Auth:            []gssh.AuthMethod{gssh.Password(cred.Password)},
			HostKeyCallback: gssh.InsecureIgnoreHostKey(),
			Timeout:         opts.Timeout,
		}
		client, err := gssh.Dial("tcp", addr, config)
		if err == nil {
			_ = client.Close()
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "SSH authentication succeeded"
			successResult.Error = ""
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		result.Error = err.Error()
		result.FailureReason = classifySSHFailure(err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if successFound {
				return successResult
			}
			return result
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func classifySSHFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "authenticate"), strings.Contains(text, "authentication"), strings.Contains(text, "permission denied"), strings.Contains(text, "unable to authenticate"), strings.Contains(text, "no supported methods remain"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
