package snmp

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

const sysDescrOID = ".1.3.6.1.2.1.1.1.0"

type snmpClient interface {
	Connect() error
	Get(oids []string) (string, error)
	Close() error
}

type goSNMPClient struct {
	client *gosnmp.GoSNMP
}

func (c *goSNMPClient) Connect() error { return c.client.Connect() }

func (c *goSNMPClient) Close() error {
	if c.client.Conn != nil {
		return c.client.Conn.Close()
	}
	return nil
}

func (c *goSNMPClient) Get(oids []string) (string, error) {
	packet, err := c.client.Get(oids)
	if err != nil {
		return "", err
	}
	if len(packet.Variables) == 0 {
		return "", errors.New("snmp returned no variables")
	}
	return packet.Variables[0].Name, nil
}

var openSNMP = func(_ context.Context, candidate core.SecurityCandidate, community string, timeout time.Duration) (snmpClient, error) {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(candidate.Port),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   0,
	}
	return &goSNMPClient{client: client}, nil
}

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "snmp" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "snmp"
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

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		client, err := openSNMP(ctx, candidate, cred.Password, opts.Timeout)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			if isTerminalSNMPFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		if err := client.Connect(); err != nil {
			_ = client.Close()
			result.Error = err.Error()
			result.FailureReason = classifySNMPFailure(err)
			if isTerminalSNMPFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		_, err = client.Get([]string{sysDescrOID})
		_ = client.Close()
		if err == nil {
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "SNMP v2c community succeeded"
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
		result.FailureReason = classifySNMPFailure(err)
		if isTerminalSNMPFailure(result.FailureReason) {
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

func classifySNMPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "authorization"), strings.Contains(text, "community"), strings.Contains(text, "unknowncommunityname"), strings.Contains(text, "noaccess"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "udp"), strings.Contains(text, "refused"), strings.Contains(text, "no route"):
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

func isTerminalSNMPFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}
