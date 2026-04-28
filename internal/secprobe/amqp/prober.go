package amqp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

type amqpClient interface {
	Channel() (amqpChannel, error)
	Close() error
}

type amqpChannel interface {
	Close() error
}

type amqpConfig struct {
	timeout time.Duration
}

type amqpConnection struct {
	conn *amqp091.Connection
}

func (c *amqpConnection) Channel() (amqpChannel, error) {
	return c.conn.Channel()
}

func (c *amqpConnection) Close() error {
	return c.conn.Close()
}

var dialAMQP = defaultDialAMQP

func New() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "amqp" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "amqp"
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
			result.FailureReason = classifyAMQPFailure(err)
			return result
		}
		if !attempted {
			attempted = true
			result.Stage = core.StageAttempted
		}

		client, err := dialAMQP(ctx, buildAMQPURL(candidate, cred), amqpConfig{timeout: opts.Timeout})
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyAMQPFailure(err)
			if result.FailureReason == core.FailureReasonCanceled || result.FailureReason == core.FailureReasonTimeout {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		channel, err := client.Channel()
		if err == nil {
			closeAMQPChannel(channel)
			_ = client.Close()
			successResult.Success = true
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "AMQP authentication succeeded and channel opened"
			successResult.Error = ""
			successResult.Stage = core.StageConfirmed
			successResult.FailureReason = ""
			successFound = true
			if opts.StopOnSuccess {
				return successResult
			}
			continue
		}

		closeAMQPChannel(channel)
		_ = client.Close()
		result.Error = err.Error()
		result.FailureReason = classifyAMQPFailure(err)
		if result.FailureReason == core.FailureReasonCanceled || result.FailureReason == core.FailureReasonTimeout {
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

func buildAMQPURL(candidate core.SecurityCandidate, cred core.Credential) string {
	scheme := "amqp"
	if candidate.Port == 5671 {
		scheme = "amqps"
	}

	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	return (&url.URL{
		Scheme: scheme,
		User:   url.UserPassword(cred.Username, cred.Password),
		Host:   net.JoinHostPort(host, strconv.Itoa(candidate.Port)),
		Path:   "/",
	}).String()
}

func defaultDialAMQP(ctx context.Context, rawURL string, cfg amqpConfig) (amqpClient, error) {
	host := amqpHost(rawURL)
	dialer := &net.Dialer{Timeout: cfg.timeout}
	config := amqp091.Config{
		Heartbeat: cfg.timeout,
		Dial: func(network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if cfg.timeout > 0 {
				_ = conn.SetDeadline(time.Now().Add(cfg.timeout))
			}
			return conn, nil
		},
	}
	if strings.HasPrefix(rawURL, "amqps://") {
		config.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}
	}

	conn, err := amqp091.DialConfig(rawURL, config)
	if err != nil {
		return nil, err
	}
	return &amqpConnection{conn: conn}, nil
}

func classifyAMQPFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	var amqpErr *amqp091.Error
	if errors.As(err, &amqpErr) {
		switch amqpErr.Code {
		case 403:
			return core.FailureReasonAuthentication
		case 504:
			return core.FailureReasonConnection
		}
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "access_refused"), strings.Contains(text, "login was refused"), strings.Contains(text, "authentication"), strings.Contains(text, "unauthorized"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "tls"), strings.Contains(text, "handshake"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"), strings.Contains(text, "channel_error"), strings.Contains(text, "channel.open"):
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

func closeAMQPChannel(ch amqpChannel) {
	if ch == nil {
		return
	}
	_ = ch.Close()
}

func amqpHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
