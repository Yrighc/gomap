package amqp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type fakeAMQPClient struct {
	channelErr   error
	channelCalls int
	closeCalls   int
}

func (c *fakeAMQPClient) Channel() (amqpChannel, error) {
	c.channelCalls++
	if c.channelErr != nil {
		return nil, c.channelErr
	}
	return &fakeAMQPChannel{}, nil
}

func (c *fakeAMQPClient) Close() error {
	c.closeCalls++
	return nil
}

type fakeAMQPChannel struct {
	closeCalls int
	closeErr   error
}

func (c *fakeAMQPChannel) Close() error {
	c.closeCalls++
	return c.closeErr
}

func TestAuthenticatorAuthenticateOnceReturnsCredentialValid(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return nil
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mq.internal",
		IP:       "127.0.0.1",
		Port:     5672,
		Protocol: "amqp",
	}, strategy.Credential{Username: "guest", Password: "guest"})

	if !out.Result.Success || out.Result.FindingType != result.FindingTypeCredentialValid {
		t.Fatalf("unexpected attempt %+v", out)
	}
}

func TestAuthenticatorAuthenticateOnceMapsAuthenticationFailure(t *testing.T) {
	auth := NewAuthenticator(func(context.Context, strategy.Target, strategy.Credential) error {
		return errors.New("Exception (403) Reason: \"ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN\"")
	})

	out := auth.AuthenticateOnce(context.Background(), strategy.Target{
		Host:     "mq.internal",
		IP:       "127.0.0.1",
		Port:     5672,
		Protocol: "amqp",
	}, strategy.Credential{Username: "guest", Password: "wrong"})

	if out.Result.ErrorCode != result.ErrorCodeAuthentication {
		t.Fatalf("expected authentication code, got %+v", out)
	}
}

func TestAMQPProberFindsValidCredentialAfterChannelConfirmation(t *testing.T) {
	originalDial := dialAMQP
	t.Cleanup(func() {
		dialAMQP = originalDial
	})

	var dialedURLs []string
	client := &fakeAMQPClient{}
	dialAMQP = func(_ context.Context, rawURL string, _ amqpConfig) (amqpClient, error) {
		dialedURLs = append(dialedURLs, rawURL)
		return client, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mq.internal",
		ResolvedIP: "127.0.0.1",
		Port:       5672,
		Service:    "amqp",
	}, core.CredentialProbeOptions{
		Timeout:       5 * time.Second,
		StopOnSuccess: true,
	}, []core.Credential{
		{Username: "guest", Password: "guest"},
	})

	if !result.Success {
		t.Fatalf("expected amqp success, got %+v", result)
	}
	if result.Stage != core.StageConfirmed {
		t.Fatalf("expected confirmed stage, got %+v", result)
	}
	if result.FindingType != core.FindingTypeCredentialValid {
		t.Fatalf("expected credential-valid finding type, got %+v", result)
	}
	if result.FailureReason != "" {
		t.Fatalf("expected empty failure reason on success, got %+v", result)
	}
	if result.Evidence == "" {
		t.Fatalf("expected success evidence, got %+v", result)
	}
	if client.channelCalls != 1 {
		t.Fatalf("expected exactly one channel confirmation, got %d", client.channelCalls)
	}
	if client.closeCalls != 1 {
		t.Fatalf("expected client close on success, got %d", client.closeCalls)
	}
	if len(dialedURLs) != 1 || dialedURLs[0] != "amqp://guest:guest@127.0.0.1:5672/" {
		t.Fatalf("unexpected dial urls: %v", dialedURLs)
	}
}

func TestAMQPProberClassifiesAuthenticationFailure(t *testing.T) {
	originalDial := dialAMQP
	t.Cleanup(func() {
		dialAMQP = originalDial
	})

	dialAMQP = func(context.Context, string, amqpConfig) (amqpClient, error) {
		return nil, errors.New("Exception (403) Reason: \"ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN\"")
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mq.internal",
		ResolvedIP: "127.0.0.1",
		Port:       5672,
		Service:    "amqp",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "guest", Password: "wrong"},
	})

	if result.Success {
		t.Fatalf("expected amqp failure, got %+v", result)
	}
	if result.Stage != core.StageAttempted {
		t.Fatalf("expected attempted stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonAuthentication {
		t.Fatalf("expected authentication failure reason, got %+v", result)
	}
}

func TestAMQPProberDoesNotConfirmConnectionWithoutChannel(t *testing.T) {
	originalDial := dialAMQP
	t.Cleanup(func() {
		dialAMQP = originalDial
	})

	client := &fakeAMQPClient{channelErr: errors.New("Exception (504) Reason: \"CHANNEL_ERROR - expected 'channel.open'\"")}
	dialAMQP = func(context.Context, string, amqpConfig) (amqpClient, error) {
		return client, nil
	}

	result := New().Probe(context.Background(), core.SecurityCandidate{
		Target:     "mq.internal",
		ResolvedIP: "127.0.0.1",
		Port:       5672,
		Service:    "amqp",
	}, core.CredentialProbeOptions{
		Timeout: 5 * time.Second,
	}, []core.Credential{
		{Username: "guest", Password: "guest"},
	})

	if result.Success {
		t.Fatalf("expected amqp failure when channel open fails, got %+v", result)
	}
	if result.Stage == core.StageConfirmed {
		t.Fatalf("expected channel failure to avoid confirmed stage, got %+v", result)
	}
	if result.FailureReason != core.FailureReasonConnection {
		t.Fatalf("expected connection failure reason for channel failure, got %+v", result)
	}
}

func TestBuildAMQPURLUsesAMQPSForPort5671(t *testing.T) {
	got := buildAMQPURL(core.SecurityCandidate{
		ResolvedIP: "10.0.0.8",
		Port:       5671,
		Service:    "amqp",
	}, core.Credential{
		Username: "guest",
		Password: "s3cret",
	})

	if got != "amqps://guest:s3cret@10.0.0.8:5671/" {
		t.Fatalf("expected amqps url, got %q", got)
	}
}
