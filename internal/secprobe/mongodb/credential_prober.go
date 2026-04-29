package mongodb

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoCredentialClient interface {
	ListDatabaseNames(context.Context, any) ([]string, error)
	Disconnect(context.Context) error
}

type mongoCredentialClientAdapter struct {
	client *mongo.Client
}

func (a mongoCredentialClientAdapter) ListDatabaseNames(ctx context.Context, filter any) ([]string, error) {
	return a.client.ListDatabaseNames(ctx, filter)
}

func (a mongoCredentialClientAdapter) Disconnect(ctx context.Context) error {
	return a.client.Disconnect(ctx)
}

var openMongoCredentialClient = func(ctx context.Context, candidate core.SecurityCandidate, timeout time.Duration, cred core.Credential) (mongoCredentialClient, error) {
	clientOptions := options.Client().
		ApplyURI(mongoCredentialURI(candidate, cred)).
		SetServerSelectionTimeout(timeout).
		SetConnectTimeout(timeout).
		SetSocketTimeout(timeout)

	connectCtx := ctx
	connectCancel := func() {}
	if timeout > 0 {
		connectCtx, connectCancel = context.WithTimeout(ctx, timeout)
	}
	client, err := mongo.Connect(connectCtx, clientOptions)
	connectCancel()
	if err != nil {
		return nil, err
	}
	return mongoCredentialClientAdapter{client: client}, nil
}

func New() core.Prober { return credentialProber{} }

type credentialProber struct{}

func (credentialProber) Name() string { return "mongodb" }

func (credentialProber) Kind() core.ProbeKind { return core.ProbeKindCredential }

func (credentialProber) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "mongodb"
}

func (credentialProber) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, creds []core.Credential) core.SecurityResult {
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

	for _, cred := range creds {
		if err := ctx.Err(); err != nil {
			if successFound {
				return successResult
			}
			result.Error = err.Error()
			result.FailureReason = classifyMongoCredentialFailure(err)
			return result
		}

		result.Stage = core.StageAttempted

		client, err := openMongoCredentialClient(ctx, candidate, opts.Timeout, cred)
		if err != nil {
			result.Error = err.Error()
			result.FailureReason = classifyMongoCredentialFailure(err)
			if isTerminalMongoCredentialFailure(result.FailureReason) {
				if successFound {
					return successResult
				}
				return result
			}
			continue
		}

		func() {
			disconnectCtx := context.Background()
			disconnectCancel := func() {}
			if opts.Timeout > 0 {
				disconnectCtx, disconnectCancel = context.WithTimeout(context.Background(), opts.Timeout)
			}
			defer disconnectCancel()
			defer func() {
				_ = client.Disconnect(disconnectCtx)
			}()

			confirmCtx := ctx
			confirmCancel := func() {}
			if opts.Timeout > 0 {
				confirmCtx, confirmCancel = context.WithTimeout(ctx, opts.Timeout)
			}
			names, listErr := client.ListDatabaseNames(confirmCtx, bson.D{})
			confirmCancel()
			if listErr != nil {
				result.Error = listErr.Error()
				result.FailureReason = classifyMongoCredentialFailure(listErr)
				if isTerminalMongoCredentialFailure(result.FailureReason) {
					return
				}
				return
			}
			if len(names) == 0 {
				result.Error = "listDatabaseNames returned no visible databases"
				result.FailureReason = core.FailureReasonInsufficientConfirmation
				return
			}

			successResult = result
			successResult.Success = true
			successResult.Stage = core.StageConfirmed
			successResult.Username = cred.Username
			successResult.Password = cred.Password
			successResult.Evidence = "listDatabaseNames succeeded after authentication"
			successResult.Error = ""
			successResult.FailureReason = ""
			successResult.Capabilities = []core.Capability{core.CapabilityEnumerable}
			successFound = true
		}()

		if isTerminalMongoCredentialFailure(result.FailureReason) {
			if successFound {
				return successResult
			}
			return result
		}

		if successFound && opts.StopOnSuccess {
			return successResult
		}
	}

	if successFound {
		return successResult
	}
	return result
}

func mongoCredentialURI(candidate core.SecurityCandidate, cred core.Credential) string {
	host := candidate.ResolvedIP
	if host == "" {
		host = candidate.Target
	}

	uri := &url.URL{
		Scheme:   "mongodb",
		Host:     net.JoinHostPort(host, strconv.Itoa(candidate.Port)),
		Path:     "/",
		RawQuery: "directConnection=true",
		User:     url.UserPassword(cred.Username, cred.Password),
	}
	return uri.String()
}

func classifyMongoCredentialFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"),
		strings.Contains(text, "authentication"),
		strings.Contains(text, "requires authentication"),
		strings.Contains(text, "not authorized"),
		strings.Contains(text, "unauthorized"),
		strings.Contains(text, "sasl"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "server selection"),
		strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func isTerminalMongoCredentialFailure(reason core.FailureReason) bool {
	return reason == core.FailureReasonCanceled || reason == core.FailureReasonTimeout
}
