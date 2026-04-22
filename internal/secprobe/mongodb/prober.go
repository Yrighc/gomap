package mongodb

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewUnauthorized() core.Prober { return prober{} }

type prober struct{}

func (prober) Name() string { return "mongodb-unauthorized" }

func (prober) Kind() core.ProbeKind { return core.ProbeKindUnauthorized }

func (prober) Match(candidate core.SecurityCandidate) bool {
	return candidate.Service == "mongodb"
}

func (prober) Probe(ctx context.Context, candidate core.SecurityCandidate, opts core.CredentialProbeOptions, _ []core.Credential) core.SecurityResult {
	result := core.SecurityResult{
		Target:      candidate.Target,
		ResolvedIP:  candidate.ResolvedIP,
		Port:        candidate.Port,
		Service:     candidate.Service,
		ProbeKind:   core.ProbeKindUnauthorized,
		FindingType: core.FindingTypeUnauthorizedAccess,
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMongoUnauthorizedFailure(err)
		return result
	}

	uri := mongoURI(candidate.ResolvedIP, candidate.Port)
	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(opts.Timeout).
		SetConnectTimeout(opts.Timeout).
		SetSocketTimeout(opts.Timeout)

	result.Stage = core.StageAttempted

	connectCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	client, err := mongo.Connect(connectCtx, clientOptions)
	cancel()
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMongoUnauthorizedFailure(err)
		return result
	}
	defer func() {
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), opts.Timeout)
		_ = client.Disconnect(disconnectCtx)
		disconnectCancel()
	}()

	listCtx, listCancel := context.WithTimeout(ctx, opts.Timeout)
	names, err := client.ListDatabaseNames(listCtx, bson.D{})
	listCancel()
	if err != nil {
		result.Error = err.Error()
		result.FailureReason = classifyMongoUnauthorizedFailure(err)
		return result
	}
	if len(names) == 0 {
		result.Error = "listDatabaseNames returned no visible databases"
		result.FailureReason = core.FailureReasonInsufficientConfirmation
		return result
	}

	result.Success = true
	result.Stage = core.StageConfirmed
	result.Capabilities = []core.Capability{core.CapabilityEnumerable}
	result.Evidence = "listDatabaseNames succeeded without authentication"
	return result
}

func mongoURI(host string, port int) string {
	return fmt.Sprintf("mongodb://%s/?directConnection=true", net.JoinHostPort(host, strconv.Itoa(port)))
}

func classifyMongoUnauthorizedFailure(err error) core.FailureReason {
	if err == nil {
		return ""
	}
	if reason := ctxFailureReason(err); reason != "" {
		return reason
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "auth"), strings.Contains(text, "authentication"), strings.Contains(text, "requires authentication"), strings.Contains(text, "not authorized"), strings.Contains(text, "unauthorized"):
		return core.FailureReasonAuthentication
	case strings.Contains(text, "server selection"), strings.Contains(text, "dial"), strings.Contains(text, "connect"), strings.Contains(text, "connection"), strings.Contains(text, "refused"), strings.Contains(text, "reset by peer"), strings.Contains(text, "no route"):
		return core.FailureReasonConnection
	default:
		return core.FailureReasonInsufficientConfirmation
	}
}

func ctxFailureReason(err error) core.FailureReason {
	text := strings.ToLower(err.Error())
	switch {
	case err == context.Canceled, strings.Contains(text, "context canceled"):
		return core.FailureReasonCanceled
	case err == context.DeadlineExceeded, strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return core.FailureReasonTimeout
	default:
		return ""
	}
}
