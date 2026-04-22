package mongodb

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/yrighc/gomap/internal/secprobe/core"
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
		return result
	}

	uri := mongoURI(candidate.ResolvedIP, candidate.Port)
	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(opts.Timeout).
		SetConnectTimeout(opts.Timeout).
		SetSocketTimeout(opts.Timeout)

	connectCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	client, err := mongo.Connect(connectCtx, clientOptions)
	cancel()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer func() {
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), opts.Timeout)
		_ = client.Disconnect(disconnectCtx)
		disconnectCancel()
	}()

	listCtx, listCancel := context.WithTimeout(ctx, opts.Timeout)
	_, err = client.ListDatabaseNames(listCtx, map[string]any{})
	listCancel()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Evidence = "listDatabaseNames succeeded without authentication"
	return result
}

func mongoURI(host string, port int) string {
	return fmt.Sprintf("mongodb://%s/?directConnection=true", net.JoinHostPort(host, strconv.Itoa(port)))
}
