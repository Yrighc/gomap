package mongodb

import (
	"context"
	"net"
	"net/url"
	"strconv"

	"github.com/yrighc/gomap/internal/secprobe/core"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	uri := mongoEnrichmentURI(result)
	clientOptions := options.Client().
		ApplyURI(uri).
		SetServerSelectionTimeout(opts.Timeout).
		SetConnectTimeout(opts.Timeout).
		SetSocketTimeout(opts.Timeout)

	connectCtx := ctx
	connectCancel := func() {}
	if opts.Timeout > 0 {
		connectCtx, connectCancel = context.WithTimeout(ctx, opts.Timeout)
	}
	client, err := mongo.Connect(connectCtx, clientOptions)
	connectCancel()
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	defer func() {
		disconnectCtx := context.Background()
		disconnectCancel := func() {}
		if opts.Timeout > 0 {
			disconnectCtx, disconnectCancel = context.WithTimeout(context.Background(), opts.Timeout)
		}
		_ = client.Disconnect(disconnectCtx)
		disconnectCancel()
	}()

	listCtx := ctx
	listCancel := func() {}
	if opts.Timeout > 0 {
		listCtx, listCancel = context.WithTimeout(ctx, opts.Timeout)
	}
	names, err := client.ListDatabaseNames(listCtx, bson.D{})
	listCancel()
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}

	result.Enrichment = map[string]any{"databases": names}
	return result
}

func mongoEnrichmentURI(result core.SecurityResult) string {
	host := result.ResolvedIP
	if host == "" {
		host = result.Target
	}
	if result.Username == "" && result.Password == "" {
		return mongoURI(host, result.Port)
	}

	uri := &url.URL{
		Scheme:   "mongodb",
		Host:     net.JoinHostPort(host, strconv.Itoa(result.Port)),
		Path:     "/",
		RawQuery: "directConnection=true",
		User:     url.UserPassword(result.Username, result.Password),
	}
	return uri.String()
}
