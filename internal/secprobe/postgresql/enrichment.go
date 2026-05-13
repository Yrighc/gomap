package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	host := result.ResolvedIP
	if host == "" {
		host = result.Target
	}

	connectTimeout := int(math.Ceil(opts.Timeout.Seconds()))
	if connectTimeout < 1 {
		connectTimeout = 1
	}

	dsn := (&url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(result.Username, result.Password),
		Host:   net.JoinHostPort(host, strconv.Itoa(result.Port)),
		Path:   "/",
		RawQuery: url.Values{
			"dbname":          []string{"postgres"},
			"sslmode":         []string{"disable"},
			"connect_timeout": []string{strconv.Itoa(connectTimeout)},
		}.Encode(),
	}).String()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}
	defer func() { _ = db.Close() }()

	queryCtx := ctx
	cancel := func() {}
	if opts.Timeout > 0 {
		queryCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	defer cancel()

	var response string
	if err := db.QueryRowContext(queryCtx, "SELECT version();").Scan(&response); err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}

	result.Enrichment = map[string]any{"payload": fmt.Sprintf("SELECT version();\n\n%s", response)}
	return result
}
