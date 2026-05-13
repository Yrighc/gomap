package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"

	gmysql "github.com/go-sql-driver/mysql"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

const mysqlVersionQuery = "SELECT @@version;"

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	host := result.ResolvedIP
	if host == "" {
		host = result.Target
	}

	cfg := gmysql.Config{
		User:                 result.Username,
		Passwd:               result.Password,
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(host, strconv.Itoa(result.Port)),
		Timeout:              opts.Timeout,
		ReadTimeout:          opts.Timeout,
		WriteTimeout:         opts.Timeout,
		AllowNativePasswords: true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
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

	var version string
	if err := db.QueryRowContext(queryCtx, mysqlVersionQuery).Scan(&version); err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}

	result.Enrichment = map[string]any{"payload": fmt.Sprintf("%s\n\n%s", mysqlVersionQuery, version)}
	return result
}
