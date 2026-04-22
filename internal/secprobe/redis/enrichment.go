package redis

import (
	"context"
	"net"
	"strconv"
	"strings"

	gredis "github.com/redis/go-redis/v9"
	"github.com/yrighc/gomap/internal/secprobe/core"
)

const (
	infoExcerptMaxLines = 6
	infoExcerptMaxChars = 240
)

func Enrich(ctx context.Context, result core.SecurityResult, opts core.CredentialProbeOptions) core.SecurityResult {
	host := result.ResolvedIP
	if host == "" {
		host = result.Target
	}

	client := gredis.NewClient(&gredis.Options{
		Addr:         net.JoinHostPort(host, strconv.Itoa(result.Port)),
		Username:     result.Username,
		Password:     result.Password,
		DialTimeout:  opts.Timeout,
		ReadTimeout:  opts.Timeout,
		WriteTimeout: opts.Timeout,
	})
	defer func() { _ = client.Close() }()

	infoCtx := ctx
	cancel := func() {}
	if opts.Timeout > 0 {
		infoCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}
	defer cancel()

	info, err := client.Info(infoCtx, "server").Result()
	if err != nil {
		result.Enrichment = map[string]any{"error": err.Error()}
		return result
	}

	result.Enrichment = map[string]any{"info_excerpt": trimInfo(info)}
	return result
}

func trimInfo(info string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(info, "\r\n", "\n"))
	if normalized == "" {
		return ""
	}

	lines := strings.Split(normalized, "\n")
	excerptLines := make([]string, 0, infoExcerptMaxLines)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		excerptLines = append(excerptLines, line)
		if len(excerptLines) == infoExcerptMaxLines {
			break
		}
	}

	excerpt := strings.Join(excerptLines, "\n")
	if len(excerpt) <= infoExcerptMaxChars {
		return excerpt
	}
	return strings.TrimSpace(excerpt[:infoExcerptMaxChars])
}
