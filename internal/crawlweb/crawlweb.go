package crawlweb

// 爬取网页信息
import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/yrighc/gomap/config/common"
	"github.com/yrighc/gomap/config/logger"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/corpix/uarand"
)

const defaultHomepageTimeout = 10 * time.Second

func FetchWebInfo(fullURL string, useHTTPS bool) (*common.GlobalJson, error) {
	return FetchWebInfoWithContext(context.Background(), fullURL, useHTTPS)
}

// FetchWebInfoWithContext 使用一个整体截止时间；调用方可用 context deadline 覆盖默认 10 秒。
// 重定向、兼容重试和 favicon 继承同一截止时间，不重新获得完整预算。
func FetchWebInfoWithContext(ctx context.Context, fullURL string, useHTTPS bool) (info *common.GlobalJson, err error) {
	defer func() {
		if r := recover(); r != nil {
			info = nil
			err = fmt.Errorf("FetchWebInfo panic: %v", r)
		}
	}()
	ctx, cancel := homepageContext(ctx)
	defer cancel()
	info, err = doFetch(ctx, fullURL, false)
	if err != nil && ctx.Err() == nil && strings.Contains(err.Error(), "tls: handshake failure") {
		logger.Warnf("TLS handshake failure: %s，尝试兼容模式重试", fullURL)
		info, err = doFetch(ctx, fullURL, true)
	}
	return info, err
}

func homepageContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultHomepageTimeout)
}

func doFetch(ctx context.Context, fullURL string, compatibleTLS bool) (*common.GlobalJson, error) {
	client := createHTTPClient(compatibleTLS)

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")

	var finalPath string
	var redirectChain []string
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirectChain = append(redirectChain, req.URL.String())
		finalPath = req.URL.Path
		return nil
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if finalPath == "" {
		finalPath = resp.Request.URL.Path
	}

	// ✅ 设置最大读取大小
	limitedBody := http.MaxBytesReader(nil, resp.Body, 2*1024*1024)

	// 请求 context 同时约束响应头与正文读取，无需另启 goroutine 或刷新超时。
	bodyBytes, readErr := io.ReadAll(limitedBody)
	if readErr != nil {
		return nil, fmt.Errorf("读取 body 失败: %w", &net.OpError{Op: "read", Net: "http", Err: readErr})
	}

	hash := md5.Sum(bodyBytes)

	info := &common.GlobalJson{}
	info.Http.Server = resp.Header.Get("Server")
	info.Http.ContentType = resp.Header.Get("Content-Type")
	info.Http.Path = finalPath
	info.Http.HTMLHash = hex.EncodeToString(hash[:])
	info.Http.ResponseHeaders = copyHeaders(resp.Header)
	info.Http.ContentLength = int64(len(bodyBytes))
	info.Http.StatusCode = resp.StatusCode
	info.Http.Host = resp.Request.URL.Hostname()
	info.Http.Body = string(bodyBytes)
	info.Http.RedirectChain = redirectChain

	extractFavicon(ctx, info, bodyBytes, resp.Request.URL, client)
	extractTitleAndICP(info, bodyBytes)
	// 附属请求自己的超时可忽略，整个首页截止或取消不能伪装为成功。
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("首页探测未完成: %w", err)
	}
	return info, nil
}

func createHTTPClient(compatibleTLS bool) *http.Client {
	var tlsConf *tls.Config

	if compatibleTLS {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
		}
	} else {
		tlsConf = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConf,
			// DNS、TCP 和 TLS/响应读取统一受请求 context 约束，不设隐藏的更短时限。
			DialContext: (&net.Dialer{}).DialContext,
		},
	}
}

func extractFavicon(ctx context.Context, info *common.GlobalJson, html []byte, baseURL *url.URL, client *http.Client) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(html))
	if err != nil {
		return
	}

	doc.Find("link[rel*='icon']").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		if strings.HasPrefix(href, "//") {
			info.Http.Favicon.Location = baseURL.Scheme + ":" + href
		} else {
			parsedHref, err := url.Parse(href)
			if err != nil {
				return
			}
			fullURL := baseURL.ResolveReference(parsedHref)
			info.Http.Favicon.Location = fullURL.String()
		}
	})

	if info.Http.Favicon.Location != "" {
		// favicon 是附属信息，最多占用 3 秒且不能超过首页剩余时间；失败保留主页面。
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", info.Http.Favicon.Location, nil)
		if err != nil {
			return
		}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			iconData, err := io.ReadAll(resp.Body)
			if err == nil {
				info.Http.Favicon.Data = base64.StdEncoding.EncodeToString(iconData)
				hash := md5.Sum(iconData)
				info.Http.Favicon.Hash = hex.EncodeToString(hash[:])
			}
		} else {
			logger.Warnf("获取 Favicon 失败: %s - %v", info.Http.Favicon.Location, err)
		}
	}
}

func extractTitleAndICP(info *common.GlobalJson, html []byte) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(html))
	if err != nil {
		return
	}
	info.Http.Title = strings.TrimSpace(doc.Find("title").First().Text())

	htmlString, _ := doc.Html()
	re := regexp.MustCompile(`([京津沪渝黑吉辽蒙新藏宁甘陕青川贵云桂琼豫苏浙皖闽赣鲁晋冀湘鄂粤港澳台]{1}ICP备[\dA-Za-z\-\s]+号)`)
	matches := re.FindStringSubmatch(htmlString)
	if len(matches) > 0 {
		info.Http.ICP = strings.TrimSpace(matches[1])
	}
}

func copyHeaders(hdr http.Header) map[string][]string {
	copied := make(map[string][]string)
	for k, v := range hdr {
		copied[k] = append([]string(nil), v...)
	}
	return copied
}

func AnalyzeWebsite(fullurl string, ishttps bool) common.GlobalJson {

	info, err := FetchWebInfo(fullurl, ishttps)
	if err != nil {
		return common.GlobalJson{}
	}
	logger.Infof("获取网站信息成功: %s", fullurl)
	return *info
}
