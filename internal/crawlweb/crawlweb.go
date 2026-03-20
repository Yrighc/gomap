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

func FetchWebInfo(fullURL string, useHTTPS bool) (*common.GlobalJson, error) {
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("FetchWebInfo panic: %v", r)
		}
	}()

	info, err := doFetch(fullURL, false)
	if err != nil && strings.Contains(err.Error(), "tls: handshake failure") {
		logger.Warnf("TLS handshake failure: %s，尝试兼容模式重试", fullURL)
		info, err = doFetch(fullURL, true)
	}
	return info, err
}

func doFetch(fullURL string, compatibleTLS bool) (*common.GlobalJson, error) {
	client := createHTTPClient(compatibleTLS)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %v", err)
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
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if finalPath == "" {
		finalPath = resp.Request.URL.Path
	}

	// ✅ 设置最大读取大小
	limitedBody := http.MaxBytesReader(nil, resp.Body, 2*1024*1024)

	// ✅ 设置超时读取保护（防止 chunked 卡死）
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	var bodyBytes []byte
	var readErr error
	done := make(chan error, 1) // 带缓冲，避免 goroutine 卡住

	go func() {
		bodyBytes, readErr = io.ReadAll(limitedBody)
		done <- readErr
	}()

	select {
	case <-ctx.Done():
		limitedBody.Close()
		return nil, fmt.Errorf("读取 body 超时: %s", fullURL)
	case readErr := <-done:
		if readErr != nil {
			return nil, fmt.Errorf("读取 body 失败: %v", readErr)
		}
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

	extractFavicon(info, bodyBytes, resp.Request.URL, client)
	extractTitleAndICP(info, bodyBytes)

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
			TLSClientConfig:       tlsConf,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}

func extractFavicon(info *common.GlobalJson, html []byte, baseURL *url.URL, client *http.Client) {
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
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", info.Http.Favicon.Location, nil)
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
