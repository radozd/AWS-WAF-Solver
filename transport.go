package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type HttpResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

type RequestOpts struct {
	Method  string
	Headers map[string]string
	Body    []byte
	Proxy   string
	Timeout time.Duration
}

type CookieJar struct {
	mu      sync.Mutex
	cookies map[string]map[string]string
}

func NewCookieJar() *CookieJar {
	return &CookieJar{cookies: make(map[string]map[string]string)}
}

func (j *CookieJar) Set(domain, name, value string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]string)
	}
	j.cookies[domain][name] = value
}

func (j *CookieJar) Get(domain string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := j.cookies[domain]
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

func (j *CookieJar) GetAll(domain string) map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := j.cookies[domain]
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (j *CookieJar) GetValue(domain, name string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	m := j.cookies[domain]
	if m == nil {
		return ""
	}
	return m[name]
}

func (j *CookieJar) ParseSetCookie(domain string, headers http.Header) {
	for _, sc := range headers.Values("Set-Cookie") {
		nv := strings.SplitN(sc, ";", 2)[0]
		nv = strings.TrimSpace(nv)
		eq := strings.IndexByte(nv, '=')
		if eq > 0 {
			j.Set(domain, nv[:eq], nv[eq+1:])
		}
	}
}

var chromeHeaderPriority = map[string]int{
	"host":                      0,
	"cache-control":             1,
	"sec-ch-ua":                 2,
	"sec-ch-ua-mobile":          3,
	"sec-ch-ua-platform":        4,
	"upgrade-insecure-requests": 5,
	"user-agent":                6,
	"accept":                    7,
	"sec-fetch-site":            8,
	"sec-fetch-mode":            9,
	"sec-fetch-user":            10,
	"sec-fetch-dest":            11,
	"accept-encoding":           12,
	"accept-language":           13,
	"cookie":                    14,
	"content-type":              15,
	"content-length":            16,
	"origin":                    17,
	"referer":                   18,
}

func sortHeaderOrder(keys []string) []string {
	sorted := make([]string, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool {
		pi, oki := chromeHeaderPriority[sorted[i]]
		pj, okj := chromeHeaderPriority[sorted[j]]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return sorted[i] < sorted[j]
	})
	return sorted
}

func parseProxyString(proxyStr string) string {
	if strings.HasPrefix(proxyStr, "http://") || strings.HasPrefix(proxyStr, "https://") {
		return proxyStr
	}
	parts := strings.SplitN(proxyStr, ":", 4)
	if len(parts) == 4 {
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	}
	if len(parts) == 2 {
		return fmt.Sprintf("http://%s:%s", parts[0], parts[1])
	}
	return proxyStr
}

var (
	tlsClientCache   = make(map[string]tls_client.HttpClient)
	tlsClientCacheMu sync.Mutex
)

func getTLSClient(proxyURL string) (tls_client.HttpClient, error) {
	tlsClientCacheMu.Lock()
	if c, ok := tlsClientCache[proxyURL]; ok {
		tlsClientCacheMu.Unlock()
		return c, nil
	}
	tlsClientCacheMu.Unlock()

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(120),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithCookieJar(nil),
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	tlsClientCacheMu.Lock()
	tlsClientCache[proxyURL] = client
	tlsClientCacheMu.Unlock()
	return client, nil
}

func DoRequest(rawURL string, opts RequestOpts) (*HttpResponse, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	method := opts.Method
	if method == "" {
		if opts.Body != nil {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	var bodyReader io.Reader
	if opts.Body != nil {
		bodyReader = bytes.NewReader(opts.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := fhttp.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return nil, err
	}

	headerKeys := make([]string, 0, len(opts.Headers))
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
		headerKeys = append(headerKeys, strings.ToLower(k))
	}
	req.Header[fhttp.HeaderOrderKey] = sortHeaderOrder(headerKeys)
	req.Header[fhttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	proxyURL := ""
	if opts.Proxy != "" {
		proxyURL = parseProxyString(opts.Proxy)
	}

	client, err := getTLSClient(proxyURL)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	defer resp.Body.Close()

	stdHeaders := make(http.Header)
	for k, v := range resp.Header {
		if k == fhttp.HeaderOrderKey || k == fhttp.PHeaderOrderKey {
			continue
		}
		stdHeaders[k] = v
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	body := rawBody
	ce := stdHeaders.Get("Content-Encoding")
	switch ce {
	case "gzip":
		if len(rawBody) >= 2 && rawBody[0] == 0x1f && rawBody[1] == 0x8b {
			if gr, e := gzip.NewReader(bytes.NewReader(rawBody)); e == nil {
				if decompressed, e2 := io.ReadAll(gr); e2 == nil {
					body = decompressed
				}
				gr.Close()
			}
		}
	case "deflate":
		if dr := flate.NewReader(bytes.NewReader(rawBody)); dr != nil {
			if decompressed, e := io.ReadAll(dr); e == nil {
				body = decompressed
			}
		}
	case "br":
		if decompressed, e := io.ReadAll(brotli.NewReader(bytes.NewReader(rawBody))); e == nil && len(decompressed) > 0 {
			body = decompressed
		}
	}

	return &HttpResponse{Status: resp.StatusCode, Headers: stdHeaders, Body: body}, nil
}

func DoRequestFollowRedirects(rawURL string, opts RequestOpts, jar *CookieJar) (*HttpResponse, error) {
	for i := 0; i < 10; i++ {
		resp, err := DoRequest(rawURL, opts)
		if err != nil {
			return nil, err
		}
		domain := extractHost(rawURL)
		if jar != nil {
			jar.ParseSetCookie(domain, resp.Headers)
		}
		if resp.Status >= 300 && resp.Status < 400 {
			loc := resp.Headers.Get("Location")
			if loc == "" {
				return resp, nil
			}
			if strings.HasPrefix(loc, "/") {
				u, _ := url.Parse(rawURL)
				loc = u.Scheme + "://" + u.Host + loc
			}
			rawURL = loc
			newDomain := extractHost(rawURL)
			opts.Headers["Host"] = newDomain
			if jar != nil {
				cookies := jar.Get(newDomain)
				if cookies != "" {
					opts.Headers["Cookie"] = cookies
				}
			}
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("too many redirects")
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	parts := strings.SplitN(rawURL, "/", 2)
	return parts[0]
}

func loadProxies(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var proxies []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	return proxies
}

func randomProxy(proxies []string) string {
	if len(proxies) == 0 {
		return ""
	}
	return proxies[rand.Intn(len(proxies))]
}
